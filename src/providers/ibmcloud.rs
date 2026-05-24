/*
 * Copyright Stalwart Labs LLC See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use crate::http::HttpClientBuilder;
use crate::utils::strip_origin_from_name;
use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, Result, SRVRecord};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api.softlayer.com/rest/v3.1";

#[derive(Clone)]
pub struct IbmCloudProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

impl IbmCloudProvider {
    pub(crate) fn new(
        username: impl AsRef<str>,
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let credentials = format!("{}:{}", username.as_ref(), api_key.as_ref());
        let encoded = BASE64.encode(credentials.as_bytes());
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {encoded}"))
            .with_timeout(timeout);
        Ok(Self {
            client,
            endpoint: DEFAULT_ENDPOINT.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        self.endpoint = endpoint.as_ref().trim_end_matches('/').to_string();
        self
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        check_record_types(record_type, &records)?;
        let host_fqdn = name.into_name().to_ascii_lowercase();
        let zone = origin.into_name().to_ascii_lowercase();
        let (domain_id, resolved_zone) = self.resolve_domain(&zone).await?;
        let host_label = strip_origin_from_name(&host_fqdn, &resolved_zone, Some("@"));
        let rr_type = softlayer_record_type(&record_type)?;

        let existing = self.list_at(domain_id, &host_label, rr_type).await?;

        let desired: Vec<SoftLayerResourceRecord> = records
            .into_iter()
            .map(|r| build_record_payload(&r, &host_label, ttl, domain_id))
            .collect::<Result<_>>()?;

        let mut existing_pool = existing;
        let mut to_add: Vec<SoftLayerResourceRecord> = Vec::new();

        for payload in desired {
            if let Some(idx) = existing_pool
                .iter()
                .position(|e| record_matches(e, &payload))
            {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(payload);
            }
        }

        for entry in existing_pool {
            if let Some(id) = entry.id {
                self.delete_record(id).await?;
            }
        }
        for payload in to_add {
            self.post_record(payload).await?;
        }
        Ok(())
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        check_record_types(record_type, &records)?;
        let host_fqdn = name.into_name().to_ascii_lowercase();
        let zone = origin.into_name().to_ascii_lowercase();
        let (domain_id, resolved_zone) = self.resolve_domain(&zone).await?;
        let host_label = strip_origin_from_name(&host_fqdn, &resolved_zone, Some("@"));
        let rr_type = softlayer_record_type(&record_type)?;
        let existing = self.list_at(domain_id, &host_label, rr_type).await?;

        for record in records {
            let payload = build_record_payload(&record, &host_label, ttl, domain_id)?;
            if existing.iter().any(|e| record_matches(e, &payload)) {
                continue;
            }
            self.post_record(payload).await?;
        }
        Ok(())
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        check_record_types(record_type, &records)?;
        let host_fqdn = name.into_name().to_ascii_lowercase();
        let zone = origin.into_name().to_ascii_lowercase();
        let (domain_id, resolved_zone) = self.resolve_domain(&zone).await?;
        let host_label = strip_origin_from_name(&host_fqdn, &resolved_zone, Some("@"));
        let rr_type = softlayer_record_type(&record_type)?;
        let existing = self.list_at(domain_id, &host_label, rr_type).await?;

        for record in records {
            let payload = build_record_payload(&record, &host_label, 0, domain_id)?;
            if let Some(entry) = existing.iter().find(|e| record_matches(e, &payload))
                && let Some(id) = entry.id
            {
                self.delete_record(id).await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> Result<Vec<DnsRecord>> {
        let host_fqdn = name.into_name().to_ascii_lowercase();
        let zone = origin.into_name().to_ascii_lowercase();
        let (domain_id, resolved_zone) = self.resolve_domain(&zone).await?;
        let host_label = strip_origin_from_name(&host_fqdn, &resolved_zone, Some("@"));
        let rr_type = softlayer_record_type(&record_type)?;
        let existing = self.list_at(domain_id, &host_label, rr_type).await?;
        existing.into_iter().map(record_to_dns_record).collect()
    }

    async fn resolve_domain(&self, zone: &str) -> Result<(i64, String)> {
        let mut current = zone.to_string();
        loop {
            let url = format!(
                "{}/SoftLayer_Dns_Domain/getByDomainName/{}.json",
                self.endpoint, current
            );
            let domains = self.client.get(url).send::<Vec<SoftLayerDomain>>().await?;

            if let Some(found) = domains.iter().find(|d| {
                d.name
                    .as_deref()
                    .map(|n| n.eq_ignore_ascii_case(&current))
                    .unwrap_or(false)
            }) {
                return Ok((found.id, current));
            }

            match current.split_once('.') {
                Some((_, parent)) if parent.contains('.') => {
                    current = parent.to_string();
                }
                _ => {
                    return Err(Error::Api(format!("No data found for domain: {zone}")));
                }
            }
        }
    }

    async fn list_at(
        &self,
        domain_id: i64,
        host_label: &str,
        rr_type: &str,
    ) -> Result<Vec<SoftLayerResourceRecord>> {
        let records = self.fetch_all_records(domain_id).await?;
        Ok(records
            .into_iter()
            .filter(|record| {
                record
                    .record_type
                    .as_deref()
                    .map(|t| t.eq_ignore_ascii_case(rr_type))
                    .unwrap_or(false)
                    && record
                        .host
                        .as_deref()
                        .map(|h| h.eq_ignore_ascii_case(host_label))
                        .unwrap_or(false)
            })
            .collect())
    }

    async fn fetch_all_records(&self, domain_id: i64) -> Result<Vec<SoftLayerResourceRecord>> {
        let url = format!(
            "{}/SoftLayer_Dns_Domain/{}/getResourceRecords.json",
            self.endpoint, domain_id
        );
        self.client
            .get(url)
            .send::<Vec<SoftLayerResourceRecord>>()
            .await
    }

    async fn post_record(&self, payload: SoftLayerResourceRecord) -> Result<()> {
        let url = format!("{}/SoftLayer_Dns_Domain_ResourceRecord.json", self.endpoint);
        self.client
            .post(url)
            .with_body(SoftLayerEnvelope {
                parameters: vec![payload],
            })?
            .send::<Value>()
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, id: i64) -> Result<()> {
        let url = format!(
            "{}/SoftLayer_Dns_Domain_ResourceRecord/{}.json",
            self.endpoint, id
        );
        self.client.delete(url).send::<Value>().await.map(|_| ())
    }
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> Result<()> {
    softlayer_record_type(&expected)?;
    for record in records {
        let actual = record.as_type();
        if actual != expected {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected.as_str(),
                actual.as_str(),
            )));
        }
    }
    Ok(())
}

fn record_matches(existing: &SoftLayerResourceRecord, desired: &SoftLayerResourceRecord) -> bool {
    let same_type = match (&existing.record_type, &desired.record_type) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    };
    if !same_type {
        return false;
    }
    let same_host = match (&existing.host, &desired.host) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    };
    if !same_host {
        return false;
    }
    if normalize_data(existing.data.as_deref()) != normalize_data(desired.data.as_deref()) {
        return false;
    }
    if existing.mx_priority != desired.mx_priority {
        return false;
    }
    if existing.priority != desired.priority
        || existing.weight != desired.weight
        || existing.port != desired.port
    {
        return false;
    }
    if !opt_eq_ignore_case(&existing.service, &desired.service) {
        return false;
    }
    if !opt_eq_ignore_case(&existing.protocol, &desired.protocol) {
        return false;
    }
    true
}

fn opt_eq_ignore_case(a: &Option<String>, b: &Option<String>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => x.eq_ignore_ascii_case(y),
        (None, None) => true,
        _ => false,
    }
}

fn normalize_data(data: Option<&str>) -> Option<String> {
    data.map(|d| d.trim_end_matches('.').to_ascii_lowercase())
}

fn build_record_payload(
    record: &DnsRecord,
    host_label: &str,
    ttl: u32,
    domain_id: i64,
) -> Result<SoftLayerResourceRecord> {
    let rr_type = softlayer_record_type(&record.as_type())?;

    let mut payload = SoftLayerResourceRecord {
        id: None,
        host: Some(host_label.to_string()),
        ttl: Some(ttl as i64),
        record_type: Some(rr_type.to_string()),
        domain_id: Some(domain_id),
        data: None,
        mx_priority: None,
        service: None,
        protocol: None,
        priority: None,
        weight: None,
        port: None,
        complex_type: None,
    };

    match record {
        DnsRecord::A(ip) => {
            payload.data = Some(ip.to_string());
        }
        DnsRecord::AAAA(ip) => {
            payload.data = Some(ip.to_string());
            payload.complex_type = Some("SoftLayer_Dns_Domain_ResourceRecord_AaaaType".to_string());
        }
        DnsRecord::CNAME(target) => {
            payload.data = Some(format!("{}.", target.trim_end_matches('.')));
        }
        DnsRecord::NS(target) => {
            payload.data = Some(format!("{}.", target.trim_end_matches('.')));
        }
        DnsRecord::MX(mx) => {
            payload.data = Some(format!("{}.", mx.exchange.trim_end_matches('.')));
            payload.mx_priority = Some(mx.priority as i64);
            payload.complex_type = Some("SoftLayer_Dns_Domain_ResourceRecord_MxType".to_string());
        }
        DnsRecord::TXT(text) => {
            payload.data = Some(text.clone());
        }
        DnsRecord::SRV(srv) => {
            payload.data = Some(format!("{}.", srv.target.trim_end_matches('.')));
            payload.priority = Some(srv.priority as i64);
            payload.weight = Some(srv.weight as i64);
            payload.port = Some(srv.port as i64);
            let (service, protocol) = parse_srv_label(host_label);
            payload.service = service;
            payload.protocol = protocol;
            payload.complex_type = Some("SoftLayer_Dns_Domain_ResourceRecord_SrvType".to_string());
        }
        DnsRecord::CAA(_) => {
            return Err(Error::Api(
                "CAA records are not supported by ibmcloud".to_string(),
            ));
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by ibmcloud".to_string(),
            ));
        }
    }

    Ok(payload)
}

fn record_to_dns_record(record: SoftLayerResourceRecord) -> Result<DnsRecord> {
    let rr_type = record
        .record_type
        .as_deref()
        .ok_or_else(|| Error::Parse("missing record type in SoftLayer response".to_string()))?
        .to_ascii_lowercase();
    let data = record
        .data
        .clone()
        .ok_or_else(|| Error::Parse("missing record data in SoftLayer response".to_string()))?;

    Ok(match rr_type.as_str() {
        "a" => DnsRecord::A(
            data.parse()
                .map_err(|e| Error::Parse(format!("invalid A data: {e}")))?,
        ),
        "aaaa" => DnsRecord::AAAA(
            data.parse()
                .map_err(|e| Error::Parse(format!("invalid AAAA data: {e}")))?,
        ),
        "cname" => DnsRecord::CNAME(data),
        "ns" => DnsRecord::NS(data),
        "txt" => DnsRecord::TXT(data),
        "mx" => DnsRecord::MX(MXRecord {
            exchange: data,
            priority: record.mx_priority.unwrap_or(10) as u16,
        }),
        "srv" => DnsRecord::SRV(SRVRecord {
            target: data,
            priority: record.priority.unwrap_or(0) as u16,
            weight: record.weight.unwrap_or(0) as u16,
            port: record.port.unwrap_or(0) as u16,
        }),
        other => {
            return Err(Error::Parse(format!(
                "unsupported SoftLayer record type: {other}"
            )));
        }
    })
}

fn parse_srv_label(host_label: &str) -> (Option<String>, Option<String>) {
    let trimmed = host_label.trim_end_matches('.');
    let mut iter = trimmed.split('.');
    let first = iter.next().map(str::to_string);
    let second = iter.next().map(str::to_string);
    (first, second)
}

fn softlayer_record_type(rt: &DnsRecordType) -> Result<&'static str> {
    Ok(match rt {
        DnsRecordType::A => "a",
        DnsRecordType::AAAA => "aaaa",
        DnsRecordType::CNAME => "cname",
        DnsRecordType::MX => "mx",
        DnsRecordType::NS => "ns",
        DnsRecordType::TXT => "txt",
        DnsRecordType::SRV => "srv",
        DnsRecordType::CAA => {
            return Err(Error::Api(
                "CAA records are not supported by ibmcloud".to_string(),
            ));
        }
        DnsRecordType::TLSA => {
            return Err(Error::Api(
                "TLSA records are not supported by ibmcloud".to_string(),
            ));
        }
    })
}

#[derive(Debug, Serialize)]
struct SoftLayerEnvelope {
    parameters: Vec<SoftLayerResourceRecord>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
struct SoftLayerResourceRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "ttl")]
    ttl: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    record_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "domainId")]
    domain_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "mxPriority")]
    mx_priority: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "complexType")]
    complex_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SoftLayerDomain {
    id: i64,
    #[serde(default)]
    name: Option<String>,
}
