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
use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, Result};
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

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        let host_fqdn = name.into_name().to_ascii_lowercase();
        let zone = origin.into_name().to_ascii_lowercase();
        let domain_id = self.resolve_domain_id(&zone).await?;
        let payload = build_record_payload(&record, &host_fqdn, ttl, domain_id)?;

        let url = format!(
            "{}/SoftLayer_Dns_Domain_ResourceRecord.json",
            self.endpoint
        );
        self.client
            .post(url)
            .with_body(SoftLayerCreate {
                parameters: vec![payload],
            })?
            .send::<Value>()
            .await
            .map(|_| ())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        let host_fqdn = name.into_name().to_ascii_lowercase();
        let zone = origin.into_name().to_ascii_lowercase();
        let domain_id = self.resolve_domain_id(&zone).await?;
        let rr_type = softlayer_record_type(&record.as_type())?;
        let existing = self
            .find_resource_record(domain_id, &host_fqdn, rr_type)
            .await?
            .ok_or(Error::NotFound)?;
        let existing_id = existing.id.ok_or(Error::NotFound)?;

        let mut payload = build_record_payload(&record, &host_fqdn, ttl, domain_id)?;
        payload.id = Some(existing_id);

        let url = format!(
            "{}/SoftLayer_Dns_Domain_ResourceRecord/{}.json",
            self.endpoint, existing_id
        );
        self.client
            .put(url)
            .with_body(SoftLayerCreate {
                parameters: vec![payload],
            })?
            .send::<Value>()
            .await
            .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> Result<()> {
        let rr_type = softlayer_record_type(&record_type)?;
        let host_fqdn = name.into_name().to_ascii_lowercase();
        let zone = origin.into_name().to_ascii_lowercase();
        let domain_id = self.resolve_domain_id(&zone).await?;
        let Some(existing) = self
            .find_resource_record(domain_id, &host_fqdn, rr_type)
            .await?
        else {
            return Ok(());
        };
        let Some(existing_id) = existing.id else {
            return Ok(());
        };

        let url = format!(
            "{}/SoftLayer_Dns_Domain_ResourceRecord/{}.json",
            self.endpoint, existing_id
        );
        self.client.delete(url).send::<Value>().await.map(|_| ())
    }

    async fn resolve_domain_id(&self, zone: &str) -> Result<i64> {
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
                return Ok(found.id);
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

    async fn find_resource_record(
        &self,
        domain_id: i64,
        host_fqdn: &str,
        rr_type: &str,
    ) -> Result<Option<SoftLayerResourceRecord>> {
        let url = format!(
            "{}/SoftLayer_Dns_Domain/{}/getResourceRecords.json",
            self.endpoint, domain_id
        );
        let records = self
            .client
            .get(url)
            .send::<Vec<SoftLayerResourceRecord>>()
            .await?;

        let match_host = host_fqdn.trim_end_matches('.');
        Ok(records.into_iter().find(|record| {
            record
                .record_type
                .as_deref()
                .map(|t| t.eq_ignore_ascii_case(rr_type))
                .unwrap_or(false)
                && record
                    .host
                    .as_deref()
                    .map(|h| h.eq_ignore_ascii_case(match_host))
                    .unwrap_or(false)
        }))
    }
}

fn build_record_payload(
    record: &DnsRecord,
    host_fqdn: &str,
    ttl: u32,
    domain_id: i64,
) -> Result<SoftLayerResourceRecord> {
    let rr_type = softlayer_record_type(&record.as_type())?;
    let host = host_fqdn.trim_end_matches('.').to_string();

    let mut payload = SoftLayerResourceRecord {
        id: None,
        host: Some(host),
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
            let (service, protocol) = parse_srv_label(host_fqdn);
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

fn parse_srv_label(host_fqdn: &str) -> (Option<String>, Option<String>) {
    let trimmed = host_fqdn.trim_end_matches('.');
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
struct SoftLayerCreate {
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

