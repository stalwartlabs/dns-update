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

use crate::utils::build_caa;
use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord,
    http::{HttpClient, HttpClientBuilder},
    utils::{strip_origin_from_name, txt_chunks},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone)]
pub struct PleskProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecordRequest<'a> {
    #[serde(rename = "type")]
    record_type: &'a str,
    host: &'a str,
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    opt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct PleskRecord {
    id: i64,
    #[serde(rename = "type")]
    record_type: String,
    host: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    opt: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EncodedPayload {
    record_type: &'static str,
    value: String,
    opt: Option<String>,
}

impl PleskProvider {
    pub(crate) fn new(
        base_url: impl AsRef<str>,
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("X-API-Key", api_key.as_ref())
            .with_timeout(timeout)
            .build();
        Self {
            client,
            endpoint: base_url.as_ref().trim_end_matches('/').to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().trim_end_matches('/').to_string(),
            ..self
        }
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if matches!(record_type, DnsRecordType::TLSA) {
            return Err(Error::Unsupported(
                "TLSA records are not supported by Plesk".to_string(),
            ));
        }
        let name_owned = name.into_name().to_string();
        let domain_owned = origin.into_name().to_string();
        let host = record_host(&name_owned, &domain_owned);

        let desired = build_payloads(record_type, records)?;
        let mut existing = self.list_at(&domain_owned, &host, record_type).await?;

        let mut to_add: Vec<EncodedPayload> = Vec::new();
        for payload in desired {
            if let Some(idx) = existing.iter().position(|r| payload_matches(r, &payload)) {
                existing.swap_remove(idx);
            } else {
                to_add.push(payload);
            }
        }

        for stale in existing {
            self.delete_record(stale.id).await?;
        }
        for payload in to_add {
            self.post_record(&domain_owned, &host, ttl, &payload)
                .await?;
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
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        if matches!(record_type, DnsRecordType::TLSA) {
            return Err(Error::Unsupported(
                "TLSA records are not supported by Plesk".to_string(),
            ));
        }
        let name_owned = name.into_name().to_string();
        let domain_owned = origin.into_name().to_string();
        let host = record_host(&name_owned, &domain_owned);

        let desired = build_payloads(record_type, records)?;
        let existing = self.list_at(&domain_owned, &host, record_type).await?;

        for payload in desired {
            if existing.iter().any(|r| payload_matches(r, &payload)) {
                continue;
            }
            self.post_record(&domain_owned, &host, ttl, &payload)
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        if matches!(record_type, DnsRecordType::TLSA) {
            return Err(Error::Unsupported(
                "TLSA records are not supported by Plesk".to_string(),
            ));
        }
        let name_owned = name.into_name().to_string();
        let domain_owned = origin.into_name().to_string();
        let host = record_host(&name_owned, &domain_owned);

        let to_remove = build_payloads(record_type, records)?;
        let existing = self.list_at(&domain_owned, &host, record_type).await?;

        for payload in to_remove {
            if let Some(target) = existing.iter().find(|r| payload_matches(r, &payload)) {
                self.delete_record(target.id).await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        if matches!(record_type, DnsRecordType::TLSA) {
            return Err(Error::Unsupported(
                "TLSA records are not supported by Plesk".to_string(),
            ));
        }
        let name_owned = name.into_name().to_string();
        let domain_owned = origin.into_name().to_string();
        let host = record_host(&name_owned, &domain_owned);

        let existing = self.list_at(&domain_owned, &host, record_type).await?;
        existing
            .into_iter()
            .map(|r| decode_record(record_type, &r))
            .collect()
    }

    fn records_url(&self, domain: &str) -> crate::Result<String> {
        let query = serde_urlencoded::to_string([("domain", domain.trim_end_matches('.'))])
            .map_err(|err| Error::Serialize(err.to_string()))?;
        Ok(format!("{}/api/v2/dns/records?{}", self.endpoint, query))
    }

    async fn list_at(
        &self,
        domain: &str,
        host_target: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<PleskRecord>> {
        let records = self
            .client
            .get(self.records_url(domain)?)
            .send_with_retry::<Vec<PleskRecord>>(3)
            .await?;

        let type_str = record_type.as_str();
        Ok(records
            .into_iter()
            .filter(|r| {
                r.record_type.eq_ignore_ascii_case(type_str)
                    && host_matches(&r.host, host_target, domain)
            })
            .collect())
    }

    async fn post_record(
        &self,
        domain: &str,
        host: &str,
        ttl: u32,
        payload: &EncodedPayload,
    ) -> crate::Result<()> {
        let body = CreateRecordRequest {
            record_type: payload.record_type,
            host,
            value: payload.value.clone(),
            opt: payload.opt.clone(),
            ttl: Some(ttl),
        };
        self.client
            .post(self.records_url(domain)?)
            .with_body(&body)?
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, id: i64) -> crate::Result<()> {
        self.client
            .delete(format!("{}/api/v2/dns/records/{}", self.endpoint, id))
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }
}

fn record_host(name: &str, domain: &str) -> String {
    let domain = domain.trim_end_matches('.');
    let subdomain = strip_origin_from_name(name, domain, Some(""));
    if subdomain.is_empty() {
        domain.to_string()
    } else {
        format!("{subdomain}.{domain}")
    }
}

fn host_matches(api_host: &str, expected_host: &str, domain: &str) -> bool {
    let api = api_host.trim_end_matches('.');
    if api.eq_ignore_ascii_case(expected_host) {
        return true;
    }
    let subdomain = strip_origin_from_name(expected_host, domain, Some(""));
    !subdomain.is_empty() && api.eq_ignore_ascii_case(&subdomain)
}

fn payload_matches(existing: &PleskRecord, desired: &EncodedPayload) -> bool {
    existing
        .record_type
        .eq_ignore_ascii_case(desired.record_type)
        && existing.value == desired.value
        && existing.opt.as_str() == desired.opt.as_deref().unwrap_or("")
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> crate::Result<()> {
    for r in records {
        if r.as_type() != expected {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected.as_str(),
                r.as_type().as_str(),
            )));
        }
    }
    Ok(())
}

fn build_payloads(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<EncodedPayload>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.extend(encode_record(&record)?);
    }
    Ok(out)
}

fn encode_record(record: &DnsRecord) -> crate::Result<Vec<EncodedPayload>> {
    Ok(match record {
        DnsRecord::A(addr) => vec![EncodedPayload {
            record_type: "A",
            value: addr.to_string(),
            opt: None,
        }],
        DnsRecord::AAAA(addr) => vec![EncodedPayload {
            record_type: "AAAA",
            value: addr.to_string(),
            opt: None,
        }],
        DnsRecord::CNAME(value) => vec![EncodedPayload {
            record_type: "CNAME",
            value: value.clone(),
            opt: None,
        }],
        DnsRecord::NS(value) => vec![EncodedPayload {
            record_type: "NS",
            value: value.clone(),
            opt: None,
        }],
        DnsRecord::MX(mx) => vec![EncodedPayload {
            record_type: "MX",
            value: mx.exchange.clone(),
            opt: Some(mx.priority.to_string()),
        }],
        DnsRecord::TXT(value) => txt_chunks(value.clone())
            .into_iter()
            .map(|chunk| EncodedPayload {
                record_type: "TXT",
                value: chunk,
                opt: None,
            })
            .collect(),
        DnsRecord::SRV(srv) => vec![EncodedPayload {
            record_type: "SRV",
            value: srv.target.clone(),
            opt: Some(format!("{} {} {}", srv.priority, srv.weight, srv.port)),
        }],
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            vec![EncodedPayload {
                record_type: "CAA",
                value,
                opt: Some(format!("{flags} {tag}")),
            }]
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Unsupported(
                "TLSA records are not supported by Plesk".to_string(),
            ));
        }
    })
}

fn decode_record(expected_type: DnsRecordType, record: &PleskRecord) -> crate::Result<DnsRecord> {
    match expected_type {
        DnsRecordType::A => {
            record
                .value
                .parse()
                .map(DnsRecord::A)
                .map_err(|e: std::net::AddrParseError| {
                    Error::Parse(format!("invalid Plesk A value: {e}"))
                })
        }
        DnsRecordType::AAAA => {
            record
                .value
                .parse()
                .map(DnsRecord::AAAA)
                .map_err(|e: std::net::AddrParseError| {
                    Error::Parse(format!("invalid Plesk AAAA value: {e}"))
                })
        }
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(record.value.clone())),
        DnsRecordType::NS => Ok(DnsRecord::NS(record.value.clone())),
        DnsRecordType::MX => {
            let priority: u16 = record.opt.trim().parse().map_err(|e| {
                Error::Parse(format!("invalid Plesk MX priority {:?}: {e}", record.opt))
            })?;
            Ok(DnsRecord::MX(MXRecord {
                exchange: record.value.clone(),
                priority,
            }))
        }
        DnsRecordType::TXT => Ok(DnsRecord::TXT(record.value.clone())),
        DnsRecordType::SRV => {
            let mut parts = record.opt.split_whitespace();
            let priority: u16 = parts
                .next()
                .ok_or_else(|| Error::Parse("missing SRV priority".to_string()))?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid SRV priority: {e}")))?;
            let weight: u16 = parts
                .next()
                .ok_or_else(|| Error::Parse("missing SRV weight".to_string()))?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid SRV weight: {e}")))?;
            let port: u16 = parts
                .next()
                .ok_or_else(|| Error::Parse("missing SRV port".to_string()))?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid SRV port: {e}")))?;
            Ok(DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target: record.value.clone(),
            }))
        }
        DnsRecordType::CAA => {
            let mut parts = record.opt.split_whitespace();
            let flags: u8 = parts
                .next()
                .ok_or_else(|| Error::Parse("missing CAA flags".to_string()))?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid CAA flags: {e}")))?;
            let tag = parts
                .next()
                .ok_or_else(|| Error::Parse("missing CAA tag".to_string()))?;
            build_caa(flags, tag, &record.value).map(DnsRecord::CAA)
        }
        DnsRecordType::TLSA => Err(Error::Unsupported(
            "TLSA records are not supported by Plesk".to_string(),
        )),
    }
}
