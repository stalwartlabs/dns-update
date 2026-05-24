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

use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, KeyValue, MXRecord, SRVRecord,
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
    #[serde(rename = "site_id")]
    site_id: i64,
    #[serde(rename = "type")]
    record_type: &'a str,
    host: &'a str,
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    opt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct CreateRecordResponse {
    id: i64,
}

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct PleskRecord {
    id: i64,
    #[serde(rename = "site_id")]
    site_id: Option<i64>,
    #[serde(rename = "type")]
    record_type: String,
    host: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    opt: String,
}

#[derive(Deserialize, Debug)]
struct PleskDomain {
    id: i64,
    name: String,
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
            return Err(Error::Api(
                "TLSA records are not supported by Plesk".to_string(),
            ));
        }
        let name_owned = name.into_name().to_string();
        let domain_owned = origin.into_name().to_string();
        let site_id = self.find_site_id(&domain_owned).await?;
        let host = strip_origin_from_name(&name_owned, &domain_owned, Some(""));

        let desired = build_payloads(record_type, records)?;
        let mut existing = self
            .list_at(site_id, &host, &domain_owned, record_type)
            .await?;

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
            self.post_record(site_id, &host, ttl, &payload).await?;
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
            return Err(Error::Api(
                "TLSA records are not supported by Plesk".to_string(),
            ));
        }
        let name_owned = name.into_name().to_string();
        let domain_owned = origin.into_name().to_string();
        let site_id = self.find_site_id(&domain_owned).await?;
        let host = strip_origin_from_name(&name_owned, &domain_owned, Some(""));

        let desired = build_payloads(record_type, records)?;
        let existing = self
            .list_at(site_id, &host, &domain_owned, record_type)
            .await?;

        for payload in desired {
            if existing.iter().any(|r| payload_matches(r, &payload)) {
                continue;
            }
            self.post_record(site_id, &host, ttl, &payload).await?;
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
            return Err(Error::Api(
                "TLSA records are not supported by Plesk".to_string(),
            ));
        }
        let name_owned = name.into_name().to_string();
        let domain_owned = origin.into_name().to_string();
        let site_id = self.find_site_id(&domain_owned).await?;
        let host = strip_origin_from_name(&name_owned, &domain_owned, Some(""));

        let to_remove = build_payloads(record_type, records)?;
        let existing = self
            .list_at(site_id, &host, &domain_owned, record_type)
            .await?;

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
            return Err(Error::Api(
                "TLSA records are not supported by Plesk".to_string(),
            ));
        }
        let name_owned = name.into_name().to_string();
        let domain_owned = origin.into_name().to_string();
        let site_id = self.find_site_id(&domain_owned).await?;
        let host = strip_origin_from_name(&name_owned, &domain_owned, Some(""));

        let existing = self
            .list_at(site_id, &host, &domain_owned, record_type)
            .await?;
        existing
            .into_iter()
            .map(|r| decode_record(record_type, &r))
            .collect()
    }

    async fn find_site_id(&self, domain: &str) -> crate::Result<i64> {
        let query = serde_urlencoded::to_string([("name", domain)])
            .map_err(|err| Error::Serialize(err.to_string()))?;
        let domains = self
            .client
            .get(format!("{}/api/v2/domains?{}", self.endpoint, query))
            .send_with_retry::<Vec<PleskDomain>>(3)
            .await?;

        domains
            .into_iter()
            .find(|d| d.name.trim_end_matches('.') == domain.trim_end_matches('.'))
            .map(|d| d.id)
            .ok_or_else(|| Error::Api(format!("Plesk site not found for {domain}")))
    }

    async fn list_at(
        &self,
        site_id: i64,
        host_target: &str,
        domain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<PleskRecord>> {
        let query = serde_urlencoded::to_string([("site_id", site_id.to_string())])
            .map_err(|err| Error::Serialize(err.to_string()))?;
        let records = self
            .client
            .get(format!("{}/api/v2/dns/records?{}", self.endpoint, query))
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
        site_id: i64,
        host: &str,
        ttl: u32,
        payload: &EncodedPayload,
    ) -> crate::Result<()> {
        let body = CreateRecordRequest {
            site_id,
            record_type: payload.record_type,
            host,
            value: payload.value.clone(),
            opt: payload.opt.clone(),
            ttl: Some(ttl),
        };
        self.client
            .post(format!("{}/api/v2/dns/records", self.endpoint))
            .with_body(&body)?
            .send_with_retry::<CreateRecordResponse>(3)
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, id: i64) -> crate::Result<()> {
        self.client
            .delete(format!("{}/api/v2/dns/records/{}", self.endpoint, id))
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn host_matches(api_host: &str, expected_subdomain: &str, domain: &str) -> bool {
    let api = api_host.trim_end_matches('.');
    let expected_full = if expected_subdomain.is_empty() {
        domain.trim_end_matches('.').to_string()
    } else {
        format!("{}.{}", expected_subdomain, domain.trim_end_matches('.'))
    };
    api.eq_ignore_ascii_case(&expected_full) || api.eq_ignore_ascii_case(expected_subdomain)
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
            return Err(Error::Api(
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
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by Plesk".to_string(),
        )),
    }
}

fn build_caa(flags: u8, tag: &str, value: &str) -> crate::Result<CAARecord> {
    let issuer_critical = flags & 0x80 != 0;
    match tag {
        "issue" => {
            let (name, options) = parse_caa_value(value);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(value);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: value.to_string(),
        }),
        other => Err(Error::Parse(format!("unknown CAA tag: {other}"))),
    }
}

fn parse_caa_value(value: &str) -> (Option<String>, Vec<KeyValue>) {
    let mut parts = value.split(';').map(str::trim);
    let name_part = parts.next().unwrap_or("").trim().to_string();
    let name = if name_part.is_empty() {
        None
    } else {
        Some(name_part)
    };
    let options = parts
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => KeyValue {
                key: k.trim().to_string(),
                value: v.trim().to_string(),
            },
            None => KeyValue {
                key: p.trim().to_string(),
                value: String::new(),
            },
        })
        .collect();
    (name, options)
}
