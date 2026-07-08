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

use crate::utils::split_caa_value;
use crate::utils::unquote_txt;
use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord,
    http::{HttpClient, HttpClientBuilder},
    utils::strip_origin_from_name,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, time::Duration};

const DEFAULT_API_ENDPOINT: &str = "https://api.vultr.com/v2";
const LIST_PAGE_SIZE: u32 = 500;

#[derive(Clone)]
pub struct VultrProvider {
    client: HttpClient,
    endpoint: Cow<'static, str>,
}

#[derive(Deserialize, Debug)]
struct DomainRecordsResponse {
    records: Vec<VultrRecord>,
    #[serde(default)]
    meta: Meta,
}

#[derive(Deserialize, Debug, Default)]
struct Meta {
    #[serde(default)]
    links: MetaLinks,
}

#[derive(Deserialize, Debug, Default)]
struct MetaLinks {
    #[serde(default)]
    next: String,
}

#[derive(Deserialize, Debug, Clone)]
struct VultrRecord {
    id: String,
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    data: String,
    #[serde(default)]
    priority: i32,
}

#[derive(Serialize, Debug)]
struct CreateRecordRequest<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'static str,
    data: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordPayload {
    data: String,
    priority: Option<u16>,
}

impl VultrProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", api_key.as_ref()))
            .with_timeout(timeout)
            .build();
        Self {
            client,
            endpoint: Cow::Borrowed(DEFAULT_API_ENDPOINT),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl Into<Cow<'static, str>>) -> Self {
        Self {
            endpoint: endpoint.into(),
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
        let domain = origin.into_name().into_owned();
        let name = name.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let desired = build_payloads(record_type, records)?;
        let existing = self.list_at(&domain, &subdomain, record_type).await?;

        let mut existing_pool: Vec<VultrRecord> = existing;
        let mut to_add: Vec<RecordPayload> = Vec::new();

        for payload in desired {
            if let Some(idx) = existing_pool
                .iter()
                .position(|r| matches_payload(r, &payload))
            {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(payload);
            }
        }

        for entry in existing_pool {
            self.delete_record(&domain, &entry.id).await?;
        }
        for payload in to_add {
            self.create_record(&domain, &subdomain, record_type, ttl, payload)
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
        let domain = origin.into_name().into_owned();
        let name = name.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let desired = build_payloads(record_type, records)?;
        let existing = self.list_at(&domain, &subdomain, record_type).await?;

        for payload in desired {
            if existing.iter().any(|r| matches_payload(r, &payload)) {
                continue;
            }
            self.create_record(&domain, &subdomain, record_type, ttl, payload)
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
        let domain = origin.into_name().into_owned();
        let name = name.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let to_remove = build_payloads(record_type, records)?;
        let existing = self.list_at(&domain, &subdomain, record_type).await?;

        for payload in to_remove {
            if let Some(entry) = existing.iter().find(|r| matches_payload(r, &payload)) {
                self.delete_record(&domain, &entry.id).await?;
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
        let domain = origin.into_name().into_owned();
        let name = name.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let listed = self.list_at(&domain, &subdomain, record_type).await?;
        listed.into_iter().map(record_from_vultr).collect()
    }

    async fn list_at(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<VultrRecord>> {
        let wanted_type = record_type.as_str();
        let mut out: Vec<VultrRecord> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let url = match &cursor {
                Some(c) => format!(
                    "{}/domains/{domain}/records?per_page={LIST_PAGE_SIZE}&cursor={}",
                    self.endpoint,
                    urlencode(c)
                ),
                None => format!(
                    "{}/domains/{domain}/records?per_page={LIST_PAGE_SIZE}",
                    self.endpoint
                ),
            };
            let response: DomainRecordsResponse = self.client.get(url).send_with_retry(3).await?;
            for record in response.records {
                if record.name == subdomain && record.record_type == wanted_type {
                    out.push(record);
                }
            }
            if response.meta.links.next.is_empty() {
                break;
            }
            cursor = Some(response.meta.links.next);
        }
        Ok(out)
    }

    async fn create_record(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
        payload: RecordPayload,
    ) -> crate::Result<()> {
        let body = CreateRecordRequest {
            name: subdomain,
            record_type: record_type.as_str(),
            data: payload.data,
            ttl,
            priority: payload.priority,
        };
        self.client
            .post(format!("{}/domains/{domain}/records", self.endpoint))
            .with_body(body)?
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, domain: &str, record_id: &str) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/domains/{domain}/records/{record_id}",
                self.endpoint
            ))
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }
}

fn urlencode(value: &str) -> String {
    serde_urlencoded::to_string([("cursor", value)])
        .ok()
        .and_then(|s| s.strip_prefix("cursor=").map(|s| s.to_string()))
        .unwrap_or_else(|| value.to_string())
}

fn matches_payload(record: &VultrRecord, payload: &RecordPayload) -> bool {
    if record.data != payload.data {
        return false;
    }
    match payload.priority {
        Some(p) => record.priority == p as i32,
        None => true,
    }
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
) -> crate::Result<Vec<RecordPayload>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(build_payload(record)?);
    }
    Ok(out)
}

fn build_payload(record: DnsRecord) -> crate::Result<RecordPayload> {
    let priority = match &record {
        DnsRecord::MX(mx) => Some(mx.priority),
        DnsRecord::SRV(srv) => Some(srv.priority),
        _ => None,
    };
    let data = record_target(&record)?;
    Ok(RecordPayload { data, priority })
}

fn record_target(record: &DnsRecord) -> Result<String, Error> {
    match record {
        DnsRecord::A(addr) => Ok(addr.to_string()),
        DnsRecord::AAAA(addr) => Ok(addr.to_string()),
        DnsRecord::CNAME(content) => Ok(content.clone()),
        DnsRecord::NS(content) => Ok(content.clone()),
        DnsRecord::MX(mx) => Ok(mx.exchange.clone()),
        DnsRecord::TXT(content) => {
            let mut out = String::with_capacity(content.len() + 2);
            out.push('"');
            for ch in content.chars() {
                match ch {
                    '\\' => out.push_str("\\\\"),
                    '"' => out.push_str("\\\""),
                    _ => out.push(ch),
                }
            }
            out.push('"');
            Ok(out)
        }
        DnsRecord::SRV(srv) => Ok(format!("{} {} {}", srv.weight, srv.port, srv.target)),
        DnsRecord::TLSA(_) => Err(Error::Unsupported(
            "TLSA records are not supported by Vultr".to_string(),
        )),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            Ok(format!("{flags} {tag} \"{value}\""))
        }
    }
}

fn record_from_vultr(record: VultrRecord) -> crate::Result<DnsRecord> {
    let priority_u16 = if record.priority < 0 {
        0
    } else {
        record.priority as u16
    };
    match record.record_type.as_str() {
        "A" => record
            .data
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A record data {}: {e}", record.data))),
        "AAAA" => record
            .data
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA record data {}: {e}", record.data))),
        "CNAME" => Ok(DnsRecord::CNAME(record.data)),
        "NS" => Ok(DnsRecord::NS(record.data)),
        "MX" => Ok(DnsRecord::MX(MXRecord {
            exchange: record.data,
            priority: priority_u16,
        })),
        "TXT" => Ok(DnsRecord::TXT(unquote_txt(&record.data))),
        "SRV" => parse_srv(&record.data, priority_u16),
        "CAA" => parse_caa(&record.data),
        other => Err(Error::Parse(format!(
            "unsupported Vultr record type: {other}"
        ))),
    }
}

fn parse_srv(data: &str, priority: u16) -> crate::Result<DnsRecord> {
    let mut parts = data.split_whitespace();
    let weight = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| Error::Parse(format!("invalid SRV weight in {data}")))?;
    let port = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| Error::Parse(format!("invalid SRV port in {data}")))?;
    let target = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("missing SRV target in {data}")))?
        .to_string();
    Ok(DnsRecord::SRV(SRVRecord {
        priority,
        weight,
        port,
        target,
    }))
}

fn parse_caa(data: &str) -> crate::Result<DnsRecord> {
    let trimmed = data.trim();
    let (flags_str, rest) = trimmed
        .split_once(char::is_whitespace)
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {data}")))?;
    let flags: u8 = flags_str
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags in {data}: {e}")))?;
    let rest = rest.trim_start();
    let (tag, value_part) = rest
        .split_once(char::is_whitespace)
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {data}")))?;
    let value = value_part.trim().trim_matches('"').to_string();
    let issuer_critical = flags & 0x80 != 0;
    let record = match tag {
        "issue" => {
            let (name, options) = split_caa_value(&value);
            CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }
        }
        "issuewild" => {
            let (name, options) = split_caa_value(&value);
            CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            }
        }
        "iodef" => CAARecord::Iodef {
            issuer_critical,
            url: value,
        },
        other => return Err(Error::Parse(format!("unknown CAA tag: {other}"))),
    };
    Ok(DnsRecord::CAA(record))
}
