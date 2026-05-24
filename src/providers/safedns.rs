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
    http::HttpClientBuilder, utils::txt_chunks_to_text,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.ukfast.io/safedns/v1";
const LIST_PAGE_SIZE: u32 = 200;

#[derive(Clone)]
pub struct SafeDnsProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct SafeDnsRecordPayload<'a> {
    pub name: &'a str,
    #[serde(rename = "type")]
    pub record_type: &'a str,
    pub content: String,
    pub ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SafeDnsRecord {
    pub id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub priority: Option<u16>,
}

#[derive(Deserialize, Debug)]
pub struct ListRecordsResponse {
    pub data: Vec<SafeDnsRecord>,
    #[serde(default)]
    pub meta: ListMeta,
}

#[derive(Deserialize, Debug, Default)]
pub struct ListMeta {
    #[serde(default)]
    pub pagination: Pagination,
}

#[derive(Deserialize, Debug, Default)]
pub struct Pagination {
    #[serde(default)]
    pub total_pages: u32,
}

#[derive(Deserialize, Debug)]
pub struct AddRecordResponse {
    #[allow(dead_code)]
    pub data: SafeDnsRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeDnsRecordContent {
    pub record_type: &'static str,
    pub content: String,
    pub priority: Option<u16>,
}

impl SafeDnsProvider {
    pub(crate) fn new(auth_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", auth_token.as_ref())
            .with_timeout(timeout);
        Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
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
        let fqdn = name.into_name().into_owned();
        let zone = origin.into_name().into_owned();
        let desired = build_contents(record_type, records)?;
        let existing = self.list_at(&zone, &fqdn, record_type).await?;

        let mut existing_pool: Vec<SafeDnsRecord> = existing;
        let mut to_add: Vec<SafeDnsRecordContent> = Vec::new();

        for content in desired {
            if let Some(idx) = existing_pool
                .iter()
                .position(|r| record_matches(r, &content))
            {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(content);
            }
        }

        for entry in existing_pool {
            self.delete_record(&zone, entry.id).await?;
        }
        for content in to_add {
            self.create_record(&zone, &fqdn, ttl, &content).await?;
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
        if records.is_empty() {
            return Ok(());
        }
        let fqdn = name.into_name().into_owned();
        let zone = origin.into_name().into_owned();
        let desired = build_contents(record_type, records)?;
        let existing = self.list_at(&zone, &fqdn, record_type).await?;

        for content in desired {
            if existing.iter().any(|r| record_matches(r, &content)) {
                continue;
            }
            self.create_record(&zone, &fqdn, ttl, &content).await?;
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
        if records.is_empty() {
            return Ok(());
        }
        let fqdn = name.into_name().into_owned();
        let zone = origin.into_name().into_owned();
        let to_remove = build_contents(record_type, records)?;
        let existing = self.list_at(&zone, &fqdn, record_type).await?;

        for content in to_remove {
            if let Some(entry) = existing.iter().find(|r| record_matches(r, &content)) {
                self.delete_record(&zone, entry.id).await?;
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
        let fqdn = name.into_name().into_owned();
        let zone = origin.into_name().into_owned();
        let listed = self.list_at(&zone, &fqdn, record_type).await?;
        listed
            .into_iter()
            .map(|r| safedns_record_to_dns_record(r, record_type))
            .collect()
    }

    async fn list_at(
        &self,
        zone: &str,
        name: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<SafeDnsRecord>> {
        let type_str = record_type.as_str();
        let mut out: Vec<SafeDnsRecord> = Vec::new();
        let mut page: u32 = 1;
        loop {
            let url = format!(
                "{endpoint}/zones/{zone}/records?name:eq={name}&type:eq={type_str}&per_page={LIST_PAGE_SIZE}&page={page}",
                endpoint = self.endpoint
            );
            let response: ListRecordsResponse = self.client.get(url).send_with_retry(3).await?;
            let total_pages = response.meta.pagination.total_pages;
            for record in response.data {
                if record.name == name && record.record_type == type_str {
                    out.push(record);
                }
            }
            if total_pages <= page {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    async fn create_record(
        &self,
        zone: &str,
        name: &str,
        ttl: u32,
        content: &SafeDnsRecordContent,
    ) -> crate::Result<()> {
        let body = SafeDnsRecordPayload {
            name,
            record_type: content.record_type,
            content: content.content.clone(),
            ttl,
            priority: content.priority,
        };

        self.client
            .post(format!(
                "{endpoint}/zones/{zone}/records",
                endpoint = self.endpoint
            ))
            .with_body(&body)?
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, zone: &str, record_id: i64) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{endpoint}/zones/{zone}/records/{record_id}",
                endpoint = self.endpoint
            ))
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn build_contents(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<SafeDnsRecordContent>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(SafeDnsRecordContent::try_from(record)?);
    }
    Ok(out)
}

fn record_matches(record: &SafeDnsRecord, content: &SafeDnsRecordContent) -> bool {
    record.record_type == content.record_type
        && record.content == content.content
        && record.priority == content.priority
}

fn safedns_record_to_dns_record(
    record: SafeDnsRecord,
    record_type: DnsRecordType,
) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => record
            .content
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A content {}: {e}", record.content))),
        DnsRecordType::AAAA => record
            .content
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA content {}: {e}", record.content))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(record.content)),
        DnsRecordType::NS => Ok(DnsRecord::NS(record.content)),
        DnsRecordType::MX => Ok(DnsRecord::MX(MXRecord {
            exchange: record.content,
            priority: record.priority.unwrap_or(0),
        })),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(unquote_txt(&record.content))),
        DnsRecordType::SRV => parse_srv(&record.content, record.priority.unwrap_or(0)),
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by SafeDNS".to_string(),
        )),
        DnsRecordType::CAA => parse_caa(&record.content),
    }
}

fn parse_srv(content: &str, priority: u16) -> crate::Result<DnsRecord> {
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(Error::Parse(format!(
            "invalid SRV content (expected `<weight> <port> <target>`): {content}"
        )));
    }
    let weight: u16 = parts[0]
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV weight {}: {e}", parts[0])))?;
    let port: u16 = parts[1]
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV port {}: {e}", parts[1])))?;
    Ok(DnsRecord::SRV(SRVRecord {
        priority,
        weight,
        port,
        target: parts[2].to_string(),
    }))
}

fn unquote_txt(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    let mut in_quote = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                in_quote = !in_quote;
            }
            '\\' => {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            ' ' if !in_quote => {}
            _ => out.push(ch),
        }
    }
    out
}

fn parse_caa(content: &str) -> crate::Result<DnsRecord> {
    let trimmed = content.trim();
    let (flags_str, rest) = trimmed
        .split_once(char::is_whitespace)
        .ok_or_else(|| Error::Parse(format!("invalid CAA content: {content}")))?;
    let (tag, value_part) = rest
        .trim_start()
        .split_once(char::is_whitespace)
        .ok_or_else(|| Error::Parse(format!("invalid CAA content: {content}")))?;
    let flags: u8 = flags_str
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags {flags_str}: {e}")))?;
    let value = value_part
        .trim()
        .trim_start_matches('"')
        .trim_end_matches('"')
        .to_string();
    let issuer_critical = flags & 0x80 != 0;
    match tag.trim() {
        "issue" => {
            let (name, options) = parse_caa_value(&value);
            Ok(DnsRecord::CAA(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }))
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(&value);
            Ok(DnsRecord::CAA(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            }))
        }
        "iodef" => Ok(DnsRecord::CAA(CAARecord::Iodef {
            issuer_critical,
            url: value,
        })),
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

impl TryFrom<DnsRecord> for SafeDnsRecordContent {
    type Error = Error;

    fn try_from(record: DnsRecord) -> Result<Self, Self::Error> {
        match record {
            DnsRecord::A(addr) => Ok(SafeDnsRecordContent {
                record_type: "A",
                content: addr.to_string(),
                priority: None,
            }),
            DnsRecord::AAAA(addr) => Ok(SafeDnsRecordContent {
                record_type: "AAAA",
                content: addr.to_string(),
                priority: None,
            }),
            DnsRecord::CNAME(target) => Ok(SafeDnsRecordContent {
                record_type: "CNAME",
                content: target,
                priority: None,
            }),
            DnsRecord::NS(target) => Ok(SafeDnsRecordContent {
                record_type: "NS",
                content: target,
                priority: None,
            }),
            DnsRecord::MX(mx) => Ok(SafeDnsRecordContent {
                record_type: "MX",
                content: mx.exchange,
                priority: Some(mx.priority),
            }),
            DnsRecord::TXT(text) => {
                let mut buf = String::new();
                txt_chunks_to_text(&mut buf, &text, " ");
                Ok(SafeDnsRecordContent {
                    record_type: "TXT",
                    content: buf,
                    priority: None,
                })
            }
            DnsRecord::SRV(srv) => Ok(SafeDnsRecordContent {
                record_type: "SRV",
                content: format!("{} {} {}", srv.weight, srv.port, srv.target),
                priority: Some(srv.priority),
            }),
            DnsRecord::TLSA(_) => Err(Error::Api(
                "TLSA records are not supported by SafeDNS".to_string(),
            )),
            DnsRecord::CAA(caa) => {
                let (flags, tag, value) = caa.decompose();
                Ok(SafeDnsRecordContent {
                    record_type: "CAA",
                    content: format!("{flags} {tag} \"{value}\""),
                    priority: None,
                })
            }
        }
    }
}
