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
    TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector, http::HttpClientBuilder,
    utils::strip_origin_from_name,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api.dnsimple.com/v2";

#[derive(Clone)]
pub struct DNSimpleProvider {
    client: HttpClientBuilder,
    account_id: String,
    endpoint: String,
}

#[derive(Deserialize, Debug)]
pub struct ApiResponse<T> {
    pub data: T,
}

#[derive(Deserialize, Debug)]
pub struct RecordEntry {
    pub id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    pub ttl: u32,
    pub priority: Option<u16>,
}

#[derive(Serialize, Debug)]
pub struct CreateRecordParams {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    pub ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
}

#[derive(Serialize, Debug)]
struct ListRecordsQuery<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    type_filter: &'a str,
    per_page: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordContent {
    content: String,
    priority: Option<u16>,
}

#[derive(Debug, Clone)]
struct ListedRecord {
    id: i64,
    content: RecordContent,
}

impl DNSimpleProvider {
    pub(crate) fn new(
        auth_token: impl AsRef<str>,
        account_id: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", auth_token.as_ref()))
            .with_timeout(timeout);
        Self {
            client,
            account_id: account_id.as_ref().to_string(),
            endpoint: DEFAULT_ENDPOINT.to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    fn base_url(&self) -> String {
        format!("{}/{}/zones", self.endpoint, self.account_id)
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let zone = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &zone, Some(""));
        let desired = build_contents(record_type, records)?;
        let existing = self.list_at(&zone, &subdomain, record_type).await?;

        let mut to_add: Vec<RecordContent> = Vec::new();
        let mut existing_pool = existing;

        for content in desired {
            if let Some(idx) = existing_pool.iter().position(|r| r.content == content) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(content);
            }
        }

        for entry in existing_pool {
            self.delete_record(&zone, entry.id).await?;
        }
        for content in to_add {
            self.create_record(&zone, &subdomain, record_type, ttl, content)
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
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name();
        let zone = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &zone, Some(""));
        let desired = build_contents(record_type, records)?;
        let existing = self.list_at(&zone, &subdomain, record_type).await?;

        for content in desired {
            if existing.iter().any(|r| r.content == content) {
                continue;
            }
            self.create_record(&zone, &subdomain, record_type, ttl, content)
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
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name();
        let zone = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &zone, Some(""));
        let to_remove = build_contents(record_type, records)?;
        let existing = self.list_at(&zone, &subdomain, record_type).await?;

        for content in to_remove {
            if let Some(entry) = existing.iter().find(|r| r.content == content) {
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
        let name = name.into_name();
        let zone = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &zone, Some(""));
        let listed = self.list_at(&zone, &subdomain, record_type).await?;
        listed
            .into_iter()
            .map(|r| record_from_content(record_type, &r.content))
            .collect()
    }

    async fn list_at(
        &self,
        zone: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ListedRecord>> {
        let query = ListRecordsQuery {
            name: subdomain,
            type_filter: record_type.as_str(),
            per_page: 100,
        };
        let url = format!(
            "{}/{}/records?{}",
            self.base_url(),
            zone,
            serde_urlencoded::to_string(&query).expect("urlencoded encoding of list query")
        );
        let response: ApiResponse<Vec<RecordEntry>> =
            self.client.get(url).send_with_retry(3).await?;
        let target_type = record_type.as_str();
        Ok(response
            .data
            .into_iter()
            .filter(|r| r.name == subdomain && r.record_type == target_type)
            .map(|r| ListedRecord {
                id: r.id,
                content: RecordContent {
                    content: r.content,
                    priority: r.priority,
                },
            })
            .collect())
    }

    async fn create_record(
        &self,
        zone: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
        content: RecordContent,
    ) -> crate::Result<()> {
        self.client
            .post(format!("{}/{}/records", self.base_url(), zone))
            .with_body(CreateRecordParams {
                name: subdomain.to_string(),
                record_type: record_type.as_str().to_string(),
                content: content.content,
                ttl,
                priority: content.priority,
            })?
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, zone: &str, record_id: i64) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/{}/records/{}",
                self.base_url(),
                zone,
                record_id
            ))
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn build_contents(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<RecordContent>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        let (content, priority) = record_content_and_priority(&record);
        out.push(RecordContent { content, priority });
    }
    Ok(out)
}

fn record_content_and_priority(record: &DnsRecord) -> (String, Option<u16>) {
    match record {
        DnsRecord::A(content) => (content.to_string(), None),
        DnsRecord::AAAA(content) => (content.to_string(), None),
        DnsRecord::CNAME(content) => (content.clone(), None),
        DnsRecord::NS(content) => (content.clone(), None),
        DnsRecord::MX(mx) => (mx.exchange.clone(), Some(mx.priority)),
        DnsRecord::TXT(content) => (content.clone(), None),
        DnsRecord::SRV(srv) => (
            format!("{} {} {}", srv.weight, srv.port, srv.target),
            Some(srv.priority),
        ),
        DnsRecord::TLSA(value) => (value.to_string(), None),
        DnsRecord::CAA(caa) => (caa.to_string(), None),
    }
}

fn record_from_content(
    record_type: DnsRecordType,
    content: &RecordContent,
) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => content
            .content
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A content {:?}: {e}", content.content))),
        DnsRecordType::AAAA => {
            content.content.parse().map(DnsRecord::AAAA).map_err(|e| {
                Error::Parse(format!("invalid AAAA content {:?}: {e}", content.content))
            })
        }
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(content.content.clone())),
        DnsRecordType::NS => Ok(DnsRecord::NS(content.content.clone())),
        DnsRecordType::MX => Ok(DnsRecord::MX(MXRecord {
            exchange: content.content.clone(),
            priority: content.priority.unwrap_or(0),
        })),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(content.content.clone())),
        DnsRecordType::SRV => parse_srv(&content.content, content.priority.unwrap_or(0)),
        DnsRecordType::TLSA => parse_tlsa(&content.content).map(DnsRecord::TLSA),
        DnsRecordType::CAA => parse_caa(&content.content).map(DnsRecord::CAA),
    }
}

fn parse_srv(content: &str, priority: u16) -> crate::Result<DnsRecord> {
    let mut parts = content.split_whitespace();
    let weight: u16 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("SRV missing weight: {content:?}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("SRV invalid weight: {e}")))?;
    let port: u16 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("SRV missing port: {content:?}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("SRV invalid port: {e}")))?;
    let target = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("SRV missing target: {content:?}")))?
        .to_string();
    if parts.next().is_some() {
        return Err(Error::Parse(format!("SRV extra fields: {content:?}")));
    }
    Ok(DnsRecord::SRV(SRVRecord {
        priority,
        weight,
        port,
        target,
    }))
}

fn parse_tlsa(content: &str) -> crate::Result<TLSARecord> {
    let mut parts = content.split_whitespace();
    let usage: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("TLSA missing usage: {content:?}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("TLSA invalid usage: {e}")))?;
    let selector: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("TLSA missing selector: {content:?}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("TLSA invalid selector: {e}")))?;
    let matching: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("TLSA missing matching: {content:?}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("TLSA invalid matching: {e}")))?;
    let cert_hex = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("TLSA missing cert data: {content:?}")))?;
    if parts.next().is_some() {
        return Err(Error::Parse(format!("TLSA extra fields: {content:?}")));
    }
    Ok(TLSARecord {
        cert_usage: tlsa_cert_usage_from_u8(usage)?,
        selector: tlsa_selector_from_u8(selector)?,
        matching: tlsa_matching_from_u8(matching)?,
        cert_data: decode_hex(cert_hex)?,
    })
}

fn parse_caa(content: &str) -> crate::Result<CAARecord> {
    let mut parts = content.splitn(3, char::is_whitespace);
    let flags: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("CAA missing flags: {content:?}")))?
        .trim()
        .parse()
        .map_err(|e| Error::Parse(format!("CAA invalid flags: {e}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("CAA missing tag: {content:?}")))?
        .trim()
        .to_string();
    let raw_value = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("CAA missing value: {content:?}")))?
        .trim();
    let value = raw_value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(raw_value)
        .to_string();
    let issuer_critical = flags & 0x80 != 0;
    match tag.as_str() {
        "issue" => {
            let (name, options) = parse_caa_value(&value);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(&value);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: value,
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

fn tlsa_cert_usage_from_u8(value: u8) -> crate::Result<TlsaCertUsage> {
    Ok(match value {
        0 => TlsaCertUsage::PkixTa,
        1 => TlsaCertUsage::PkixEe,
        2 => TlsaCertUsage::DaneTa,
        3 => TlsaCertUsage::DaneEe,
        255 => TlsaCertUsage::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA cert usage: {value}"))),
    })
}

fn tlsa_selector_from_u8(value: u8) -> crate::Result<TlsaSelector> {
    Ok(match value {
        0 => TlsaSelector::Full,
        1 => TlsaSelector::Spki,
        255 => TlsaSelector::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA selector: {value}"))),
    })
}

fn tlsa_matching_from_u8(value: u8) -> crate::Result<TlsaMatching> {
    Ok(match value {
        0 => TlsaMatching::Raw,
        1 => TlsaMatching::Sha256,
        2 => TlsaMatching::Sha512,
        255 => TlsaMatching::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA matching: {value}"))),
    })
}

fn decode_hex(hex: &str) -> crate::Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::Parse(format!("invalid hex string: {hex}")));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| Error::Parse(format!("invalid hex byte: {e}")))
        })
        .collect()
}
