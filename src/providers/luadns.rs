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
    utils::txt_chunks_to_text,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.luadns.com";
const PAGE_SIZE: u32 = 500;

#[derive(Clone)]
pub struct LuaDnsProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct LuaZone {
    pub id: i64,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LuaRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub name: String,
    #[serde(rename = "type")]
    pub rr_type: String,
    pub content: String,
    pub ttl: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<i64>,
}

impl LuaDnsProvider {
    pub(crate) fn new(
        api_username: impl AsRef<str>,
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let raw = format!("{}:{}", api_username.as_ref(), api_token.as_ref());
        let encoded = B64.encode(raw);
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {encoded}"))
            .with_header("Accept", "application/json")
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

    async fn list_zones(&self) -> crate::Result<Vec<LuaZone>> {
        let mut out: Vec<LuaZone> = Vec::new();
        let mut page: u32 = 1;
        loop {
            let chunk: Vec<LuaZone> = self
                .client
                .get(format!(
                    "{}/v1/zones?limit={PAGE_SIZE}&page={page}",
                    self.endpoint
                ))
                .send_with_retry(3)
                .await?;
            let received = chunk.len();
            out.extend(chunk);
            if (received as u32) < PAGE_SIZE {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    async fn find_zone(&self, origin: &str) -> crate::Result<LuaZone> {
        let zones = self.list_zones().await?;
        zones
            .into_iter()
            .find(|z| z.name.eq_ignore_ascii_case(origin))
            .ok_or_else(|| Error::Api(format!("LuaDNS zone {origin} not found")))
    }

    async fn list_records(&self, zone_id: i64) -> crate::Result<Vec<LuaRecord>> {
        let mut out: Vec<LuaRecord> = Vec::new();
        let mut page: u32 = 1;
        loop {
            let chunk: Vec<LuaRecord> = self
                .client
                .get(format!(
                    "{}/v1/zones/{zone_id}/records?limit={PAGE_SIZE}&page={page}",
                    self.endpoint
                ))
                .send_with_retry(3)
                .await?;
            let received = chunk.len();
            out.extend(chunk);
            if (received as u32) < PAGE_SIZE {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    async fn list_at(
        &self,
        zone_id: i64,
        fqdn: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<LuaRecord>> {
        let target = fqdn.trim_end_matches('.');
        let rr_type = record_type.as_str();
        let records = self.list_records(zone_id).await?;
        Ok(records
            .into_iter()
            .filter(|r| r.rr_type == rr_type && r.name.trim_end_matches('.') == target)
            .collect())
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
        let origin_name = origin.into_name().to_string();
        let zone = self.find_zone(&origin_name).await?;
        let fqdn = name.into_fqdn().to_string();
        let desired = build_contents(record_type, records)?;
        let mut existing_pool = self.list_at(zone.id, &fqdn, record_type).await?;

        let mut to_add = Vec::new();
        for content in desired {
            if let Some(idx) = existing_pool.iter().position(|r| r.content == content) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(content);
            }
        }

        for entry in existing_pool {
            if let Some(id) = entry.id {
                self.delete_record(zone.id, id).await?;
            }
        }
        for content in to_add {
            self.create_raw(zone.id, &fqdn, record_type, ttl, content)
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
        let origin_name = origin.into_name().to_string();
        let zone = self.find_zone(&origin_name).await?;
        let fqdn = name.into_fqdn().to_string();
        let desired = build_contents(record_type, records)?;
        let existing = self.list_at(zone.id, &fqdn, record_type).await?;

        for content in desired {
            if existing.iter().any(|r| r.content == content) {
                continue;
            }
            self.create_raw(zone.id, &fqdn, record_type, ttl, content)
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
        let origin_name = origin.into_name().to_string();
        let zone = self.find_zone(&origin_name).await?;
        let fqdn = name.into_fqdn().to_string();
        let to_remove = build_contents(record_type, records)?;
        let existing = self.list_at(zone.id, &fqdn, record_type).await?;

        for content in to_remove {
            if let Some(entry) = existing.iter().find(|r| r.content == content)
                && let Some(id) = entry.id
            {
                self.delete_record(zone.id, id).await?;
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
        let origin_name = origin.into_name().to_string();
        let zone = self.find_zone(&origin_name).await?;
        let fqdn = name.into_fqdn().to_string();
        let listed = self.list_at(zone.id, &fqdn, record_type).await?;
        listed
            .into_iter()
            .map(|r| parse_content(record_type, &r.content))
            .collect()
    }

    async fn create_raw(
        &self,
        zone_id: i64,
        fqdn: &str,
        record_type: DnsRecordType,
        ttl: u32,
        content: String,
    ) -> crate::Result<()> {
        let body = LuaRecord {
            id: None,
            name: fqdn.to_string(),
            rr_type: record_type.as_str().to_string(),
            content,
            ttl,
            zone_id: None,
        };
        self.client
            .post(format!("{}/v1/zones/{zone_id}/records", self.endpoint))
            .with_body(&body)?
            .send_with_retry::<LuaRecord>(3)
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, zone_id: i64, record_id: i64) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/v1/zones/{zone_id}/records/{record_id}",
                self.endpoint
            ))
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn ensure_dot(name: String) -> String {
    if name.ends_with('.') {
        name
    } else {
        format!("{name}.")
    }
}

fn render_content(record: DnsRecord) -> String {
    match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => ensure_dot(content),
        DnsRecord::NS(content) => ensure_dot(content),
        DnsRecord::TXT(content) => {
            let mut out = String::with_capacity(content.len() + 4);
            txt_chunks_to_text(&mut out, &content, " ");
            out
        }
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, ensure_dot(mx.exchange)),
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            ensure_dot(srv.target)
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    }
}

fn build_contents(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<String>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(render_content(record));
    }
    Ok(out)
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

fn parse_content(record_type: DnsRecordType, content: &str) -> crate::Result<DnsRecord> {
    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(
            content
                .parse()
                .map_err(|e| Error::Parse(format!("invalid A value '{content}': {e}")))?,
        ),
        DnsRecordType::AAAA => DnsRecord::AAAA(
            content
                .parse()
                .map_err(|e| Error::Parse(format!("invalid AAAA value '{content}': {e}")))?,
        ),
        DnsRecordType::CNAME => DnsRecord::CNAME(strip_trailing_dot(content)),
        DnsRecordType::NS => DnsRecord::NS(strip_trailing_dot(content)),
        DnsRecordType::MX => parse_mx(content)?,
        DnsRecordType::TXT => DnsRecord::TXT(parse_txt(content)),
        DnsRecordType::SRV => parse_srv(content)?,
        DnsRecordType::TLSA => parse_tlsa(content)?,
        DnsRecordType::CAA => parse_caa(content)?,
    })
}

fn parse_mx(value: &str) -> crate::Result<DnsRecord> {
    let mut parts = value.splitn(2, char::is_whitespace);
    let priority = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid MX value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid MX priority in '{value}': {e}")))?;
    let exchange = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid MX value '{value}'")))?
        .trim();
    Ok(DnsRecord::MX(MXRecord {
        priority,
        exchange: strip_trailing_dot(exchange),
    }))
}

fn parse_srv(value: &str) -> crate::Result<DnsRecord> {
    let mut parts = value.split_whitespace();
    let priority = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV priority in '{value}': {e}")))?;
    let weight = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV weight in '{value}': {e}")))?;
    let port = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV port in '{value}': {e}")))?;
    let target = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV value '{value}'")))?;
    Ok(DnsRecord::SRV(SRVRecord {
        priority,
        weight,
        port,
        target: strip_trailing_dot(target),
    }))
}

fn parse_txt(value: &str) -> String {
    let trimmed = value.trim();
    let mut out = String::with_capacity(trimmed.len());
    let mut bytes = trimmed.bytes().peekable();
    while let Some(&b) = bytes.peek() {
        if b != b'"' {
            bytes.next();
            continue;
        }
        bytes.next();
        loop {
            match bytes.next() {
                Some(b'"') => break,
                Some(b'\\') => {
                    if let Some(next) = bytes.next() {
                        out.push(next as char);
                    }
                }
                Some(other) => out.push(other as char),
                None => break,
            }
        }
    }
    if out.is_empty() && !trimmed.is_empty() && !trimmed.starts_with('"') {
        return trimmed.to_string();
    }
    out
}

fn parse_tlsa(content: &str) -> crate::Result<DnsRecord> {
    let mut parts = content.split_whitespace();
    let usage: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA usage: {e}")))?;
    let selector: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA selector: {e}")))?;
    let matching: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA matching: {e}")))?;
    let hex: String = parts.collect::<Vec<_>>().join("");
    Ok(DnsRecord::TLSA(TLSARecord {
        cert_usage: tlsa_cert_usage_from_u8(usage)?,
        selector: tlsa_selector_from_u8(selector)?,
        matching: tlsa_matching_from_u8(matching)?,
        cert_data: decode_hex(&hex)?,
    }))
}

fn parse_caa(value: &str) -> crate::Result<DnsRecord> {
    let mut parts = value.splitn(3, char::is_whitespace);
    let flags: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags in '{value}': {e}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value '{value}'")))?
        .to_ascii_lowercase();
    let raw_value = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value '{value}'")))?
        .trim();
    let unquoted = raw_value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .map(|s| s.replace("\\\"", "\""))
        .unwrap_or_else(|| raw_value.to_string());

    let issuer_critical = flags & 0x80 != 0;
    match tag.as_str() {
        "issue" => {
            let (name, options) = parse_caa_kv(&unquoted);
            Ok(DnsRecord::CAA(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }))
        }
        "issuewild" => {
            let (name, options) = parse_caa_kv(&unquoted);
            Ok(DnsRecord::CAA(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            }))
        }
        "iodef" => Ok(DnsRecord::CAA(CAARecord::Iodef {
            issuer_critical,
            url: unquoted,
        })),
        other => Err(Error::Parse(format!("unknown CAA tag: {other}"))),
    }
}

fn parse_caa_kv(value: &str) -> (Option<String>, Vec<KeyValue>) {
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

fn strip_trailing_dot(value: &str) -> String {
    value.strip_suffix('.').unwrap_or(value).to_string()
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
