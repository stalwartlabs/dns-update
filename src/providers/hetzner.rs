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
    TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector,
    http::{HttpClient, HttpClientBuilder},
    utils::{strip_origin_from_name, txt_chunks_to_text},
};
use serde::{Deserialize, Serialize};
use std::{net::AddrParseError, time::Duration};

#[derive(Clone)]
pub struct HetznerProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct SetRecordsBody {
    records: Vec<RecordValue>,
}

#[derive(Serialize, Debug)]
struct RemoveRecordsBody {
    records: Vec<RecordValue>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RecordValue {
    value: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ActionResponse {
    #[serde(default)]
    action: Option<serde_json::Value>,
    #[serde(default)]
    rrset: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct ListRRSetsResponse {
    #[serde(default)]
    rrsets: Vec<ListedRRSet>,
}

#[derive(Deserialize, Debug)]
struct ListedRRSet {
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default)]
    records: Vec<RecordValue>,
}

const DEFAULT_API_ENDPOINT: &str = "https://api.hetzner.cloud/v1";
const RETRIES: u32 = 3;

impl HetznerProvider {
    pub(crate) fn new(
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let token = api_token.as_ref();
        if token.is_empty() {
            return Err(Error::Api(
                "Hetzner API token must not be empty".to_string(),
            ));
        }

        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {token}"))
            .with_timeout(timeout)
            .build();

        Ok(Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
        })
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
        check_record_types(record_type, &records)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));

        if records.is_empty() {
            return self.delete_rrset(&domain, &subdomain, record_type).await;
        }

        let values = build_values(records)?;

        match self
            .post_set_records(&domain, &subdomain, record_type, &values)
            .await
        {
            Ok(_) => self.change_ttl(&domain, &subdomain, record_type, ttl).await,
            Err(Error::NotFound) => {
                self.add_records_then_change_ttl(&domain, &subdomain, record_type, ttl, values)
                    .await
            }
            Err(e) => Err(e),
        }
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let values = build_values(records)?;

        match self
            .post_add_records(&domain, &subdomain, record_type, &values)
            .await
        {
            Ok(_) => self.change_ttl(&domain, &subdomain, record_type, ttl).await,
            Err(Error::NotFound) => {
                self.set_records_then_change_ttl(&domain, &subdomain, record_type, ttl, values)
                    .await
            }
            Err(e) => Err(e),
        }
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let values = build_values(records)?;

        let url = format!(
            "{}/zones/{}/rrsets/{}/{}/actions/remove_records",
            self.endpoint,
            domain,
            subdomain,
            record_type.as_str(),
        );

        match self
            .client
            .post(url)
            .with_body(RemoveRecordsBody { records: values })?
            .send_with_retry::<ActionResponse>(RETRIES)
            .await
        {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));

        let query = serde_urlencoded::to_string([
            ("name", subdomain.as_str()),
            ("type", record_type.as_str()),
            ("per_page", "50"),
        ])
        .map_err(|e| Error::Serialize(e.to_string()))?;

        let url = format!("{}/zones/{}/rrsets?{}", self.endpoint, domain, query);

        let response: ListRRSetsResponse = match self.client.get(url).send_with_retry(RETRIES).await
        {
            Ok(r) => r,
            Err(Error::NotFound) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };

        let expected_type = record_type.as_str();
        let mut out = Vec::new();
        for rrset in response.rrsets {
            if rrset.record_type != expected_type {
                continue;
            }
            for r in rrset.records {
                out.push(parse_value(record_type, &r.value)?);
            }
        }
        Ok(out)
    }

    async fn post_set_records(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        values: &[RecordValue],
    ) -> crate::Result<()> {
        let url = format!(
            "{}/zones/{}/rrsets/{}/{}/actions/set_records",
            self.endpoint,
            domain,
            subdomain,
            record_type.as_str(),
        );

        self.client
            .post(url)
            .with_body(SetRecordsBody {
                records: values.to_vec(),
            })?
            .send_with_retry::<ActionResponse>(RETRIES)
            .await
            .map(|_| ())
    }

    async fn post_add_records(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        values: &[RecordValue],
    ) -> crate::Result<()> {
        let url = format!(
            "{}/zones/{}/rrsets/{}/{}/actions/add_records",
            self.endpoint,
            domain,
            subdomain,
            record_type.as_str(),
        );

        self.client
            .post(url)
            .with_body(SetRecordsBody {
                records: values.to_vec(),
            })?
            .send_with_retry::<ActionResponse>(RETRIES)
            .await
            .map(|_| ())
    }

    async fn add_records_then_change_ttl(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
        values: Vec<RecordValue>,
    ) -> crate::Result<()> {
        self.post_add_records(domain, subdomain, record_type, &values)
            .await?;
        self.change_ttl(domain, subdomain, record_type, ttl).await
    }

    async fn set_records_then_change_ttl(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
        values: Vec<RecordValue>,
    ) -> crate::Result<()> {
        self.post_set_records(domain, subdomain, record_type, &values)
            .await?;
        self.change_ttl(domain, subdomain, record_type, ttl).await
    }

    async fn delete_rrset(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        match self
            .client
            .delete(format!(
                "{}/zones/{}/rrsets/{}/{}",
                self.endpoint,
                domain,
                subdomain,
                record_type.as_str(),
            ))
            .send_raw()
            .await
        {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn change_ttl(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
    ) -> crate::Result<()> {
        #[derive(Serialize)]
        struct ChangeTtl {
            ttl: u32,
        }

        let url = format!(
            "{}/zones/{}/rrsets/{}/{}/actions/change_ttl",
            self.endpoint,
            domain,
            subdomain,
            record_type.as_str(),
        );

        self.client
            .post(url)
            .with_body(ChangeTtl { ttl })?
            .send_with_retry::<ActionResponse>(RETRIES)
            .await
            .map(|_| ())
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

fn build_values(records: Vec<DnsRecord>) -> crate::Result<Vec<RecordValue>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        out.push(RecordValue {
            value: render_value(record)?,
        });
    }
    Ok(out)
}

fn render_value(record: DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => ensure_trailing_dot(content),
        DnsRecord::NS(content) => ensure_trailing_dot(content),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, ensure_trailing_dot(mx.exchange)),
        DnsRecord::TXT(content) => {
            let mut out = String::with_capacity(content.len() + 4);
            txt_chunks_to_text(&mut out, &content, " ");
            out
        }
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            ensure_trailing_dot(srv.target),
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    })
}

fn parse_value(record_type: DnsRecordType, value: &str) -> crate::Result<DnsRecord> {
    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(value.parse().map_err(|e: AddrParseError| {
            Error::Parse(format!("invalid A value '{value}': {e}"))
        })?),
        DnsRecordType::AAAA => DnsRecord::AAAA(value.parse().map_err(|e: AddrParseError| {
            Error::Parse(format!("invalid AAAA value '{value}': {e}"))
        })?),
        DnsRecordType::CNAME => DnsRecord::CNAME(strip_trailing_dot(value)),
        DnsRecordType::NS => DnsRecord::NS(strip_trailing_dot(value)),
        DnsRecordType::MX => parse_mx(value)?,
        DnsRecordType::TXT => DnsRecord::TXT(parse_txt(value)),
        DnsRecordType::SRV => parse_srv(value)?,
        DnsRecordType::TLSA => parse_tlsa(value)?,
        DnsRecordType::CAA => parse_caa(value)?,
    })
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

fn ensure_trailing_dot(value: String) -> String {
    if value.ends_with('.') {
        value
    } else {
        format!("{value}.")
    }
}

fn strip_trailing_dot(value: &str) -> String {
    value.strip_suffix('.').unwrap_or(value).to_string()
}
