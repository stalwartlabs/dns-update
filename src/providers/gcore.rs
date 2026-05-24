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
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, KeyValue as DnsKeyValue, MXRecord,
    SRVRecord, TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector,
    http::{HttpClient, HttpClientBuilder},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{borrow::Cow, time::Duration};

const DEFAULT_API_ENDPOINT: &str = "https://api.gcore.com/dns";

#[derive(Clone)]
pub struct GcoreProvider {
    client: HttpClient,
    endpoint: Cow<'static, str>,
}

#[derive(Deserialize, Debug)]
struct Zone {
    name: String,
}

#[derive(Serialize, Debug)]
struct RrSet {
    ttl: u32,
    resource_records: Vec<ResourceRecord>,
}

#[derive(Serialize, Debug)]
struct ResourceRecord {
    content: Vec<Value>,
}

#[derive(Deserialize, Debug)]
struct RrSetResponse {
    #[serde(default)]
    ttl: u32,
    #[serde(default)]
    resource_records: Vec<ResourceRecordResponse>,
}

#[derive(Deserialize, Debug)]
struct ResourceRecordResponse {
    content: Vec<Value>,
}

impl GcoreProvider {
    pub(crate) fn new(api_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("APIKey {}", api_token.as_ref()))
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
        let zone = self.obtain_zone(&origin.into_name()).await?;
        let fqdn = name.into_name();
        let url = self.rrset_url(&zone, &fqdn, record_type);

        if records.is_empty() {
            return self
                .client
                .delete(url)
                .send_raw()
                .await
                .map(|_| ())
                .or_else(|err| match err {
                    Error::NotFound => Ok(()),
                    err => Err(err),
                });
        }

        let body = build_rrset_from_many(records, ttl)?;
        self.put_or_post(url, body).await
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
        check_record_types(record_type, &records)?;
        let zone = self.obtain_zone(&origin.into_name()).await?;
        let fqdn = name.into_name();
        let url = self.rrset_url(&zone, &fqdn, record_type);

        let to_add: Vec<Vec<Value>> = records.into_iter().map(record_to_content).collect();

        let (mut current, existed, effective_ttl) = match self.fetch_rrset(&url).await? {
            Some(existing) => {
                let existing_ttl = existing.ttl;
                let contents = existing
                    .resource_records
                    .into_iter()
                    .map(|r| r.content)
                    .collect::<Vec<_>>();
                (contents, true, existing_ttl)
            }
            None => (Vec::new(), false, ttl),
        };

        let before = current.len();
        for content in to_add {
            if !current.iter().any(|c| contents_equal(c, &content)) {
                current.push(content);
            }
        }

        if existed && current.len() == before {
            return Ok(());
        }

        let body = RrSet {
            ttl: effective_ttl,
            resource_records: current
                .into_iter()
                .map(|content| ResourceRecord { content })
                .collect(),
        };
        self.put_or_post(url, body).await
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
        check_record_types(record_type, &records)?;
        let zone = self.obtain_zone(&origin.into_name()).await?;
        let fqdn = name.into_name();
        let url = self.rrset_url(&zone, &fqdn, record_type);

        let existing = match self.fetch_rrset(&url).await? {
            Some(existing) => existing,
            None => return Ok(()),
        };

        let to_remove: Vec<Vec<Value>> = records.into_iter().map(record_to_content).collect();
        let original_len = existing.resource_records.len();
        let filtered: Vec<Vec<Value>> = existing
            .resource_records
            .into_iter()
            .map(|r| r.content)
            .filter(|content| !to_remove.iter().any(|r| contents_equal(r, content)))
            .collect();

        if filtered.len() == original_len {
            return Ok(());
        }

        if filtered.is_empty() {
            return self
                .client
                .delete(url)
                .send_raw()
                .await
                .map(|_| ())
                .or_else(|err| match err {
                    Error::NotFound => Ok(()),
                    err => Err(err),
                });
        }

        let body = RrSet {
            ttl: existing.ttl,
            resource_records: filtered
                .into_iter()
                .map(|content| ResourceRecord { content })
                .collect(),
        };
        self.client
            .put(url)
            .with_body(body)?
            .send_raw()
            .await
            .map(|_| ())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let zone = self.obtain_zone(&origin.into_name()).await?;
        let fqdn = name.into_name();
        let url = self.rrset_url(&zone, &fqdn, record_type);

        let existing = match self.fetch_rrset(&url).await? {
            Some(existing) => existing,
            None => return Ok(Vec::new()),
        };

        existing
            .resource_records
            .into_iter()
            .map(|r| parse_content(record_type, &r.content))
            .collect()
    }

    fn rrset_url(&self, zone: &str, fqdn: &str, record_type: DnsRecordType) -> String {
        format!(
            "{}/v2/zones/{}/{}/{}",
            self.endpoint,
            zone,
            fqdn,
            record_type.as_str()
        )
    }

    async fn fetch_rrset(&self, url: &str) -> crate::Result<Option<RrSetResponse>> {
        match self
            .client
            .get(url.to_string())
            .send_with_retry::<RrSetResponse>(3)
            .await
        {
            Ok(rrset) => Ok(Some(rrset)),
            Err(Error::NotFound) => Ok(None),
            Err(err) => Err(err),
        }
    }

    async fn put_or_post(&self, url: String, body: RrSet) -> crate::Result<()> {
        match self
            .client
            .put(url.clone())
            .with_body(&body)?
            .send_raw()
            .await
        {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => self
                .client
                .post(url)
                .with_body(body)?
                .send_raw()
                .await
                .map(|_| ()),
            Err(err) => Err(err),
        }
    }

    async fn obtain_zone(&self, origin: &str) -> crate::Result<String> {
        let mut candidate: &str = origin;
        loop {
            let result = self
                .client
                .get(format!("{}/v2/zones/{}", self.endpoint, candidate))
                .send_with_retry::<Zone>(3)
                .await;
            match result {
                Ok(zone) => return Ok(zone.name),
                Err(Error::NotFound) => {}
                Err(err) => return Err(err),
            }
            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => {
                    return Err(Error::Api(format!("No Gcore zone found for {origin}")));
                }
            }
        }
    }
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> crate::Result<()> {
    for record in records {
        if record.as_type() != expected {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected.as_str(),
                record.as_type().as_str(),
            )));
        }
    }
    Ok(())
}

fn build_rrset_from_many(records: Vec<DnsRecord>, ttl: u32) -> crate::Result<RrSet> {
    Ok(RrSet {
        ttl,
        resource_records: records
            .into_iter()
            .map(|r| ResourceRecord {
                content: record_to_content(r),
            })
            .collect(),
    })
}

fn record_to_content(record: DnsRecord) -> Vec<Value> {
    match record {
        DnsRecord::A(addr) => vec![Value::String(addr.to_string())],
        DnsRecord::AAAA(addr) => vec![Value::String(addr.to_string())],
        DnsRecord::CNAME(content) => vec![Value::String(content)],
        DnsRecord::NS(content) => vec![Value::String(content)],
        DnsRecord::MX(mx) => vec![
            Value::Number(mx.priority.into()),
            Value::String(mx.exchange),
        ],
        DnsRecord::TXT(content) => vec![Value::String(content)],
        DnsRecord::SRV(srv) => vec![
            Value::Number(srv.priority.into()),
            Value::Number(srv.weight.into()),
            Value::Number(srv.port.into()),
            Value::String(srv.target),
        ],
        DnsRecord::TLSA(tlsa) => vec![Value::String(tlsa.to_string())],
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.decompose();
            vec![
                Value::Number(flags.into()),
                Value::String(tag),
                Value::String(value),
            ]
        }
    }
}

fn contents_equal(a: &[Value], b: &[Value]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(x, y)| values_equal(x, y))
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Number(x), Value::Number(y)) => match (x.as_i64(), y.as_i64()) {
            (Some(xi), Some(yi)) => xi == yi,
            _ => match (x.as_u64(), y.as_u64()) {
                (Some(xu), Some(yu)) => xu == yu,
                _ => match (x.as_f64(), y.as_f64()) {
                    (Some(xf), Some(yf)) => xf == yf,
                    _ => false,
                },
            },
        },
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Null, Value::Null) => true,
        _ => a == b,
    }
}

fn parse_content(record_type: DnsRecordType, content: &[Value]) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => {
            let s = expect_string(content, 0, "A")?;
            s.parse()
                .map(DnsRecord::A)
                .map_err(|e| Error::Parse(format!("invalid A record: {e}")))
        }
        DnsRecordType::AAAA => {
            let s = expect_string(content, 0, "AAAA")?;
            s.parse()
                .map(DnsRecord::AAAA)
                .map_err(|e| Error::Parse(format!("invalid AAAA record: {e}")))
        }
        DnsRecordType::CNAME => {
            let s = expect_string(content, 0, "CNAME")?;
            Ok(DnsRecord::CNAME(strip_trailing_dot(s)))
        }
        DnsRecordType::NS => {
            let s = expect_string(content, 0, "NS")?;
            Ok(DnsRecord::NS(strip_trailing_dot(s)))
        }
        DnsRecordType::MX => {
            if content.len() < 2 {
                return Err(Error::Parse(format!(
                    "invalid MX content array length: {}",
                    content.len()
                )));
            }
            let priority = expect_u16(content, 0, "MX")?;
            let exchange = expect_string(content, 1, "MX")?;
            Ok(DnsRecord::MX(MXRecord {
                priority,
                exchange: strip_trailing_dot(exchange),
            }))
        }
        DnsRecordType::TXT => {
            let s = expect_string(content, 0, "TXT")?;
            Ok(DnsRecord::TXT(s.to_string()))
        }
        DnsRecordType::SRV => {
            if content.len() < 4 {
                return Err(Error::Parse(format!(
                    "invalid SRV content array length: {}",
                    content.len()
                )));
            }
            let priority = expect_u16(content, 0, "SRV")?;
            let weight = expect_u16(content, 1, "SRV")?;
            let port = expect_u16(content, 2, "SRV")?;
            let target = expect_string(content, 3, "SRV")?;
            Ok(DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target: strip_trailing_dot(target),
            }))
        }
        DnsRecordType::TLSA => {
            let s = expect_string(content, 0, "TLSA")?;
            parse_tlsa_text(s)
        }
        DnsRecordType::CAA => {
            if content.len() < 3 {
                return Err(Error::Parse(format!(
                    "invalid CAA content array length: {}",
                    content.len()
                )));
            }
            let flags = expect_u8(content, 0, "CAA")?;
            let tag = expect_string(content, 1, "CAA")?.to_string();
            let value = expect_string(content, 2, "CAA")?.to_string();
            build_caa(flags, &tag, value)
        }
    }
}

fn expect_string<'a>(content: &'a [Value], idx: usize, rtype: &str) -> crate::Result<&'a str> {
    match content.get(idx) {
        Some(Value::String(s)) => Ok(s.as_str()),
        Some(other) => Err(Error::Parse(format!(
            "expected string at position {idx} for {rtype}, got: {other}"
        ))),
        None => Err(Error::Parse(format!(
            "missing element at position {idx} for {rtype}"
        ))),
    }
}

fn expect_u16(content: &[Value], idx: usize, rtype: &str) -> crate::Result<u16> {
    match content.get(idx) {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| Error::Parse(format!("invalid u16 at position {idx} for {rtype}: {n}"))),
        Some(other) => Err(Error::Parse(format!(
            "expected number at position {idx} for {rtype}, got: {other}"
        ))),
        None => Err(Error::Parse(format!(
            "missing element at position {idx} for {rtype}"
        ))),
    }
}

fn expect_u8(content: &[Value], idx: usize, rtype: &str) -> crate::Result<u8> {
    match content.get(idx) {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| Error::Parse(format!("invalid u8 at position {idx} for {rtype}: {n}"))),
        Some(other) => Err(Error::Parse(format!(
            "expected number at position {idx} for {rtype}, got: {other}"
        ))),
        None => Err(Error::Parse(format!(
            "missing element at position {idx} for {rtype}"
        ))),
    }
}

fn strip_trailing_dot(s: &str) -> String {
    s.strip_suffix('.').unwrap_or(s).to_string()
}

fn parse_tlsa_text(text: &str) -> crate::Result<DnsRecord> {
    let mut parts = text.split_whitespace();
    let usage: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA record: {text}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA usage: {e}")))?;
    let selector: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA record: {text}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA selector: {e}")))?;
    let matching: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA record: {text}")))?
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

fn build_caa(flags: u8, tag: &str, value: String) -> crate::Result<DnsRecord> {
    let issuer_critical = flags & 0x80 != 0;
    Ok(DnsRecord::CAA(match tag {
        "issue" => {
            let (name, options) = parse_caa_value(&value);
            CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(&value);
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
    }))
}

fn parse_caa_value(value: &str) -> (Option<String>, Vec<DnsKeyValue>) {
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
            Some((k, v)) => DnsKeyValue {
                key: k.trim().to_string(),
                value: v.trim().to_string(),
            },
            None => DnsKeyValue {
                key: p.trim().to_string(),
                value: String::new(),
            },
        })
        .collect();
    (name, options)
}
