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
    crypto::{hmac_sha256, sha256_digest},
    http::{HttpClient, HttpClientBuilder, HttpRequest},
    utils::txt_chunks_to_text,
};
use chrono::Utc;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::{net::AddrParseError, time::Duration};

const HUAWEI_ALGORITHM: &str = "SDK-HMAC-SHA256";
const PAGE_LIMIT: u32 = 500;

#[derive(Clone)]
pub struct HuaweiCloudProvider {
    client: HttpClient,
    access_key: String,
    secret_key: String,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecordSetBody<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    rr_type: &'a str,
    ttl: u32,
    records: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
}

#[derive(Serialize, Debug)]
struct UpdateRecordSetBody<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    rr_type: &'a str,
    ttl: u32,
    records: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
}

#[derive(Deserialize, Debug)]
struct CreateRecordSetResponse {}

#[derive(Deserialize, Debug)]
struct ListZonesResponse {
    #[serde(default)]
    zones: Vec<HuaweiZone>,
    #[serde(default)]
    links: Option<HuaweiLinks>,
}

#[derive(Deserialize, Debug)]
struct HuaweiZone {
    id: String,
    name: String,
}

#[derive(Deserialize, Debug)]
struct ListRecordSetsResponse {
    #[serde(default)]
    recordsets: Vec<HuaweiRecordSet>,
    #[serde(default)]
    links: Option<HuaweiLinks>,
}

#[derive(Deserialize, Debug)]
struct HuaweiRecordSet {
    id: String,
    name: String,
    #[serde(rename = "type")]
    rr_type: String,
    #[serde(default)]
    ttl: u32,
    #[serde(default)]
    records: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct HuaweiLinks {
    #[serde(default)]
    next: Option<String>,
}

impl HuaweiCloudProvider {
    pub(crate) fn new(
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        region: impl Into<String>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let access_key = access_key.into();
        let secret_key = secret_key.into();
        let region = region.into();

        if access_key.is_empty() || secret_key.is_empty() || region.is_empty() {
            return Err(Error::Api("huaweicloud: credentials missing".to_string()));
        }

        let endpoint = format!("https://dns.{}.myhuaweicloud.com", region);
        let client = HttpClientBuilder::default().with_timeout(timeout).build();

        Ok(Self {
            client,
            access_key,
            secret_key,
            endpoint,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl Into<String>) -> Self {
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
        reject_tlsa(record_type)?;
        let name_fqdn = ensure_fqdn(&name.into_name());
        let zone_id = self.resolve_zone_id(origin).await?;

        let existing = self
            .find_recordset(&zone_id, &name_fqdn, record_type.as_str())
            .await?;

        if records.is_empty() {
            if let Some(rs) = existing {
                let path = format!("/v2/zones/{}/recordsets/{}", zone_id, rs.id);
                let _ = self
                    .send_signed_raw(Method::DELETE, &path, "", None)
                    .await?;
            }
            return Ok(());
        }

        let values = render_records(&records)?;

        match existing {
            Some(rs) => {
                self.put_recordset(&zone_id, &rs.id, &name_fqdn, record_type, ttl, values)
                    .await
            }
            None => {
                self.post_recordset(&zone_id, &name_fqdn, record_type, ttl, values)
                    .await
            }
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
        reject_tlsa(record_type)?;
        if records.is_empty() {
            return Ok(());
        }
        let name_fqdn = ensure_fqdn(&name.into_name());
        let zone_id = self.resolve_zone_id(origin).await?;
        let new_values = render_records(&records)?;

        match self
            .find_recordset(&zone_id, &name_fqdn, record_type.as_str())
            .await?
        {
            Some(rs) => {
                let mut merged = rs.records.clone();
                for v in new_values {
                    if !merged.contains(&v) {
                        merged.push(v);
                    }
                }
                self.put_recordset(&zone_id, &rs.id, &name_fqdn, record_type, rs.ttl, merged)
                    .await
            }
            None => {
                self.post_recordset(&zone_id, &name_fqdn, record_type, ttl, new_values)
                    .await
            }
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
        reject_tlsa(record_type)?;
        if records.is_empty() {
            return Ok(());
        }
        let name_fqdn = ensure_fqdn(&name.into_name());
        let zone_id = self.resolve_zone_id(origin).await?;
        let to_remove = render_records(&records)?;

        let Some(rs) = self
            .find_recordset(&zone_id, &name_fqdn, record_type.as_str())
            .await?
        else {
            return Ok(());
        };

        let remaining: Vec<String> = rs
            .records
            .iter()
            .filter(|v| !to_remove.contains(v))
            .cloned()
            .collect();

        if remaining.len() == rs.records.len() {
            return Ok(());
        }

        if remaining.is_empty() {
            let path = format!("/v2/zones/{}/recordsets/{}", zone_id, rs.id);
            let _ = self
                .send_signed_raw(Method::DELETE, &path, "", None)
                .await?;
            Ok(())
        } else {
            self.put_recordset(&zone_id, &rs.id, &name_fqdn, record_type, rs.ttl, remaining)
                .await
        }
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        reject_tlsa(record_type)?;
        let name_fqdn = ensure_fqdn(&name.into_name());
        let zone_id = match self.resolve_zone_id(origin).await {
            Ok(id) => id,
            Err(Error::NotFound) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };

        let rs = match self
            .find_recordset(&zone_id, &name_fqdn, record_type.as_str())
            .await
        {
            Ok(Some(rs)) => rs,
            Ok(None) => return Ok(Vec::new()),
            Err(Error::NotFound) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };

        let mut out = Vec::with_capacity(rs.records.len());
        for value in rs.records {
            out.push(parse_value(record_type, &value)?);
        }
        Ok(out)
    }

    async fn post_recordset(
        &self,
        zone_id: &str,
        name_fqdn: &str,
        record_type: DnsRecordType,
        ttl: u32,
        values: Vec<String>,
    ) -> crate::Result<()> {
        let body = serde_json::to_string(&CreateRecordSetBody {
            name: name_fqdn,
            rr_type: record_type.as_str(),
            ttl,
            records: values,
            description: None,
        })
        .map_err(|err| Error::Serialize(err.to_string()))?;

        let path = format!("/v2/zones/{}/recordsets", zone_id);
        let _: CreateRecordSetResponse = self
            .send_signed(Method::POST, &path, "", Some(body))
            .await?;
        Ok(())
    }

    async fn put_recordset(
        &self,
        zone_id: &str,
        recordset_id: &str,
        name_fqdn: &str,
        record_type: DnsRecordType,
        ttl: u32,
        values: Vec<String>,
    ) -> crate::Result<()> {
        let body = serde_json::to_string(&UpdateRecordSetBody {
            name: name_fqdn,
            rr_type: record_type.as_str(),
            ttl,
            records: values,
            description: None,
        })
        .map_err(|err| Error::Serialize(err.to_string()))?;

        let path = format!("/v2/zones/{}/recordsets/{}", zone_id, recordset_id);
        let _ = self
            .send_signed_raw(Method::PUT, &path, "", Some(body))
            .await?;
        Ok(())
    }

    async fn resolve_zone_id(&self, origin: impl IntoFqdn<'_>) -> crate::Result<String> {
        let zone_name = ensure_fqdn(&origin.into_name());
        let mut marker: Option<String> = None;
        loop {
            let mut query = format!("limit={}&name={}", PAGE_LIMIT, zone_name);
            if let Some(m) = &marker {
                query.push_str("&marker=");
                query.push_str(m);
            }
            let response: ListZonesResponse = self
                .send_signed(Method::GET, "/v2/zones", &query, None)
                .await?;

            for zone in &response.zones {
                if zone.name.trim_end_matches('.') == zone_name.trim_end_matches('.') {
                    return Ok(zone.id.clone());
                }
            }

            let next = response
                .links
                .as_ref()
                .and_then(|l| l.next.as_deref())
                .and_then(extract_marker);
            match next {
                Some(m) if response.zones.len() as u32 == PAGE_LIMIT => {
                    marker = Some(m);
                }
                _ => {
                    return Err(Error::Api(format!(
                        "huaweicloud: zone {} not found",
                        zone_name
                    )));
                }
            }
        }
    }

    async fn find_recordset(
        &self,
        zone_id: &str,
        name_fqdn: &str,
        rr_type: &str,
    ) -> crate::Result<Option<HuaweiRecordSet>> {
        let path = format!("/v2/zones/{}/recordsets", zone_id);
        let mut marker: Option<String> = None;
        loop {
            let mut query = format!("limit={}&name={}&type={}", PAGE_LIMIT, name_fqdn, rr_type);
            if let Some(m) = &marker {
                query.push_str("&marker=");
                query.push_str(m);
            }
            let response: ListRecordSetsResponse =
                self.send_signed(Method::GET, &path, &query, None).await?;

            let page_len = response.recordsets.len();
            let next = response
                .links
                .as_ref()
                .and_then(|l| l.next.as_deref())
                .and_then(extract_marker);

            for rs in response.recordsets {
                if rs.name.trim_end_matches('.') == name_fqdn.trim_end_matches('.')
                    && rs.rr_type == rr_type
                {
                    return Ok(Some(rs));
                }
            }

            match next {
                Some(m) if page_len as u32 == PAGE_LIMIT => {
                    marker = Some(m);
                }
                _ => return Ok(None),
            }
        }
    }

    async fn send_signed<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &str,
        body: Option<String>,
    ) -> crate::Result<T> {
        let text = self.send_signed_raw(method, path, query, body).await?;
        if text.is_empty() {
            serde_json::from_str("{}")
                .map_err(|err| Error::Serialize(format!("Failed to deserialize empty: {err}")))
        } else {
            serde_json::from_str(&text)
                .map_err(|err| Error::Serialize(format!("Failed to deserialize: {err}")))
        }
    }

    async fn send_signed_raw(
        &self,
        method: Method,
        path: &str,
        query: &str,
        body: Option<String>,
    ) -> crate::Result<String> {
        let canonical_uri = canonicalize_path(path);
        let url = if query.is_empty() {
            format!("{}{}", self.endpoint, canonical_uri)
        } else {
            format!("{}{}?{}", self.endpoint, canonical_uri, query)
        };

        let host = host_from_endpoint(&self.endpoint);
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        let body_str = body.as_deref().unwrap_or("");
        let payload_hash = hex::encode(sha256_digest(body_str.as_bytes()));

        let canonical_query = canonical_query_string(query);

        let canonical_headers = format!(
            "content-type:application/json\nhost:{}\nx-sdk-date:{}\n",
            host, amz_date
        );
        let signed_headers = "content-type;host;x-sdk-date";

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash
        );

        let string_to_sign = format!(
            "{}\n{}\n{}",
            HUAWEI_ALGORITHM,
            amz_date,
            hex::encode(sha256_digest(canonical_request.as_bytes()))
        );

        let signature = hex::encode(hmac_sha256(
            self.secret_key.as_bytes(),
            string_to_sign.as_bytes(),
        ));

        let authorization = format!(
            "{} Access={}, SignedHeaders={}, Signature={}",
            HUAWEI_ALGORITHM, self.access_key, signed_headers, signature
        );

        let mut http: HttpRequest = self
            .client
            .request(method, url)
            .with_header("Host", host)
            .with_header("X-Sdk-Date", &amz_date)
            .with_header("Authorization", &authorization);

        if let Some(b) = body {
            http = http.with_raw_body(b);
        }

        http.send_raw().await
    }
}

fn host_from_endpoint(endpoint: &str) -> String {
    endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(endpoint)
        .to_string()
}

fn canonicalize_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{}/", path)
    }
}

fn canonical_query_string(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut parts: Vec<(String, String)> = query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next().unwrap_or("").to_string();
            let v = it.next().unwrap_or("").to_string();
            (uri_encode(&k, true), uri_encode(&v, true))
        })
        .collect();
    parts.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    parts
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let safe = b.is_ascii_alphanumeric()
            || b == b'-'
            || b == b'_'
            || b == b'.'
            || b == b'~'
            || (!encode_slash && b == b'/');
        if safe {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn ensure_fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    }
}

fn extract_marker(url: &str) -> Option<String> {
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or(url);
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("marker=") {
            return Some(value.to_string());
        }
    }
    None
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

fn reject_tlsa(record_type: DnsRecordType) -> crate::Result<()> {
    if record_type == DnsRecordType::TLSA {
        Err(Error::Unsupported(
            "TLSA records are not supported by huaweicloud".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn render_records(records: &[DnsRecord]) -> crate::Result<Vec<String>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        out.push(render_record(record)?);
    }
    Ok(out)
}

fn render_record(record: &DnsRecord) -> crate::Result<String> {
    match record {
        DnsRecord::A(addr) => Ok(addr.to_string()),
        DnsRecord::AAAA(addr) => Ok(addr.to_string()),
        DnsRecord::CNAME(name) => Ok(ensure_fqdn(name)),
        DnsRecord::NS(name) => Ok(ensure_fqdn(name)),
        DnsRecord::MX(mx) => Ok(format!("{} {}", mx.priority, ensure_fqdn(&mx.exchange))),
        DnsRecord::TXT(text) => {
            let mut out = String::with_capacity(text.len() + 4);
            txt_chunks_to_text(&mut out, text, " ");
            Ok(out)
        }
        DnsRecord::SRV(srv) => Ok(format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            ensure_fqdn(&srv.target)
        )),
        DnsRecord::CAA(caa) => Ok(caa.clone().to_string()),
        DnsRecord::TLSA(_) => Err(Error::Unsupported(
            "TLSA records are not supported by huaweicloud".to_string(),
        )),
    }
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
        DnsRecordType::CAA => parse_caa(value)?,
        DnsRecordType::TLSA => {
            return Err(Error::Unsupported(
                "TLSA records are not supported by huaweicloud".to_string(),
            ));
        }
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
    let mut saw_quote = false;
    while let Some(&b) = bytes.peek() {
        if b != b'"' {
            bytes.next();
            continue;
        }
        saw_quote = true;
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
    if !saw_quote {
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

fn strip_trailing_dot(value: &str) -> String {
    value.strip_suffix('.').unwrap_or(value).to_string()
}
