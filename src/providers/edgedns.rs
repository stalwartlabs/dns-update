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

use crate::crypto::{hmac_sha256, sha256_digest};
use crate::http::{HttpClient, HttpClientBuilder};
use crate::utils::split_caa_value;
use crate::utils::strip_trailing_dot;
use crate::utils::txt_chunks_to_text;
use crate::{CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, Result, SRVRecord};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_API_BASE: &str = "/config-dns/v2";
const DEFAULT_MAX_BODY: usize = 131072;

#[derive(Debug, Clone)]
pub struct EdgeDnsConfig {
    pub host: String,
    pub client_token: String,
    pub client_secret: String,
    pub access_token: String,
    pub account_switch_key: Option<String>,
    pub request_timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct EdgeDnsProvider {
    client: HttpClient,
    host: String,
    scheme: String,
    base_path: String,
    client_token: String,
    client_secret: String,
    access_token: String,
    account_switch_key: Option<String>,
    max_body: usize,
}

#[derive(Serialize, Debug)]
struct RecordBody<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    ttl: u32,
    rdata: Vec<String>,
}

impl EdgeDnsProvider {
    pub(crate) fn new(config: EdgeDnsConfig) -> Result<Self> {
        if config.host.is_empty() {
            return Err(Error::Client("edgedns: host is required".to_string()));
        }
        if config.client_token.is_empty()
            || config.client_secret.is_empty()
            || config.access_token.is_empty()
        {
            return Err(Error::Client(
                "edgedns: client_token, client_secret and access_token are required".to_string(),
            ));
        }
        let client = HttpClientBuilder::default()
            .with_timeout(config.request_timeout)
            .build();
        let (host, scheme) = parse_host(&config.host);
        Ok(Self {
            client,
            host,
            scheme,
            base_path: DEFAULT_API_BASE.to_string(),
            client_token: config.client_token,
            client_secret: config.client_secret,
            access_token: config.access_token,
            account_switch_key: config.account_switch_key,
            max_body: DEFAULT_MAX_BODY,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        let endpoint = endpoint.as_ref().trim_end_matches('/').to_string();
        let (host, scheme) = parse_host(&endpoint);
        self.host = host;
        self.scheme = scheme;
        self
    }

    fn base_url(&self) -> String {
        format!("{}://{}{}", self.scheme, self.host, self.base_path)
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        check_record_types(record_type, &records)?;
        let name = name.into_name().to_ascii_lowercase();
        let zone = origin.into_name().to_ascii_lowercase();
        if zone.is_empty() {
            return Err(Error::Api("edgedns: origin zone is required".to_string()));
        }
        let type_str = edgedns_record_type(record_type)?;
        let path = self.record_path(&zone, &name, type_str);
        let url = format!("{}{}", self.base_url(), path);

        if records.is_empty() {
            match self.send("DELETE", &url, None).await {
                Ok(_) => return Ok(()),
                Err(Error::NotFound) => return Ok(()),
                Err(e) => return Err(e),
            }
        }

        let rdata = build_rdata(record_type, &records)?;
        let body = RecordBody {
            name: &name,
            record_type: type_str,
            ttl,
            rdata,
        };
        let payload =
            serde_json::to_string(&body).map_err(|e| Error::Serialize(format!("edgedns: {e}")))?;
        match self.send("PUT", &url, Some(&payload)).await {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => {
                self.send("POST", &url, Some(&payload)).await?;
                Ok(())
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
    ) -> Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name().to_ascii_lowercase();
        let zone = origin.into_name().to_ascii_lowercase();
        if zone.is_empty() {
            return Err(Error::Api("edgedns: origin zone is required".to_string()));
        }
        let type_str = edgedns_record_type(record_type)?;
        let path = self.record_path(&zone, &name, type_str);
        let url = format!("{}{}", self.base_url(), path);

        let current = self.fetch_rdata(&url).await?;
        let desired = build_rdata(record_type, &records)?;
        let mut merged = current;
        for entry in desired {
            if !merged.iter().any(|existing| existing == &entry) {
                merged.push(entry);
            }
        }

        let body = RecordBody {
            name: &name,
            record_type: type_str,
            ttl,
            rdata: merged,
        };
        let payload =
            serde_json::to_string(&body).map_err(|e| Error::Serialize(format!("edgedns: {e}")))?;
        match self.send("PUT", &url, Some(&payload)).await {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => {
                self.send("POST", &url, Some(&payload)).await?;
                Ok(())
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
    ) -> Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name().to_ascii_lowercase();
        let zone = origin.into_name().to_ascii_lowercase();
        if zone.is_empty() {
            return Err(Error::Api("edgedns: origin zone is required".to_string()));
        }
        let type_str = edgedns_record_type(record_type)?;
        let path = self.record_path(&zone, &name, type_str);
        let url = format!("{}{}", self.base_url(), path);

        let current = self.fetch_rrset(&url).await?;
        let Some(existing) = current else {
            return Ok(());
        };
        let to_remove = build_rdata(record_type, &records)?;
        let remaining: Vec<String> = existing
            .rdata
            .into_iter()
            .filter(|entry| !to_remove.iter().any(|drop| drop == entry))
            .collect();

        if remaining.is_empty() {
            match self.send("DELETE", &url, None).await {
                Ok(_) => return Ok(()),
                Err(Error::NotFound) => return Ok(()),
                Err(e) => return Err(e),
            }
        }

        let body = RecordBody {
            name: &name,
            record_type: type_str,
            ttl: existing.ttl,
            rdata: remaining,
        };
        let payload =
            serde_json::to_string(&body).map_err(|e| Error::Serialize(format!("edgedns: {e}")))?;
        self.send("PUT", &url, Some(&payload)).await?;
        Ok(())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> Result<Vec<DnsRecord>> {
        let name = name.into_name().to_ascii_lowercase();
        let zone = origin.into_name().to_ascii_lowercase();
        if zone.is_empty() {
            return Err(Error::Api("edgedns: origin zone is required".to_string()));
        }
        let type_str = edgedns_record_type(record_type)?;
        let path = self.record_path(&zone, &name, type_str);
        let url = format!("{}{}", self.base_url(), path);
        let Some(current) = self.fetch_rrset(&url).await? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(current.rdata.len());
        for entry in current.rdata {
            out.push(rdata_to_record(record_type, &entry)?);
        }
        Ok(out)
    }

    async fn fetch_rrset(&self, url: &str) -> Result<Option<RecordResponse>> {
        match self.send("GET", url, None).await {
            Ok(text) => {
                let parsed: RecordResponse = serde_json::from_str(&text)
                    .map_err(|e| Error::Parse(format!("edgedns rrset parse: {e}")))?;
                Ok(Some(parsed))
            }
            Err(Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn fetch_rdata(&self, url: &str) -> Result<Vec<String>> {
        Ok(self
            .fetch_rrset(url)
            .await?
            .map(|r| r.rdata)
            .unwrap_or_default())
    }

    fn record_path(&self, zone: &str, name: &str, record_type: &str) -> String {
        format!(
            "/zones/{}/names/{}/types/{}",
            url_encode(zone),
            url_encode(name),
            record_type
        )
    }

    async fn send(&self, method: &str, url: &str, body: Option<&str>) -> Result<String> {
        let parsed = url
            .parse::<reqwest::Url>()
            .map_err(|e| Error::Client(format!("edgedns url parse: {e}")))?;
        let path_query = match parsed.query() {
            Some(q) => format!("{}?{}", parsed.path(), q),
            None => parsed.path().to_string(),
        };
        let host = match parsed.port() {
            Some(p) => format!("{}:{}", parsed.host_str().unwrap_or(""), p),
            None => parsed.host_str().unwrap_or("").to_string(),
        };
        let scheme = parsed.scheme().to_string();
        let timestamp = Utc::now().format("%Y%m%dT%H:%M:%S+0000").to_string();
        let nonce = generate_nonce();

        let body_for_hash = if matches!(method, "POST" | "PUT") {
            body.unwrap_or("").as_bytes()
        } else {
            &[][..]
        };
        let content_hash = if body_for_hash.is_empty() {
            String::new()
        } else {
            let truncated = if body_for_hash.len() > self.max_body {
                &body_for_hash[..self.max_body]
            } else {
                body_for_hash
            };
            BASE64_STANDARD.encode(sha256_digest(truncated))
        };

        let auth_without_signature = format!(
            "EG1-HMAC-SHA256 client_token={};access_token={};timestamp={};nonce={};",
            self.client_token, self.access_token, timestamp, nonce
        );

        let canonical_headers = String::new();
        let data_to_sign = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            method.to_ascii_uppercase(),
            scheme,
            host,
            path_query,
            canonical_headers,
            content_hash,
            auth_without_signature
        );

        let signing_key = BASE64_STANDARD.encode(hmac_sha256(
            self.client_secret.as_bytes(),
            timestamp.as_bytes(),
        ));
        let signature =
            BASE64_STANDARD.encode(hmac_sha256(signing_key.as_bytes(), data_to_sign.as_bytes()));
        let authorization = format!("{}signature={}", auth_without_signature, signature);

        let mut request = match method {
            "GET" => self.client.get(url),
            "POST" => self.client.post(url),
            "PUT" => self.client.put(url),
            "DELETE" => self.client.delete(url),
            other => {
                return Err(Error::Unsupported(format!(
                    "edgedns unsupported method: {other}"
                )));
            }
        };
        request = request
            .with_header("Authorization", authorization)
            .with_header("Accept", "application/json");
        if let Some(asw) = &self.account_switch_key {
            request = request.with_header("X-AccountSwitchKey", asw);
        }
        if let Some(body) = body {
            request = request
                .with_header("Content-Type", "application/json")
                .with_raw_body(body.to_string());
        }

        request.send_raw().await
    }
}

fn parse_host(input: &str) -> (String, String) {
    let trimmed = input.trim_end_matches('/');
    if let Some(rest) = trimmed.strip_prefix("https://") {
        return (rest.to_string(), "https".to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("http://") {
        return (rest.to_string(), "http".to_string());
    }
    (trimmed.to_string(), "https".to_string())
}

fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let c = *byte as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

fn generate_nonce() -> String {
    let now = Utc::now();
    let nanos = now.timestamp_nanos_opt().unwrap_or(now.timestamp());
    let mut buf = [0u8; 16];
    let bytes = (nanos as u128).to_le_bytes();
    buf.copy_from_slice(&bytes);
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_le_bytes(buf[0..4].try_into().unwrap()),
        u16::from_le_bytes(buf[4..6].try_into().unwrap()),
        u16::from_le_bytes(buf[6..8].try_into().unwrap()),
        u16::from_le_bytes(buf[8..10].try_into().unwrap()),
        {
            let mut full = [0u8; 8];
            full[2..8].copy_from_slice(&buf[10..16]);
            u64::from_be_bytes(full)
        }
    )
}

fn edgedns_record_type(record_type: DnsRecordType) -> Result<&'static str> {
    match record_type {
        DnsRecordType::A => Ok("A"),
        DnsRecordType::AAAA => Ok("AAAA"),
        DnsRecordType::CNAME => Ok("CNAME"),
        DnsRecordType::NS => Ok("NS"),
        DnsRecordType::MX => Ok("MX"),
        DnsRecordType::TXT => Ok("TXT"),
        DnsRecordType::SRV => Ok("SRV"),
        DnsRecordType::CAA => Ok("CAA"),
        DnsRecordType::TLSA => Err(Error::Unsupported(
            "TLSA records are not supported by EdgeDNS".to_string(),
        )),
    }
}

struct EdgeDnsRecord {
    record_type: String,
    rdata: Vec<String>,
}

impl TryFrom<&DnsRecord> for EdgeDnsRecord {
    type Error = Error;

    fn try_from(record: &DnsRecord) -> Result<Self> {
        Ok(match record {
            DnsRecord::A(addr) => Self {
                record_type: "A".to_string(),
                rdata: vec![addr.to_string()],
            },
            DnsRecord::AAAA(addr) => Self {
                record_type: "AAAA".to_string(),
                rdata: vec![addr.to_string()],
            },
            DnsRecord::CNAME(value) => Self {
                record_type: "CNAME".to_string(),
                rdata: vec![ensure_dot(value)],
            },
            DnsRecord::NS(value) => Self {
                record_type: "NS".to_string(),
                rdata: vec![ensure_dot(value)],
            },
            DnsRecord::MX(MXRecord { priority, exchange }) => Self {
                record_type: "MX".to_string(),
                rdata: vec![format!("{} {}", priority, ensure_dot(exchange))],
            },
            DnsRecord::TXT(value) => Self {
                record_type: "TXT".to_string(),
                rdata: vec![{
                    let mut out = String::new();
                    txt_chunks_to_text(&mut out, value, " ");
                    out
                }],
            },
            DnsRecord::SRV(SRVRecord {
                target,
                priority,
                weight,
                port,
            }) => Self {
                record_type: "SRV".to_string(),
                rdata: vec![format!(
                    "{} {} {} {}",
                    priority,
                    weight,
                    port,
                    ensure_dot(target)
                )],
            },
            DnsRecord::CAA(caa) => Self {
                record_type: "CAA".to_string(),
                rdata: vec![caa_to_rdata(caa)],
            },
            DnsRecord::TLSA(_) => {
                return Err(Error::Unsupported(
                    "TLSA records are not supported by EdgeDNS".to_string(),
                ));
            }
        })
    }
}

fn caa_to_rdata(caa: &CAARecord) -> String {
    match caa {
        CAARecord::Issue {
            issuer_critical,
            name,
            options,
        } => {
            let flags = if *issuer_critical { 128 } else { 0 };
            let mut value = name.clone().unwrap_or_default();
            for opt in options {
                value.push_str(&format!(";{}", opt));
            }
            format!("{} issue \"{}\"", flags, value)
        }
        CAARecord::IssueWild {
            issuer_critical,
            name,
            options,
        } => {
            let flags = if *issuer_critical { 128 } else { 0 };
            let mut value = name.clone().unwrap_or_default();
            for opt in options {
                value.push_str(&format!(";{}", opt));
            }
            format!("{} issuewild \"{}\"", flags, value)
        }
        CAARecord::Iodef {
            issuer_critical,
            url,
        } => {
            let flags = if *issuer_critical { 128 } else { 0 };
            format!("{} iodef \"{}\"", flags, url)
        }
    }
}

fn ensure_dot(value: &str) -> String {
    if value.ends_with('.') {
        value.to_string()
    } else {
        format!("{}.", value)
    }
}

#[derive(Deserialize)]
struct RecordResponse {
    #[serde(default)]
    ttl: u32,
    #[serde(default)]
    rdata: Vec<String>,
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> Result<()> {
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

fn build_rdata(record_type: DnsRecordType, records: &[DnsRecord]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        let representation = EdgeDnsRecord::try_from(record)?;
        let expected_type = edgedns_record_type(record_type)?;
        if representation.record_type != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type, representation.record_type,
            )));
        }
        for entry in representation.rdata {
            out.push(entry);
        }
    }
    Ok(out)
}

fn rdata_to_record(record_type: DnsRecordType, entry: &str) -> Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => entry
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("edgedns A rdata: {e}"))),
        DnsRecordType::AAAA => entry
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("edgedns AAAA rdata: {e}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(strip_trailing_dot(entry).to_string())),
        DnsRecordType::NS => Ok(DnsRecord::NS(strip_trailing_dot(entry).to_string())),
        DnsRecordType::MX => {
            let (priority_str, exchange) = entry
                .split_once(' ')
                .ok_or_else(|| Error::Parse(format!("edgedns MX rdata: {entry}")))?;
            let priority: u16 = priority_str
                .parse()
                .map_err(|e| Error::Parse(format!("edgedns MX priority: {e}")))?;
            Ok(DnsRecord::MX(MXRecord {
                priority,
                exchange: strip_trailing_dot(exchange.trim()).to_string(),
            }))
        }
        DnsRecordType::TXT => Ok(DnsRecord::TXT(parse_txt_rdata(entry))),
        DnsRecordType::SRV => {
            let mut parts = entry.split_whitespace();
            let priority: u16 = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("edgedns SRV rdata: {entry}")))?
                .parse()
                .map_err(|e| Error::Parse(format!("edgedns SRV priority: {e}")))?;
            let weight: u16 = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("edgedns SRV rdata: {entry}")))?
                .parse()
                .map_err(|e| Error::Parse(format!("edgedns SRV weight: {e}")))?;
            let port: u16 = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("edgedns SRV rdata: {entry}")))?
                .parse()
                .map_err(|e| Error::Parse(format!("edgedns SRV port: {e}")))?;
            let target = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("edgedns SRV rdata: {entry}")))?;
            Ok(DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target: strip_trailing_dot(target).to_string(),
            }))
        }
        DnsRecordType::CAA => parse_caa_rdata(entry),
        DnsRecordType::TLSA => Err(Error::Unsupported(
            "TLSA records are not supported by EdgeDNS".to_string(),
        )),
    }
}

fn parse_txt_rdata(entry: &str) -> String {
    let trimmed = entry.trim();
    let mut out = String::new();
    let chars = trimmed.chars().peekable();
    let mut in_quotes = false;
    let mut escape = false;
    for ch in chars {
        if escape {
            out.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escape = true,
            '"' => in_quotes = !in_quotes,
            _ if in_quotes => out.push(ch),
            _ => {}
        }
    }
    if out.is_empty() {
        trimmed.to_string()
    } else {
        out
    }
}

fn parse_caa_rdata(entry: &str) -> Result<DnsRecord> {
    let mut parts = entry.splitn(3, ' ');
    let flags_str = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("edgedns CAA rdata: {entry}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("edgedns CAA rdata: {entry}")))?;
    let value_quoted = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("edgedns CAA rdata: {entry}")))?;
    let flags: u8 = flags_str
        .parse()
        .map_err(|e| Error::Parse(format!("edgedns CAA flags: {e}")))?;
    let issuer_critical = flags & 128 != 0;
    let value = value_quoted
        .trim()
        .trim_start_matches('"')
        .trim_end_matches('"')
        .to_string();
    match tag {
        "issue" => {
            let (name, options) = split_caa_value(&value);
            Ok(DnsRecord::CAA(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }))
        }
        "issuewild" => {
            let (name, options) = split_caa_value(&value);
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
        other => Err(Error::Unsupported(format!(
            "edgedns CAA tag unsupported: {other}"
        ))),
    }
}
