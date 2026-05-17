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
use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, Result, SRVRecord,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::Utc;
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Serialize;
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
    client: Client,
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
        let mut builder = Client::builder();
        if let Some(timeout) = config.request_timeout {
            builder = builder.timeout(timeout);
        }
        let client = builder
            .build()
            .map_err(|e| Error::Client(format!("edgedns client: {e}")))?;
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

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        let name = name.into_name().to_ascii_lowercase();
        let zone = origin.into_name().to_ascii_lowercase();
        if zone.is_empty() {
            return Err(Error::Api("edgedns: origin zone is required".to_string()));
        }
        let representation = EdgeDnsRecord::try_from(&record)?;
        let body = RecordBody {
            name: &name,
            record_type: &representation.record_type,
            ttl,
            rdata: representation.rdata,
        };
        let path = self.record_path(&zone, &name, &representation.record_type);
        let url = format!("{}{}", self.base_url(), path);
        let payload = serde_json::to_string(&body)
            .map_err(|e| Error::Serialize(format!("edgedns: {e}")))?;
        self.send("POST", &url, Some(&payload)).await?;
        Ok(())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        let name = name.into_name().to_ascii_lowercase();
        let zone = origin.into_name().to_ascii_lowercase();
        if zone.is_empty() {
            return Err(Error::Api("edgedns: origin zone is required".to_string()));
        }
        let representation = EdgeDnsRecord::try_from(&record)?;
        let body = RecordBody {
            name: &name,
            record_type: &representation.record_type,
            ttl,
            rdata: representation.rdata,
        };
        let path = self.record_path(&zone, &name, &representation.record_type);
        let url = format!("{}{}", self.base_url(), path);
        let payload = serde_json::to_string(&body)
            .map_err(|e| Error::Serialize(format!("edgedns: {e}")))?;
        match self.send("PUT", &url, Some(&payload)).await {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => {
                self.send("POST", &url, Some(&payload)).await?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> Result<()> {
        let name = name.into_name().to_ascii_lowercase();
        let zone = origin.into_name().to_ascii_lowercase();
        if zone.is_empty() {
            return Err(Error::Api("edgedns: origin zone is required".to_string()));
        }
        let type_str = edgedns_record_type(record_type)?;
        let path = self.record_path(&zone, &name, type_str);
        let url = format!("{}{}", self.base_url(), path);
        match self.send("DELETE", &url, None).await {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
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

        let signing_key =
            BASE64_STANDARD.encode(hmac_sha256(self.client_secret.as_bytes(), timestamp.as_bytes()));
        let signature = BASE64_STANDARD
            .encode(hmac_sha256(signing_key.as_bytes(), data_to_sign.as_bytes()));
        let authorization = format!("{}signature={}", auth_without_signature, signature);

        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&authorization)
                .map_err(|e| Error::Client(format!("edgedns auth: {e}")))?,
        );
        headers.insert(
            "Accept",
            HeaderValue::from_static("application/json"),
        );
        if let Some(asw) = &self.account_switch_key {
            headers.insert(
                "X-AccountSwitchKey",
                HeaderValue::from_str(asw)
                    .map_err(|e| Error::Client(format!("edgedns switch key: {e}")))?,
            );
        }
        if body.is_some() {
            headers.insert(
                "Content-Type",
                HeaderValue::from_static("application/json"),
            );
        }

        let request_method = method
            .parse::<reqwest::Method>()
            .map_err(|e| Error::Client(format!("edgedns method: {e}")))?;
        let mut request = self.client.request(request_method, url).headers(headers);
        if let Some(body) = body {
            request = request.body(body.to_string());
        }
        let response = request
            .send()
            .await
            .map_err(|e| Error::Api(format!("edgedns request: {e}")))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| Error::Api(format!("edgedns body: {e}")))?;

        match status.as_u16() {
            200..=299 => Ok(text),
            400 => Err(Error::Api(format!("edgedns BadRequest: {text}"))),
            401 | 403 => Err(Error::Unauthorized),
            404 => Err(Error::NotFound),
            code => Err(Error::Api(format!("edgedns HTTP {code}: {text}"))),
        }
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
        DnsRecordType::TLSA => Err(Error::Api(
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
                rdata: vec![format!("\"{}\"", value.replace('"', "\\\""))],
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
                return Err(Error::Api(
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

