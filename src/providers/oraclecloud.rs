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

#![cfg(any(feature = "ring", feature = "aws-lc-rs"))]

use crate::crypto::sha256_digest;
use crate::jwt::{parse_rsa_pkcs8_pem, rsa_sha256_sign};
use crate::utils::txt_chunks_to_text;
use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, KeyValue as DnsKeyValue, MXRecord,
    Result, SRVRecord, TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::Utc;
use reqwest::Method;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use std::net::AddrParseError;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "ring")]
use ring::signature::RsaKeyPair;

#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
use aws_lc_rs::signature::RsaKeyPair;

const RETRIES: u32 = 3;
const PAGE_LIMIT: u32 = 1000;

#[derive(Debug, Clone)]
pub struct OracleCloudConfig {
    pub tenancy_ocid: String,
    pub user_ocid: String,
    pub fingerprint: String,
    pub private_key_pem: String,
    pub private_key_password: Option<String>,
    pub region: String,
    pub compartment_ocid: String,
    pub request_timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct OracleCloudProvider {
    config: OracleCloudConfig,
    key_pair: Arc<RsaKeyPair>,
    endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct OciRecord {
    domain: String,
    rtype: String,
    rdata: String,
    ttl: u32,
    #[serde(rename = "isProtected", skip_serializing_if = "Option::is_none")]
    is_protected: Option<bool>,
    #[serde(rename = "recordHash", skip_serializing_if = "Option::is_none")]
    record_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct UpdateRecordsRequest {
    items: Vec<OciRecord>,
}

#[derive(Debug, Serialize)]
struct PatchRecordsRequest {
    items: Vec<PatchOperation>,
}

#[derive(Debug, Serialize)]
struct PatchOperation {
    operation: &'static str,
    rdata: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RecordCollection {
    items: Vec<OciRecord>,
}

#[derive(Debug, Deserialize)]
struct Zone {
    name: String,
    id: String,
}

impl OracleCloudProvider {
    pub(crate) fn new(config: OracleCloudConfig) -> Result<Self> {
        if config.tenancy_ocid.is_empty() {
            return Err(Error::Client("tenancy_ocid is required".into()));
        }
        if config.user_ocid.is_empty() {
            return Err(Error::Client("user_ocid is required".into()));
        }
        if config.fingerprint.is_empty() {
            return Err(Error::Client("fingerprint is required".into()));
        }
        if config.region.is_empty() {
            return Err(Error::Client("region is required".into()));
        }
        if config.compartment_ocid.is_empty() {
            return Err(Error::Client("compartment_ocid is required".into()));
        }
        if config
            .private_key_password
            .as_ref()
            .is_some_and(|p| !p.is_empty())
        {
            return Err(Error::Api(
                "OCI private keys with a passphrase are not supported".into(),
            ));
        }

        let key_pair = parse_rsa_pkcs8_pem(&config.private_key_pem)
            .map_err(|e| Error::Client(format!("Failed to parse OCI private key: {}", e)))?;

        let endpoint = format!("https://dns.{}.oraclecloud.com", config.region);

        Ok(Self {
            config,
            key_pair: Arc::new(key_pair),
            endpoint,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into().trim_end_matches('/').to_string();
        self
    }

    fn key_id(&self) -> String {
        format!(
            "{}/{}/{}",
            self.config.tenancy_ocid, self.config.user_ocid, self.config.fingerprint
        )
    }

    fn sign_request(&self, method: &Method, url: &str, body: Option<&str>) -> Result<HeaderMap> {
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| Error::Client(format!("Failed to parse URL {}: {}", url, e)))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| Error::Client(format!("URL missing host: {}", url)))?
            .to_string();
        let host_header = if let Some(port) = parsed.port() {
            format!("{}:{}", host, port)
        } else {
            host.clone()
        };
        let mut path_and_query = parsed.path().to_string();
        if let Some(q) = parsed.query() {
            path_and_query.push('?');
            path_and_query.push_str(q);
        }

        let method_lower = method.as_str().to_lowercase();
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

        let mut signed_pairs: Vec<(String, String)> = Vec::new();
        signed_pairs.push((
            "(request-target)".to_string(),
            format!("{} {}", method_lower, path_and_query),
        ));
        signed_pairs.push(("host".to_string(), host_header.clone()));
        signed_pairs.push(("date".to_string(), date.clone()));

        let needs_body_headers = matches!(*method, Method::POST | Method::PUT | Method::PATCH);
        let body_bytes = body.unwrap_or("").as_bytes();
        let content_sha256 = B64.encode(sha256_digest(body_bytes));
        let content_length = body_bytes.len().to_string();
        if needs_body_headers {
            signed_pairs.push(("x-content-sha256".to_string(), content_sha256.clone()));
            signed_pairs.push(("content-type".to_string(), "application/json".to_string()));
            signed_pairs.push(("content-length".to_string(), content_length.clone()));
        }

        let signing_string = signed_pairs
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect::<Vec<_>>()
            .join("\n");
        let signature = rsa_sha256_sign(&self.key_pair, signing_string.as_bytes())
            .map_err(|e| Error::Client(format!("Failed to sign request: {}", e)))?;
        let signature_b64 = B64.encode(&signature);

        let headers_list = signed_pairs
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let authorization = format!(
            "Signature version=\"1\",keyId=\"{}\",algorithm=\"rsa-sha256\",headers=\"{}\",signature=\"{}\"",
            self.key_id(),
            headers_list,
            signature_b64,
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_str(&host_header)
                .map_err(|e| Error::Client(format!("Invalid host header: {}", e)))?,
        );
        headers.insert(
            "date",
            HeaderValue::from_str(&date)
                .map_err(|e| Error::Client(format!("Invalid date header: {}", e)))?,
        );
        headers.insert(
            "authorization",
            HeaderValue::from_str(&authorization)
                .map_err(|e| Error::Client(format!("Invalid authorization header: {}", e)))?,
        );
        if needs_body_headers {
            headers.insert(
                "x-content-sha256",
                HeaderValue::from_str(&content_sha256)
                    .map_err(|e| Error::Client(format!("Invalid x-content-sha256: {}", e)))?,
            );
            headers.insert("content-type", HeaderValue::from_static("application/json"));
            headers.insert(
                "content-length",
                HeaderValue::from_str(&content_length)
                    .map_err(|e| Error::Client(format!("Invalid content-length: {}", e)))?,
            );
        }

        Ok(headers)
    }

    async fn send_signed(
        &self,
        method: Method,
        url: &str,
        body: Option<String>,
    ) -> Result<(reqwest::StatusCode, String, HeaderMap)> {
        let client = reqwest::Client::builder()
            .timeout(
                self.config
                    .request_timeout
                    .unwrap_or(Duration::from_secs(30)),
            )
            .build()
            .map_err(|e| Error::Client(format!("Failed to build HTTP client: {}", e)))?;

        let mut attempts: u32 = 0;
        loop {
            let headers = self.sign_request(&method, url, body.as_deref())?;
            let mut request = client.request(method.clone(), url).headers(headers);
            if let Some(b) = body.as_ref() {
                request = request.body(b.clone());
            }
            let response = request
                .send()
                .await
                .map_err(|e| Error::Api(format!("Failed to send request to {}: {}", url, e)))?;
            let status = response.status();
            let response_headers = response.headers().clone();

            if status.as_u16() == 429 && attempts < RETRIES {
                let retry_after = response_headers
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(1);
                tokio::time::sleep(Duration::from_secs(retry_after)).await;
                attempts += 1;
                continue;
            }

            let text = response
                .text()
                .await
                .map_err(|e| Error::Api(format!("Failed to read response body: {}", e)))?;
            return Ok((status, text, response_headers));
        }
    }

    fn record_to_rdata(record: &DnsRecord) -> Result<(String, String)> {
        let (rtype, rdata) = match record {
            DnsRecord::A(ip) => ("A".to_string(), ip.to_string()),
            DnsRecord::AAAA(ip) => ("AAAA".to_string(), ip.to_string()),
            DnsRecord::CNAME(c) => ("CNAME".to_string(), format_target(c)),
            DnsRecord::NS(n) => ("NS".to_string(), format_target(n)),
            DnsRecord::MX(mx) => (
                "MX".to_string(),
                format!("{} {}", mx.priority, format_target(&mx.exchange)),
            ),
            DnsRecord::TXT(txt) => {
                let mut rdata = String::new();
                txt_chunks_to_text(&mut rdata, txt, " ");
                ("TXT".to_string(), rdata)
            }
            DnsRecord::SRV(srv) => (
                "SRV".to_string(),
                format!(
                    "{} {} {} {}",
                    srv.priority,
                    srv.weight,
                    srv.port,
                    format_target(&srv.target)
                ),
            ),
            DnsRecord::CAA(caa) => {
                let (flags, tag, value) = caa.clone().decompose();
                (
                    "CAA".to_string(),
                    format!("{} {} \"{}\"", flags, tag, value),
                )
            }
            DnsRecord::TLSA(tlsa) => ("TLSA".to_string(), tlsa.to_string()),
        };
        Ok((rtype, rdata))
    }

    async fn resolve_zone(&self, origin: &str) -> Result<String> {
        let trimmed = origin.trim_end_matches('.');
        let url = format!(
            "{}/20180115/zones?compartmentId={}&name={}",
            self.endpoint,
            urlencode(&self.config.compartment_ocid),
            urlencode(trimmed),
        );
        let (status, body, _) = self.send_signed(Method::GET, &url, None).await?;
        if !status.is_success() {
            return Err(map_error(status, &body));
        }
        let zones: Vec<Zone> = serde_json::from_str(&body)
            .map_err(|e| Error::Serialize(format!("Failed to parse zones list: {}", e)))?;
        zones
            .into_iter()
            .find(|z| z.name.trim_end_matches('.') == trimmed)
            .map(|z| z.id)
            .ok_or(Error::NotFound)
    }

    fn records_url(&self, zone_id: &str, domain: &str, rtype: &str) -> String {
        format!(
            "{}/20180115/zones/{}/records/{}/{}?compartmentId={}",
            self.endpoint,
            urlencode(zone_id),
            urlencode(domain),
            urlencode(rtype),
            urlencode(&self.config.compartment_ocid),
        )
    }

    fn records_url_paged(
        &self,
        zone_id: &str,
        domain: &str,
        rtype: &str,
        page: Option<&str>,
    ) -> String {
        let mut url = format!(
            "{}/20180115/zones/{}/records/{}/{}?compartmentId={}&limit={}",
            self.endpoint,
            urlencode(zone_id),
            urlencode(domain),
            urlencode(rtype),
            urlencode(&self.config.compartment_ocid),
            PAGE_LIMIT,
        );
        if let Some(page) = page {
            url.push_str("&page=");
            url.push_str(&urlencode(page));
        }
        url
    }

    async fn get_records(
        &self,
        zone_id: &str,
        domain: &str,
        rtype: &str,
    ) -> Result<Vec<OciRecord>> {
        let mut all: Vec<OciRecord> = Vec::new();
        let mut next_page: Option<String> = None;
        loop {
            let url = self.records_url_paged(zone_id, domain, rtype, next_page.as_deref());
            let (status, body, headers) = self.send_signed(Method::GET, &url, None).await?;
            if status.as_u16() == 404 {
                return Ok(Vec::new());
            }
            if !status.is_success() {
                return Err(map_error(status, &body));
            }
            let collection: RecordCollection = serde_json::from_str(&body)
                .map_err(|e| Error::Serialize(format!("Failed to parse records: {}", e)))?;
            all.extend(collection.items);
            next_page = headers
                .get("opc-next-page")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            if next_page.is_none() {
                return Ok(all);
            }
        }
    }

    async fn put_records(
        &self,
        zone_id: &str,
        domain: &str,
        rtype: &str,
        items: Vec<OciRecord>,
    ) -> Result<()> {
        let url = self.records_url(zone_id, domain, rtype);
        let request = UpdateRecordsRequest { items };
        let body = serde_json::to_string(&request)
            .map_err(|e| Error::Serialize(format!("Failed to serialize request: {}", e)))?;
        let (status, response_body, _) = self.send_signed(Method::PUT, &url, Some(body)).await?;
        if !status.is_success() {
            return Err(map_error(status, &response_body));
        }
        Ok(())
    }

    async fn patch_records(
        &self,
        zone_id: &str,
        domain: &str,
        rtype: &str,
        items: Vec<PatchOperation>,
    ) -> Result<()> {
        let url = self.records_url(zone_id, domain, rtype);
        let request = PatchRecordsRequest { items };
        let body = serde_json::to_string(&request)
            .map_err(|e| Error::Serialize(format!("Failed to serialize request: {}", e)))?;
        let (status, response_body, _) = self.send_signed(Method::PATCH, &url, Some(body)).await?;
        if !status.is_success() {
            return Err(map_error(status, &response_body));
        }
        Ok(())
    }

    async fn delete_rrset(&self, zone_id: &str, domain: &str, rtype: &str) -> Result<()> {
        let url = self.records_url(zone_id, domain, rtype);
        let (status, body, _) = self.send_signed(Method::DELETE, &url, None).await?;
        if status.as_u16() == 404 {
            return Ok(());
        }
        if !status.is_success() {
            return Err(map_error(status, &body));
        }
        Ok(())
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
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone_id = self.resolve_zone(&origin).await?;
        let rtype = record_type.as_str();

        if records.is_empty() {
            return self.delete_rrset(&zone_id, &name, rtype).await;
        }

        let mut items = Vec::with_capacity(records.len());
        for record in records {
            let (_, rdata) = Self::record_to_rdata(&record)?;
            items.push(OciRecord {
                domain: name.clone(),
                rtype: rtype.to_string(),
                rdata,
                ttl,
                is_protected: None,
                record_hash: None,
            });
        }
        self.put_records(&zone_id, &name, rtype, items).await
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
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone_id = self.resolve_zone(&origin).await?;
        let rtype = record_type.as_str();

        let existing = self.get_records(&zone_id, &name, rtype).await?;
        let mut items = Vec::with_capacity(records.len());
        for record in records {
            let (_, rdata) = Self::record_to_rdata(&record)?;
            if existing
                .iter()
                .any(|e| e.rtype.eq_ignore_ascii_case(rtype) && e.rdata == rdata)
            {
                continue;
            }
            items.push(PatchOperation {
                operation: "ADD",
                rdata,
                ttl: Some(ttl),
            });
        }
        if items.is_empty() {
            return Ok(());
        }
        self.patch_records(&zone_id, &name, rtype, items).await
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
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone_id = self.resolve_zone(&origin).await?;
        let rtype = record_type.as_str();

        let mut items = Vec::with_capacity(records.len());
        for record in records {
            let (_, rdata) = Self::record_to_rdata(&record)?;
            items.push(PatchOperation {
                operation: "REMOVE",
                rdata,
                ttl: None,
            });
        }
        match self.patch_records(&zone_id, &name, rtype, items).await {
            Ok(()) => Ok(()),
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> Result<Vec<DnsRecord>> {
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone_id = match self.resolve_zone(&origin).await {
            Ok(id) => id,
            Err(Error::NotFound) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let rtype = record_type.as_str();
        let items = self.get_records(&zone_id, &name, rtype).await?;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            if !item.rtype.eq_ignore_ascii_case(rtype) {
                continue;
            }
            out.push(parse_rdata(record_type, &item.rdata)?);
        }
        Ok(out)
    }
}

fn format_target(value: &str) -> String {
    format!("{}.", value.trim_end_matches('.'))
}

fn urlencode(value: &str) -> String {
    serde_urlencoded::to_string([("v", value)])
        .ok()
        .and_then(|s| s.strip_prefix("v=").map(str::to_string))
        .unwrap_or_else(|| value.to_string())
}

fn map_error(status: reqwest::StatusCode, body: &str) -> Error {
    match status.as_u16() {
        400 => Error::BadRequest,
        401 | 403 => Error::Unauthorized,
        404 => Error::NotFound,
        _ => Error::Api(format!("Oracle Cloud DNS error {}: {}", status, body)),
    }
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

fn parse_rdata(record_type: DnsRecordType, value: &str) -> Result<DnsRecord> {
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

fn parse_mx(value: &str) -> Result<DnsRecord> {
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

fn parse_srv(value: &str) -> Result<DnsRecord> {
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

fn parse_caa(value: &str) -> Result<DnsRecord> {
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

fn parse_caa_kv(value: &str) -> (Option<String>, Vec<DnsKeyValue>) {
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

fn parse_tlsa(value: &str) -> Result<DnsRecord> {
    let mut parts = value.split_whitespace();
    let cert_usage_n: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA cert usage in '{value}': {e}")))?;
    let selector_n: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA selector in '{value}': {e}")))?;
    let matching_n: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA matching in '{value}': {e}")))?;
    let hex: String = parts.collect::<Vec<_>>().join("");
    let cert_data = hex_decode(&hex)
        .map_err(|e| Error::Parse(format!("invalid TLSA hex in '{value}': {e}")))?;
    Ok(DnsRecord::TLSA(TLSARecord {
        cert_usage: tlsa_cert_usage_from(cert_usage_n)?,
        selector: tlsa_selector_from(selector_n)?,
        matching: tlsa_matching_from(matching_n)?,
        cert_data,
    }))
}

fn tlsa_cert_usage_from(n: u8) -> Result<TlsaCertUsage> {
    Ok(match n {
        0 => TlsaCertUsage::PkixTa,
        1 => TlsaCertUsage::PkixEe,
        2 => TlsaCertUsage::DaneTa,
        3 => TlsaCertUsage::DaneEe,
        255 => TlsaCertUsage::Private,
        other => return Err(Error::Parse(format!("unknown TLSA cert usage: {other}"))),
    })
}

fn tlsa_selector_from(n: u8) -> Result<TlsaSelector> {
    Ok(match n {
        0 => TlsaSelector::Full,
        1 => TlsaSelector::Spki,
        255 => TlsaSelector::Private,
        other => return Err(Error::Parse(format!("unknown TLSA selector: {other}"))),
    })
}

fn tlsa_matching_from(n: u8) -> Result<TlsaMatching> {
    Ok(match n {
        0 => TlsaMatching::Raw,
        1 => TlsaMatching::Sha256,
        2 => TlsaMatching::Sha512,
        255 => TlsaMatching::Private,
        other => return Err(Error::Parse(format!("unknown TLSA matching: {other}"))),
    })
}

fn hex_decode(s: &str) -> std::result::Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return Err("odd hex length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).map_err(|e| e.to_string())?;
        let byte = u8::from_str_radix(pair, 16).map_err(|e| e.to_string())?;
        out.push(byte);
    }
    Ok(out)
}

fn strip_trailing_dot(s: &str) -> String {
    s.strip_suffix('.').unwrap_or(s).to_string()
}
