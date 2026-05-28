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
use crate::utils::{strip_origin_from_name, txt_chunks_to_text};
use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, Result, SRVRecord};
use chrono::Utc;
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const LIGHTSAIL_SERVICE: &str = "lightsail";
const LIGHTSAIL_TARGET_PREFIX: &str = "Lightsail_20161128";
const LIGHTSAIL_CONTENT_TYPE: &str = "application/x-amz-json-1.1";
const DEFAULT_REGION: &str = "us-east-1";

#[derive(Debug, Clone)]
pub struct LightsailConfig {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub region: Option<String>,
    pub domain: Option<String>,
    pub request_timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct LightsailProvider {
    client: Client,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    region: String,
    configured_domain: Option<String>,
    endpoint: Option<String>,
}

#[derive(Serialize, Debug)]
struct LightsailDomainEntryPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a str>,
    name: &'a str,
    target: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
}

#[derive(Serialize, Debug)]
struct CreateDomainEntryRequest<'a> {
    #[serde(rename = "domainName")]
    domain_name: &'a str,
    #[serde(rename = "domainEntry")]
    domain_entry: LightsailDomainEntryPayload<'a>,
}

#[derive(Serialize, Debug)]
struct DeleteDomainEntryRequest<'a> {
    #[serde(rename = "domainName")]
    domain_name: &'a str,
    #[serde(rename = "domainEntry")]
    domain_entry: LightsailDomainEntryPayload<'a>,
}

#[derive(Serialize, Debug)]
struct GetDomainRequest<'a> {
    #[serde(rename = "domainName")]
    domain_name: &'a str,
}

#[derive(Serialize, Debug, Default)]
struct GetDomainsRequest<'a> {
    #[serde(rename = "pageToken", skip_serializing_if = "Option::is_none")]
    page_token: Option<&'a str>,
}

#[derive(Deserialize, Debug)]
struct GetDomainsResponse {
    #[serde(default)]
    domains: Vec<LightsailDomain>,
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize, Debug)]
struct GetDomainResponse {
    domain: LightsailDomain,
}

#[derive(Deserialize, Debug, Clone)]
struct LightsailDomain {
    #[allow(dead_code)]
    name: String,
    #[serde(default, rename = "domainEntries")]
    domain_entries: Vec<LightsailDomainEntry>,
}

#[derive(Deserialize, Debug, Clone)]
struct LightsailDomainEntry {
    #[serde(default)]
    id: Option<String>,
    name: String,
    target: String,
    #[serde(rename = "type")]
    record_type: String,
}

impl LightsailProvider {
    pub(crate) fn new(config: LightsailConfig) -> Result<Self> {
        let region = config.region.unwrap_or_else(|| DEFAULT_REGION.to_string());
        let mut builder = Client::builder();
        if let Some(timeout) = config.request_timeout {
            builder = builder.timeout(timeout);
        }
        let client = builder
            .build()
            .map_err(|e| Error::Client(format!("lightsail client: {e}")))?;
        Ok(Self {
            client,
            access_key_id: config.access_key_id,
            secret_access_key: config.secret_access_key,
            session_token: config.session_token,
            region,
            configured_domain: config.domain,
            endpoint: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        self.endpoint = Some(endpoint.as_ref().trim_end_matches('/').to_string());
        self
    }

    fn default_host(&self) -> String {
        format!("lightsail.{}.amazonaws.com", self.region)
    }

    fn base_url(&self) -> String {
        match &self.endpoint {
            Some(ep) => ep.clone(),
            None => format!("https://{}", self.default_host()),
        }
    }

    fn signing_host(&self) -> String {
        let url = format!("{}/", self.base_url());
        if let Ok(parsed) = url.parse::<reqwest::Url>()
            && let Some(host) = parsed.host_str()
        {
            return match parsed.port() {
                Some(p) => format!("{}:{}", host, p),
                None => host.to_string(),
            };
        }
        self.default_host()
    }

    async fn invoke<T>(&self, operation: &str, body: &impl Serialize) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let response_text = self.invoke_raw(operation, body).await?;
        if response_text.is_empty() {
            serde_json::from_str("{}")
                .map_err(|e| Error::Serialize(format!("lightsail decode empty: {e}")))
        } else {
            serde_json::from_str(&response_text)
                .map_err(|e| Error::Serialize(format!("lightsail decode: {e}")))
        }
    }

    async fn invoke_raw(&self, operation: &str, body: &impl Serialize) -> Result<String> {
        let payload = serde_json::to_string(body)
            .map_err(|e| Error::Serialize(format!("lightsail serialize: {e}")))?;
        let target = format!("{}.{}", LIGHTSAIL_TARGET_PREFIX, operation);
        let url = format!("{}/", self.base_url());
        let headers = self.sign("POST", "/", &target, &payload)?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .body(payload)
            .send()
            .await
            .map_err(|e| Error::Api(format!("lightsail request: {e}")))?;

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| Error::Api(format!("lightsail body: {e}")))?;

        match status.as_u16() {
            200..=299 => Ok(text),
            401 | 403 => Err(Error::Unauthorized),
            404 => Err(Error::NotFound),
            400 => Err(Error::Api(format!("lightsail BadRequest: {text}"))),
            code => Err(Error::Api(format!("lightsail HTTP {code}: {text}"))),
        }
    }

    fn sign(&self, method: &str, path: &str, target: &str, payload: &str) -> Result<HeaderMap> {
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let payload_hash = hex::encode(sha256_digest(payload.as_bytes()));
        let host = self.signing_host();

        let mut canonical_headers = format!(
            "content-type:{}\nhost:{}\nx-amz-date:{}\nx-amz-target:{}\n",
            LIGHTSAIL_CONTENT_TYPE, host, amz_date, target
        );
        let mut signed_headers = String::from("content-type;host;x-amz-date;x-amz-target");
        if let Some(token) = &self.session_token {
            canonical_headers.push_str(&format!("x-amz-security-token:{}\n", token));
            signed_headers.push_str(";x-amz-security-token");
        }

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method, path, "", canonical_headers, signed_headers, payload_hash
        );

        let algorithm = "AWS4-HMAC-SHA256";
        let credential_scope = format!(
            "{}/{}/{}/aws4_request",
            date_stamp, self.region, LIGHTSAIL_SERVICE
        );
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            algorithm,
            amz_date,
            credential_scope,
            hex::encode(sha256_digest(canonical_request.as_bytes()))
        );

        let k_date = hmac_sha256(
            format!("AWS4{}", self.secret_access_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, LIGHTSAIL_SERVICE.as_bytes());
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

        let authorization = format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            algorithm, self.access_key_id, credential_scope, signed_headers, signature
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static(LIGHTSAIL_CONTENT_TYPE),
        );
        headers.insert(
            "x-amz-date",
            HeaderValue::from_str(&amz_date)
                .map_err(|e| Error::Client(format!("amz-date: {e}")))?,
        );
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(target).map_err(|e| Error::Client(format!("amz-target: {e}")))?,
        );
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&authorization)
                .map_err(|e| Error::Client(format!("auth header: {e}")))?,
        );
        if let Some(token) = &self.session_token {
            headers.insert(
                "x-amz-security-token",
                HeaderValue::from_str(token)
                    .map_err(|e| Error::Client(format!("security-token: {e}")))?,
            );
        }
        let _ = path;
        let _ = method;
        Ok(headers)
    }

    async fn resolve_domain(&self, fqdn: &str) -> Result<String> {
        if let Some(domain) = &self.configured_domain {
            return Ok(domain.trim_end_matches('.').to_ascii_lowercase());
        }
        let target = fqdn.trim_end_matches('.').to_ascii_lowercase();
        let mut best: Option<String> = None;
        let mut page_token: Option<String> = None;
        loop {
            let request = GetDomainsRequest {
                page_token: page_token.as_deref(),
            };
            let response: GetDomainsResponse = self.invoke("GetDomains", &request).await?;
            for domain in response.domains {
                let candidate = domain.name.trim_end_matches('.').to_ascii_lowercase();
                if (target == candidate || target.ends_with(&format!(".{}", candidate)))
                    && best
                        .as_ref()
                        .map(|current| current.len() < candidate.len())
                        .unwrap_or(true)
                {
                    best = Some(candidate);
                }
            }
            match response.next_page_token {
                Some(token) if !token.is_empty() => page_token = Some(token),
                _ => break,
            }
        }
        best.ok_or_else(|| Error::Api(format!("No Lightsail domain found for {fqdn}")))
    }

    async fn fetch_domain_entries(&self, domain_name: &str) -> Result<Vec<LightsailDomainEntry>> {
        let response: GetDomainResponse = self
            .invoke("GetDomain", &GetDomainRequest { domain_name })
            .await?;
        Ok(response.domain.domain_entries)
    }

    async fn find_entries(
        &self,
        domain_name: &str,
        record_name: &str,
        record_type: &str,
    ) -> Result<Vec<LightsailDomainEntry>> {
        let entries = self.fetch_domain_entries(domain_name).await?;
        let needle = record_name.trim_end_matches('.').to_ascii_lowercase();
        let mut matches = Vec::new();
        for entry in entries {
            let entry_name = entry.name.trim_end_matches('.').to_ascii_lowercase();
            if entry_name == needle && entry.record_type.eq_ignore_ascii_case(record_type) {
                matches.push(entry);
            }
        }
        Ok(matches)
    }

    async fn create_entry(
        &self,
        domain_name: &str,
        entry_name: &str,
        record_type: &str,
        target: &str,
    ) -> Result<()> {
        let payload = LightsailDomainEntryPayload {
            id: None,
            name: entry_name,
            target,
            record_type,
        };
        let request = CreateDomainEntryRequest {
            domain_name,
            domain_entry: payload,
        };
        let _ = self.invoke_raw("CreateDomainEntry", &request).await?;
        Ok(())
    }

    async fn delete_entry(&self, domain_name: &str, entry: &LightsailDomainEntry) -> Result<()> {
        let payload = LightsailDomainEntryPayload {
            id: entry.id.as_deref(),
            name: &entry.name,
            target: &entry.target,
            record_type: &entry.record_type,
        };
        let request = DeleteDomainEntryRequest {
            domain_name,
            domain_entry: payload,
        };
        let _ = self.invoke_raw("DeleteDomainEntry", &request).await?;
        Ok(())
    }

    async fn resolve_zone(&self, name: &str, origin: &str) -> Result<String> {
        if self.configured_domain.is_some() || origin.is_empty() {
            self.resolve_domain(name).await
        } else {
            Ok(origin.to_ascii_lowercase())
        }
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        check_record_types(record_type, &records)?;
        let type_str = lightsail_record_type(record_type)?;

        let name = name.into_name().to_ascii_lowercase();
        let origin = origin.into_name().to_ascii_lowercase();
        let domain_name = self.resolve_zone(&name, &origin).await?;
        let entry_name = full_record_name(&name, &domain_name);

        let mut desired: Vec<String> = Vec::new();
        for record in &records {
            let reps = LightsailRecord::from_dns_record(record)?;
            for rep in reps {
                desired.push(rep.target);
            }
        }

        let existing = self
            .find_entries(&domain_name, &entry_name, type_str)
            .await?;

        let mut remaining: Vec<LightsailDomainEntry> = existing;
        let mut to_add: Vec<String> = Vec::new();
        for target in desired {
            if let Some(idx) = remaining.iter().position(|e| e.target == target) {
                remaining.swap_remove(idx);
            } else if !to_add.contains(&target) {
                to_add.push(target);
            }
        }

        for entry in remaining {
            self.delete_entry(&domain_name, &entry).await?;
        }
        for target in to_add {
            self.create_entry(&domain_name, &entry_name, type_str, &target)
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let type_str = lightsail_record_type(record_type)?;

        let name = name.into_name().to_ascii_lowercase();
        let origin = origin.into_name().to_ascii_lowercase();
        let domain_name = self.resolve_zone(&name, &origin).await?;
        let entry_name = full_record_name(&name, &domain_name);

        let mut desired: Vec<String> = Vec::new();
        for record in &records {
            let reps = LightsailRecord::from_dns_record(record)?;
            for rep in reps {
                desired.push(rep.target);
            }
        }

        let existing = self
            .find_entries(&domain_name, &entry_name, type_str)
            .await?;

        let mut queued: Vec<String> = Vec::new();
        for target in desired {
            if existing.iter().any(|e| e.target == target) {
                continue;
            }
            if queued.contains(&target) {
                continue;
            }
            queued.push(target);
        }

        for target in queued {
            self.create_entry(&domain_name, &entry_name, type_str, &target)
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
    ) -> Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let type_str = lightsail_record_type(record_type)?;

        let name = name.into_name().to_ascii_lowercase();
        let origin = origin.into_name().to_ascii_lowercase();
        let domain_name = self.resolve_zone(&name, &origin).await?;
        let entry_name = full_record_name(&name, &domain_name);

        let mut to_remove: Vec<String> = Vec::new();
        for record in &records {
            let reps = LightsailRecord::from_dns_record(record)?;
            for rep in reps {
                to_remove.push(rep.target);
            }
        }

        let existing = self
            .find_entries(&domain_name, &entry_name, type_str)
            .await?;

        for entry in existing {
            if to_remove.contains(&entry.target) {
                self.delete_entry(&domain_name, &entry).await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> Result<Vec<DnsRecord>> {
        let type_str = lightsail_record_type(record_type)?;

        let name = name.into_name().to_ascii_lowercase();
        let origin = origin.into_name().to_ascii_lowercase();
        let domain_name = self.resolve_zone(&name, &origin).await?;
        let entry_name = full_record_name(&name, &domain_name);

        let entries = self
            .find_entries(&domain_name, &entry_name, type_str)
            .await?;

        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            out.push(parse_target(record_type, &entry.target)?);
        }
        Ok(out)
    }
}

fn full_record_name(name: &str, domain: &str) -> String {
    let stripped = strip_origin_from_name(name, domain, Some(""));
    let domain = domain.trim_end_matches('.');
    if stripped.is_empty() {
        domain.to_string()
    } else {
        format!("{}.{}", stripped, domain)
    }
}

fn lightsail_record_type(record_type: DnsRecordType) -> Result<&'static str> {
    match record_type {
        DnsRecordType::A => Ok("A"),
        DnsRecordType::AAAA => Ok("AAAA"),
        DnsRecordType::CNAME => Ok("CNAME"),
        DnsRecordType::NS => Ok("NS"),
        DnsRecordType::MX => Ok("MX"),
        DnsRecordType::TXT => Ok("TXT"),
        DnsRecordType::SRV => Ok("SRV"),
        DnsRecordType::CAA => Err(Error::Unsupported(
            "CAA records are not supported by Lightsail".to_string(),
        )),
        DnsRecordType::TLSA => Err(Error::Unsupported(
            "TLSA records are not supported by Lightsail".to_string(),
        )),
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

#[allow(dead_code)]
struct LightsailRecord {
    record_type: String,
    target: String,
}

impl LightsailRecord {
    fn from_dns_record(record: &DnsRecord) -> Result<Vec<Self>> {
        let (record_type, targets) = match record {
            DnsRecord::A(addr) => ("A", vec![addr.to_string()]),
            DnsRecord::AAAA(addr) => ("AAAA", vec![addr.to_string()]),
            DnsRecord::CNAME(value) => ("CNAME", vec![ensure_dot(value)]),
            DnsRecord::NS(value) => ("NS", vec![ensure_dot(value)]),
            DnsRecord::MX(mx) => (
                "MX",
                vec![format!("{} {}", mx.priority, ensure_dot(&mx.exchange))],
            ),
            DnsRecord::TXT(value) => {
                let mut out = String::new();
                txt_chunks_to_text(&mut out, value, " ");
                ("TXT", vec![out])
            }
            DnsRecord::SRV(srv) => (
                "SRV",
                vec![format!(
                    "{} {} {} {}",
                    srv.priority,
                    srv.weight,
                    srv.port,
                    ensure_dot(&srv.target)
                )],
            ),
            DnsRecord::CAA(_) => {
                return Err(Error::Unsupported(
                    "CAA records are not supported by Lightsail".to_string(),
                ));
            }
            DnsRecord::TLSA(_) => {
                return Err(Error::Unsupported(
                    "TLSA records are not supported by Lightsail".to_string(),
                ));
            }
        };
        Ok(targets
            .into_iter()
            .map(|target| Self {
                record_type: record_type.to_string(),
                target,
            })
            .collect())
    }
}

fn parse_target(record_type: DnsRecordType, target: &str) -> Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => target
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("lightsail invalid A target {target}: {e}"))),
        DnsRecordType::AAAA => target
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("lightsail invalid AAAA target {target}: {e}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(target.to_string())),
        DnsRecordType::NS => Ok(DnsRecord::NS(target.to_string())),
        DnsRecordType::MX => {
            let trimmed = target.trim();
            let (prio_str, exchange) = trimmed
                .split_once(char::is_whitespace)
                .ok_or_else(|| Error::Parse(format!("lightsail invalid MX target: {target}")))?;
            let priority: u16 = prio_str
                .parse()
                .map_err(|e| Error::Parse(format!("lightsail MX priority {prio_str}: {e}")))?;
            Ok(DnsRecord::MX(MXRecord {
                priority,
                exchange: exchange.trim().to_string(),
            }))
        }
        DnsRecordType::TXT => Ok(DnsRecord::TXT(unquote_txt(target))),
        DnsRecordType::SRV => {
            let mut parts = target.split_whitespace();
            let priority: u16 = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("lightsail SRV missing priority: {target}")))?
                .parse()
                .map_err(|e| Error::Parse(format!("lightsail SRV priority: {e}")))?;
            let weight: u16 = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("lightsail SRV missing weight: {target}")))?
                .parse()
                .map_err(|e| Error::Parse(format!("lightsail SRV weight: {e}")))?;
            let port: u16 = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("lightsail SRV missing port: {target}")))?
                .parse()
                .map_err(|e| Error::Parse(format!("lightsail SRV port: {e}")))?;
            let target_field = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("lightsail SRV missing target: {target}")))?
                .to_string();
            Ok(DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target: target_field,
            }))
        }
        DnsRecordType::CAA => Err(Error::Unsupported(
            "CAA records are not supported by Lightsail".to_string(),
        )),
        DnsRecordType::TLSA => Err(Error::Unsupported(
            "TLSA records are not supported by Lightsail".to_string(),
        )),
    }
}

fn unquote_txt(content: &str) -> String {
    let mut out = String::new();
    let mut chars = content.chars().peekable();
    let mut inside = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                inside = !inside;
            }
            '\\' if inside => {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            _ if inside => out.push(ch),
            _ => {}
        }
    }
    if !out.is_empty() {
        out
    } else {
        content.to_string()
    }
}

fn ensure_dot(value: &str) -> String {
    if value.ends_with('.') {
        value.to_string()
    } else {
        format!("{}.", value)
    }
}
