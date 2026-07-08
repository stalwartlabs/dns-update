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

use crate::utils::split_caa_value;
use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord,
    crypto::hmac_sha1,
    http::{HttpClient, HttpClientBuilder},
    utils::strip_origin_from_name,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{SecondsFormat, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://rest.websupport.sk";
const SERVICES_PAGE_SIZE: u32 = 500;

#[derive(Clone)]
pub struct WebSupportProvider {
    client: HttpClient,
    api_key: String,
    secret: String,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecord<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    name: &'a str,
    content: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
}

#[derive(Deserialize, Debug)]
struct WebSupportRecord {
    id: i64,
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    priority: Option<u16>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    weight: Option<u16>,
}

#[derive(Deserialize, Debug)]
struct RecordResponse {
    data: Vec<WebSupportRecord>,
}

#[derive(Deserialize, Debug)]
struct Service {
    id: i64,
    #[serde(rename = "serviceName", default)]
    service_name: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize, Debug)]
struct ServicesResponse {
    items: Vec<Service>,
    #[serde(default)]
    pager: Option<Pager>,
}

#[derive(Deserialize, Debug)]
struct Pager {
    #[serde(default)]
    pagesize: Option<u32>,
    #[serde(default)]
    items: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordContent {
    content: String,
    priority: Option<u16>,
    port: Option<u16>,
    weight: Option<u16>,
}

#[derive(Debug, Clone)]
struct ListedRecord {
    id: i64,
    content: RecordContent,
}

impl WebSupportProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        let secret = secret.as_ref();
        if api_key.is_empty() || secret.is_empty() {
            return Err(Error::Api("WebSupport credentials missing".into()));
        }
        let client = HttpClientBuilder::default()
            .with_header("Accept", "application/json")
            .with_header("Accept-Language", "en_us")
            .with_timeout(timeout)
            .build();
        Ok(Self {
            client,
            api_key: api_key.to_string(),
            secret: secret.to_string(),
            endpoint: DEFAULT_ENDPOINT.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    fn signed(
        &self,
        request: crate::http::HttpRequest,
        method: Method,
        path: &str,
    ) -> crate::http::HttpRequest {
        let now = Utc::now();
        let timestamp = now.timestamp();
        let date = now.to_rfc3339_opts(SecondsFormat::Secs, true);
        let canonical = format!("{} {} {}", method.as_str(), path, timestamp);
        let signature = hex::encode(hmac_sha1(self.secret.as_bytes(), canonical.as_bytes()));
        let basic = BASE64_STANDARD.encode(format!("{}:{}", self.api_key, signature));
        request
            .with_header("Authorization", format!("Basic {}", basic))
            .with_header("Date", date)
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
        reject_unsupported_type(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let service_id = self.obtain_service_id(&domain).await?;
        let desired = build_contents(record_type, records)?;
        let existing = self.list_at(service_id, &subdomain, record_type).await?;

        let mut existing_pool: Vec<ListedRecord> = existing;
        let mut to_add: Vec<RecordContent> = Vec::new();

        for content in desired {
            if let Some(idx) = existing_pool.iter().position(|r| r.content == content) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(content);
            }
        }

        for entry in existing_pool {
            self.delete_record(service_id, entry.id).await?;
        }
        for content in to_add {
            let body = content_to_create(record_type, &subdomain, ttl, content);
            self.create_record(service_id, body).await?;
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
        check_record_types(record_type, &records)?;
        reject_unsupported_type(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let service_id = self.obtain_service_id(&domain).await?;
        let desired = build_contents(record_type, records)?;
        let existing = self.list_at(service_id, &subdomain, record_type).await?;

        for content in desired {
            if existing.iter().any(|r| r.content == content) {
                continue;
            }
            let body = content_to_create(record_type, &subdomain, ttl, content);
            self.create_record(service_id, body).await?;
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
        check_record_types(record_type, &records)?;
        reject_unsupported_type(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let service_id = self.obtain_service_id(&domain).await?;
        let to_remove = build_contents(record_type, records)?;
        let existing = self.list_at(service_id, &subdomain, record_type).await?;

        for content in to_remove {
            if let Some(entry) = existing.iter().find(|r| r.content == content) {
                self.delete_record(service_id, entry.id).await?;
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
        reject_unsupported_type(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let service_id = self.obtain_service_id(&domain).await?;
        let existing = self.list_at(service_id, &subdomain, record_type).await?;
        existing
            .into_iter()
            .map(|r| record_from_listed(record_type, r.content))
            .collect()
    }

    async fn obtain_service_id(&self, domain: &str) -> crate::Result<i64> {
        const SERVICES_PATH: &str = "/v1/user/self/service";
        let mut page: u32 = 1;
        loop {
            let url = format!(
                "{}{}?page={}&pagesize={}",
                self.endpoint, SERVICES_PATH, page, SERVICES_PAGE_SIZE
            );
            let response: ServicesResponse = self
                .signed(self.client.get(url), Method::GET, SERVICES_PATH)
                .send()
                .await?;
            let returned = response.items.len() as u32;
            if let Some(found) = response
                .items
                .into_iter()
                .find(|s| s.service_name == "domain" && s.name == domain)
            {
                return Ok(found.id);
            }
            let total = response.pager.as_ref().map(|p| p.items).unwrap_or(0);
            let pagesize = response
                .pager
                .as_ref()
                .and_then(|p| p.pagesize)
                .unwrap_or(SERVICES_PAGE_SIZE);
            let seen = page.saturating_mul(pagesize.max(1));
            if returned == 0 || total == 0 || seen >= total {
                return Err(Error::Api(format!(
                    "WebSupport domain service {} not found",
                    domain
                )));
            }
            page += 1;
        }
    }

    async fn list_at(
        &self,
        service_id: i64,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ListedRecord>> {
        let path = format!("/v2/service/{}/dns/record", service_id);
        let url = format!("{}{}", self.endpoint, path);
        let response: RecordResponse = self
            .signed(self.client.get(url), Method::GET, &path)
            .send()
            .await?;
        let type_str = record_type.as_str();
        let mut out = Vec::new();
        for r in response.data {
            if r.name != subdomain || r.record_type != type_str {
                continue;
            }
            out.push(ListedRecord {
                id: r.id,
                content: RecordContent {
                    content: r.content,
                    priority: r.priority,
                    port: r.port,
                    weight: r.weight,
                },
            });
        }
        Ok(out)
    }

    async fn create_record<'a>(
        &self,
        service_id: i64,
        body: CreateRecord<'a>,
    ) -> crate::Result<()> {
        let path = format!("/v2/service/{}/dns/record", service_id);
        let url = format!("{}{}", self.endpoint, path);
        self.signed(self.client.post(url).with_body(body)?, Method::POST, &path)
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, service_id: i64, record_id: i64) -> crate::Result<()> {
        let path = format!("/v2/service/{}/dns/record/{}", service_id, record_id);
        let url = format!("{}{}", self.endpoint, path);
        self.signed(self.client.delete(url), Method::DELETE, &path)
            .send_with_retry::<serde_json::Value>(3)
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

fn reject_unsupported_type(record_type: DnsRecordType) -> crate::Result<()> {
    if matches!(record_type, DnsRecordType::TLSA) {
        return Err(Error::Unsupported(
            "TLSA records are not supported by WebSupport".into(),
        ));
    }
    Ok(())
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
        out.push(record_to_content(record)?);
    }
    Ok(out)
}

fn record_to_content(record: DnsRecord) -> crate::Result<RecordContent> {
    Ok(match record {
        DnsRecord::A(addr) => RecordContent {
            content: addr.to_string(),
            priority: None,
            port: None,
            weight: None,
        },
        DnsRecord::AAAA(addr) => RecordContent {
            content: addr.to_string(),
            priority: None,
            port: None,
            weight: None,
        },
        DnsRecord::CNAME(target) => RecordContent {
            content: target,
            priority: None,
            port: None,
            weight: None,
        },
        DnsRecord::NS(target) => RecordContent {
            content: target,
            priority: None,
            port: None,
            weight: None,
        },
        DnsRecord::MX(mx) => RecordContent {
            content: mx.exchange,
            priority: Some(mx.priority),
            port: None,
            weight: None,
        },
        DnsRecord::TXT(text) => RecordContent {
            content: text,
            priority: None,
            port: None,
            weight: None,
        },
        DnsRecord::SRV(srv) => RecordContent {
            content: srv.target,
            priority: Some(srv.priority),
            port: Some(srv.port),
            weight: Some(srv.weight),
        },
        DnsRecord::CAA(caa) => RecordContent {
            content: format!("{}", caa),
            priority: None,
            port: None,
            weight: None,
        },
        DnsRecord::TLSA(_) => {
            return Err(Error::Unsupported(
                "TLSA records are not supported by WebSupport".into(),
            ));
        }
    })
}

fn content_to_create<'a>(
    record_type: DnsRecordType,
    name: &'a str,
    ttl: u32,
    content: RecordContent,
) -> CreateRecord<'a> {
    CreateRecord {
        record_type: record_type.as_str(),
        name,
        content: content.content,
        ttl,
        priority: content.priority,
        port: content.port,
        weight: content.weight,
    }
}

fn record_from_listed(
    record_type: DnsRecordType,
    content: RecordContent,
) -> crate::Result<DnsRecord> {
    Ok(match record_type {
        DnsRecordType::A => {
            DnsRecord::A(content.content.parse().map_err(|e| {
                Error::Parse(format!("invalid A address {}: {}", content.content, e))
            })?)
        }
        DnsRecordType::AAAA => DnsRecord::AAAA(content.content.parse().map_err(|e| {
            Error::Parse(format!("invalid AAAA address {}: {}", content.content, e))
        })?),
        DnsRecordType::CNAME => DnsRecord::CNAME(content.content),
        DnsRecordType::NS => DnsRecord::NS(content.content),
        DnsRecordType::MX => DnsRecord::MX(MXRecord {
            exchange: content.content,
            priority: content.priority.unwrap_or(0),
        }),
        DnsRecordType::TXT => DnsRecord::TXT(content.content),
        DnsRecordType::SRV => DnsRecord::SRV(SRVRecord {
            target: content.content,
            priority: content.priority.unwrap_or(0),
            weight: content.weight.unwrap_or(0),
            port: content.port.unwrap_or(0),
        }),
        DnsRecordType::CAA => DnsRecord::CAA(parse_caa(&content.content)?),
        DnsRecordType::TLSA => {
            return Err(Error::Unsupported(
                "TLSA records are not supported by WebSupport".into(),
            ));
        }
    })
}

fn parse_caa(raw: &str) -> crate::Result<CAARecord> {
    let trimmed = raw.trim();
    let mut parts = trimmed.splitn(3, char::is_whitespace);
    let flags_str = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {raw}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {raw}")))?;
    let value = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {raw}")))?;
    let flags: u8 = flags_str
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags {flags_str}: {e}")))?;
    let issuer_critical = flags & 0x80 != 0;
    let value_unquoted = value
        .trim()
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(value.trim())
        .to_string();
    match tag {
        "issue" => {
            let (name, options) = split_caa_value(&value_unquoted);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = split_caa_value(&value_unquoted);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: value_unquoted,
        }),
        other => Err(Error::Parse(format!("unknown CAA tag: {other}"))),
    }
}
