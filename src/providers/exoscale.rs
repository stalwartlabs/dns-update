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
    crypto::hmac_sha256,
    http::{HttpClient, HttpClientBuilder},
    utils::strip_origin_from_name,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api-ch-gva-2.exoscale.com/v2";
const SIGNATURE_EXPIRES_SECONDS: i64 = 300;

#[derive(Clone)]
pub struct ExoscaleProvider {
    client: HttpClient,
    api_key: String,
    api_secret: String,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecordRequest<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'static str,
    content: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
}

#[derive(Deserialize, Debug)]
struct DnsDomain {
    id: String,
    #[serde(rename = "unicode-name", default)]
    unicode_name: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize, Debug)]
struct DomainList {
    #[serde(rename = "dns-domains", default)]
    dns_domains: Vec<DnsDomain>,
}

#[derive(Deserialize, Debug, Clone)]
struct DnsRecordResponse {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(rename = "type", default)]
    record_type: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    priority: Option<u16>,
}

#[derive(Deserialize, Debug)]
struct RecordList {
    #[serde(rename = "dns-domain-records", default)]
    records: Vec<DnsRecordResponse>,
}

struct ListedRecord {
    id: String,
    record: DnsRecord,
}

impl ExoscaleProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        api_secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        let api_secret = api_secret.as_ref();
        if api_key.is_empty() || api_secret.is_empty() {
            return Err(Error::Api("Exoscale credentials missing".into()));
        }
        let client = HttpClientBuilder::default().with_timeout(timeout).build();
        Ok(Self {
            client,
            api_key: api_key.to_string(),
            api_secret: api_secret.to_string(),
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

    fn build_authorization(&self, method: &Method, path: &str, body: &str) -> String {
        let expires = Utc::now().timestamp() + SIGNATURE_EXPIRES_SECONDS;
        let signing_string = format!("{} {}\n\n{}\n\n{}", method.as_str(), path, body, expires);
        let signature = hmac_sha256(self.api_secret.as_bytes(), signing_string.as_bytes());
        let signature_b64 = BASE64_STANDARD.encode(&signature);
        format!(
            "EXO2-HMAC-SHA256 credential={},expires={},signature={}",
            self.api_key, expires, signature_b64
        )
    }

    fn signed(
        &self,
        request: crate::http::HttpRequest,
        method: Method,
        path: &str,
        body: &str,
    ) -> crate::http::HttpRequest {
        let auth = self.build_authorization(&method, path, body);
        request.with_header("Authorization", auth)
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
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let zone_id = self.obtain_zone_id(&domain).await?;
        let existing = self.list_at(&zone_id, &subdomain, record_type).await?;

        let mut to_keep: Vec<bool> = vec![false; existing.len()];
        let mut to_add: Vec<DnsRecord> = Vec::new();
        for desired in records {
            if let Some(idx) = existing
                .iter()
                .enumerate()
                .position(|(i, r)| !to_keep[i] && r.record == desired)
            {
                to_keep[idx] = true;
            } else {
                to_add.push(desired);
            }
        }

        for (i, entry) in existing.iter().enumerate() {
            if !to_keep[i] {
                self.delete_record(&zone_id, &entry.id).await?;
            }
        }
        for desired in to_add {
            self.post_record(&zone_id, &subdomain, &desired, ttl)
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
        check_record_types(record_type, &records)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let zone_id = self.obtain_zone_id(&domain).await?;
        let existing = self.list_at(&zone_id, &subdomain, record_type).await?;
        for desired in records {
            if existing.iter().any(|r| r.record == desired) {
                continue;
            }
            self.post_record(&zone_id, &subdomain, &desired, ttl)
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
        check_record_types(record_type, &records)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let zone_id = self.obtain_zone_id(&domain).await?;
        let existing = self.list_at(&zone_id, &subdomain, record_type).await?;
        let mut deleted: Vec<bool> = vec![false; existing.len()];
        for desired in records {
            if let Some(idx) = existing
                .iter()
                .enumerate()
                .position(|(i, r)| !deleted[i] && r.record == desired)
            {
                deleted[idx] = true;
                self.delete_record(&zone_id, &existing[idx].id).await?;
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
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let zone_id = self.obtain_zone_id(&domain).await?;
        let existing = self.list_at(&zone_id, &subdomain, record_type).await?;
        Ok(existing.into_iter().map(|r| r.record).collect())
    }

    async fn obtain_zone_id(&self, domain: &str) -> crate::Result<String> {
        let path = "/dns-domain";
        let url = format!("{}{}", self.endpoint, path);
        let response: DomainList = self
            .signed(self.client.get(url), Method::GET, path, "")
            .send()
            .await?;
        response
            .dns_domains
            .into_iter()
            .find(|d| d.unicode_name == domain || d.name.as_deref() == Some(domain))
            .map(|d| d.id)
            .ok_or_else(|| Error::Api(format!("Exoscale domain {} not found", domain)))
    }

    async fn list_at(
        &self,
        zone_id: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ListedRecord>> {
        let path = format!("/dns-domain/{}/record", zone_id);
        let url = format!("{}{}", self.endpoint, path);
        let response: RecordList = self
            .signed(self.client.get(url), Method::GET, &path, "")
            .send()
            .await?;
        let type_str = record_type.as_str();
        let mut out = Vec::new();
        for raw in response.records {
            if raw.name != subdomain || raw.record_type != type_str {
                continue;
            }
            if let Some(record) = parse_listed_record(&raw)? {
                out.push(ListedRecord { id: raw.id, record });
            }
        }
        Ok(out)
    }

    async fn post_record(
        &self,
        zone_id: &str,
        subdomain: &str,
        record: &DnsRecord,
        ttl: u32,
    ) -> crate::Result<()> {
        let body = build_create_record(subdomain, record, ttl)?;
        let body_str = serde_json::to_string(&body)
            .map_err(|e| Error::Serialize(format!("body serialization failed: {e}")))?;
        let path = format!("/dns-domain/{}/record", zone_id);
        let url = format!("{}{}", self.endpoint, path);
        self.signed(
            self.client.post(url).with_raw_body(body_str.clone()),
            Method::POST,
            &path,
            &body_str,
        )
        .send_with_retry::<serde_json::Value>(3)
        .await
        .map(|_| ())
    }

    async fn delete_record(&self, zone_id: &str, record_id: &str) -> crate::Result<()> {
        let path = format!("/dns-domain/{}/record/{}", zone_id, record_id);
        let url = format!("{}{}", self.endpoint, path);
        self.signed(self.client.delete(url), Method::DELETE, &path, "")
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> crate::Result<()> {
    if expected == DnsRecordType::TLSA {
        return Err(Error::Unsupported(
            "TLSA records are not supported by Exoscale".into(),
        ));
    }
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

fn build_create_record<'a>(
    name: &'a str,
    record: &DnsRecord,
    ttl: u32,
) -> crate::Result<CreateRecordRequest<'a>> {
    let mut req = CreateRecordRequest {
        name,
        record_type: dns_type(record)?,
        content: String::new(),
        ttl,
        priority: None,
    };
    match record {
        DnsRecord::A(addr) => req.content = addr.to_string(),
        DnsRecord::AAAA(addr) => req.content = addr.to_string(),
        DnsRecord::CNAME(target) => req.content = target.clone(),
        DnsRecord::NS(target) => req.content = target.clone(),
        DnsRecord::MX(mx) => {
            req.content = mx.exchange.clone();
            req.priority = Some(mx.priority);
        }
        DnsRecord::TXT(text) => {
            req.content = format!("\"{}\"", text.replace('\"', "\\\""));
        }
        DnsRecord::SRV(srv) => {
            req.content = format!("{} {} {}", srv.weight, srv.port, srv.target);
            req.priority = Some(srv.priority);
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Unsupported(
                "TLSA records are not supported by Exoscale".into(),
            ));
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            req.content = format!("{} {} \"{}\"", flags, tag, value);
        }
    }
    Ok(req)
}

fn dns_type(record: &DnsRecord) -> crate::Result<&'static str> {
    match record {
        DnsRecord::A(_) => Ok("A"),
        DnsRecord::AAAA(_) => Ok("AAAA"),
        DnsRecord::CNAME(_) => Ok("CNAME"),
        DnsRecord::NS(_) => Ok("NS"),
        DnsRecord::MX(_) => Ok("MX"),
        DnsRecord::TXT(_) => Ok("TXT"),
        DnsRecord::SRV(_) => Ok("SRV"),
        DnsRecord::CAA(_) => Ok("CAA"),
        DnsRecord::TLSA(_) => Err(Error::Unsupported(
            "TLSA records are not supported by Exoscale".into(),
        )),
    }
}

fn parse_listed_record(raw: &DnsRecordResponse) -> crate::Result<Option<DnsRecord>> {
    let priority = raw.priority.unwrap_or(0);
    Ok(Some(match raw.record_type.as_str() {
        "A" => match raw.content.parse() {
            Ok(addr) => DnsRecord::A(addr),
            Err(_) => return Ok(None),
        },
        "AAAA" => match raw.content.parse() {
            Ok(addr) => DnsRecord::AAAA(addr),
            Err(_) => return Ok(None),
        },
        "CNAME" => DnsRecord::CNAME(raw.content.clone()),
        "NS" => DnsRecord::NS(raw.content.clone()),
        "MX" => DnsRecord::MX(MXRecord {
            exchange: raw.content.clone(),
            priority,
        }),
        "TXT" => DnsRecord::TXT(unquote_txt(&raw.content)),
        "SRV" => match parse_srv_content(&raw.content, priority) {
            Some(srv) => DnsRecord::SRV(srv),
            None => return Ok(None),
        },
        "CAA" => match parse_caa_content(&raw.content) {
            Some(caa) => DnsRecord::CAA(caa),
            None => return Ok(None),
        },
        _ => return Ok(None),
    }))
}

fn unquote_txt(content: &str) -> String {
    let trimmed = content
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(content);
    trimmed.replace("\\\"", "\"")
}

fn parse_srv_content(content: &str, priority: u16) -> Option<SRVRecord> {
    let mut parts = content.split_whitespace();
    let weight: u16 = parts.next()?.parse().ok()?;
    let port: u16 = parts.next()?.parse().ok()?;
    let target = parts.next()?.to_string();
    if parts.next().is_some() {
        return None;
    }
    Some(SRVRecord {
        priority,
        weight,
        port,
        target,
    })
}

fn parse_caa_content(content: &str) -> Option<CAARecord> {
    let trimmed = content.trim();
    let mut iter = trimmed.splitn(3, char::is_whitespace);
    let flags_str = iter.next()?;
    let tag = iter.next()?;
    let value_part = iter.next()?.trim();
    let flags: u8 = flags_str.parse().ok()?;
    let issuer_critical = flags & 0x80 != 0;
    let raw_value = value_part
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(value_part)
        .to_string();
    Some(match tag {
        "issue" => {
            let (name, options) = parse_caa_value(&raw_value);
            CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(&raw_value);
            CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            }
        }
        "iodef" => CAARecord::Iodef {
            issuer_critical,
            url: raw_value,
        },
        _ => return None,
    })
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
