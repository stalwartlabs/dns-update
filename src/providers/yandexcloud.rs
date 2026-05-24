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

use crate::http::{HttpClient, HttpClientBuilder};
use crate::jwt::{JwtSignAlgorithm, sign_jwt};
use crate::utils::{strip_origin_from_name, txt_chunks_to_text};
use crate::{CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, KeyValue, MXRecord, SRVRecord};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_TXT_RDATA_BYTES: usize = 255;
const ZONE_PAGE_SIZE: u32 = 100;

#[derive(Debug, Clone)]
pub struct YandexCloudConfig {
    pub iam_token_b64: String,
    pub folder_id: String,
    pub request_timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct YandexCloudProvider {
    iam_client: Client,
    http: HttpClient,
    config: YandexCloudConfig,
    token: Arc<Mutex<Option<(String, Instant)>>>,
    endpoints: YandexCloudEndpoints,
}

#[derive(Clone)]
struct YandexCloudEndpoints {
    iam_base_url: String,
    dns_base_url: String,
}

impl Default for YandexCloudEndpoints {
    fn default() -> Self {
        Self {
            iam_base_url: "https://iam.api.cloud.yandex.net".to_string(),
            dns_base_url: "https://dns.api.cloud.yandex.net".to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    id: String,
    service_account_id: String,
    private_key: String,
}

#[derive(Debug, Clone)]
struct RecordSet {
    name: String,
    record_type: &'static str,
    ttl: u32,
    data: Vec<String>,
}

impl RecordSet {
    fn to_json(&self) -> Value {
        serde_json::json!({
            "name": self.name,
            "type": self.record_type,
            "ttl": self.ttl,
            "data": self.data,
        })
    }
}

impl YandexCloudProvider {
    pub(crate) fn new(config: YandexCloudConfig) -> crate::Result<Self> {
        if config.iam_token_b64.is_empty() {
            return Err(Error::Api(
                "Yandex Cloud requires a base64-encoded service account key (iam_token_b64)".into(),
            ));
        }
        if config.folder_id.is_empty() {
            return Err(Error::Api("Yandex Cloud requires a folder_id".into()));
        }

        let mut builder = Client::builder();
        if let Some(timeout) = config.request_timeout {
            builder = builder.timeout(timeout);
        }
        let iam_client = builder
            .build()
            .map_err(|e| Error::Client(format!("Failed to build reqwest client: {}", e)))?;

        let http = HttpClientBuilder::default()
            .with_timeout(config.request_timeout)
            .build();

        Ok(Self {
            iam_client,
            http,
            config,
            token: Arc::new(Mutex::new(None)),
            endpoints: YandexCloudEndpoints::default(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoints(
        mut self,
        iam_base_url: impl AsRef<str>,
        dns_base_url: impl AsRef<str>,
    ) -> Self {
        self.endpoints = YandexCloudEndpoints {
            iam_base_url: iam_base_url.as_ref().trim_end_matches('/').to_string(),
            dns_base_url: dns_base_url.as_ref().trim_end_matches('/').to_string(),
        };
        self
    }

    #[cfg(test)]
    pub(crate) fn with_cached_token(self, token: impl Into<String>) -> Self {
        *self.token.lock().expect("yc token lock") =
            Some((token.into(), Instant::now() + Duration::from_secs(55 * 60)));
        self
    }

    async fn ensure_token(&self) -> crate::Result<String> {
        if let Some((ref token, expiry)) = *self.token_lock()?
            && Instant::now() < expiry
        {
            return Ok(token.clone());
        }

        let key = decode_service_account_key(&self.config.iam_token_b64)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Api(format!("Clock error: {}", e)))?
            .as_secs();
        let exp = now + 3600;
        let audience = format!("{}/iam/v1/tokens", self.endpoints.iam_base_url);
        let header = serde_json::json!({
            "alg": "PS256",
            "typ": "JWT",
            "kid": key.id,
        });
        let claims = serde_json::json!({
            "iss": key.service_account_id,
            "aud": audience,
            "iat": now,
            "exp": exp,
        });
        let jwt = sign_jwt(&header, &claims, &key.private_key, JwtSignAlgorithm::Ps256)
            .map_err(|e| Error::Api(format!("Failed to sign Yandex JWT: {}", e)))?;

        let url = format!("{}/iam/v1/tokens", self.endpoints.iam_base_url);
        let resp = self
            .iam_client
            .post(&url)
            .json(&serde_json::json!({ "jwt": jwt }))
            .send()
            .await
            .map_err(|e| Error::Api(format!("Yandex IAM token request failed: {}", e)))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| Error::Api(format!("Failed to read IAM token response: {}", e)))?;
        if !status.is_success() {
            return Err(match status.as_u16() {
                400 => Error::Api(format!("BadRequest {}", text)),
                401 | 403 => Error::Unauthorized,
                404 => Error::NotFound,
                _ => Error::Api(format!("Yandex IAM token error {}: {}", status, text)),
            });
        }
        let value: Value = serde_json::from_str(&text)
            .map_err(|e| Error::Api(format!("Failed to parse IAM token response: {}", e)))?;
        let access_token = value
            .get("iamToken")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Api("Yandex IAM token response missing iamToken".into()))?
            .to_string();

        let expiry = Instant::now() + Duration::from_secs(55 * 60);
        *self.token_lock()? = Some((access_token.clone(), expiry));
        Ok(access_token)
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
        let type_str = record_type_str(record_type)?;
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone = self.resolve_zone(&origin).await?;
        let subdomain = strip_origin_from_name(&name, &zone.zone, None);

        if records.is_empty() {
            let Some(existing) = self.get_record_set(&zone.id, &subdomain, type_str).await? else {
                return Ok(());
            };
            return self.upsert(&zone.id, &[existing], &[], &[]).await;
        }

        let data = records
            .iter()
            .map(|r| record_to_entry(r).map(|e| e.value))
            .collect::<crate::Result<Vec<_>>>()?;
        let desired = RecordSet {
            name: subdomain,
            record_type: type_str,
            ttl,
            data,
        };
        self.upsert(&zone.id, &[], &[desired], &[]).await
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
        let type_str = record_type_str(record_type)?;
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone = self.resolve_zone(&origin).await?;
        let subdomain = strip_origin_from_name(&name, &zone.zone, None);

        let existing = self
            .get_record_set(&zone.id, &subdomain, type_str)
            .await?;
        let existing_data = existing
            .as_ref()
            .map(|rs| rs.data.clone())
            .unwrap_or_default();
        let effective_ttl = existing.as_ref().map(|rs| rs.ttl).unwrap_or(ttl);

        let to_add: Vec<String> = records
            .iter()
            .map(|r| record_to_entry(r).map(|e| e.value))
            .collect::<crate::Result<Vec<_>>>()?
            .into_iter()
            .filter(|v| !existing_data.iter().any(|e| txt_equivalent(e, v, type_str)))
            .collect();

        if to_add.is_empty() {
            return Ok(());
        }

        let merge = RecordSet {
            name: subdomain,
            record_type: type_str,
            ttl: effective_ttl,
            data: to_add,
        };
        self.upsert(&zone.id, &[], &[], &[merge]).await
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
        let type_str = record_type_str(record_type)?;
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone = self.resolve_zone(&origin).await?;
        let subdomain = strip_origin_from_name(&name, &zone.zone, None);

        let Some(existing) = self.get_record_set(&zone.id, &subdomain, type_str).await? else {
            return Ok(());
        };

        let to_remove = records
            .iter()
            .map(|r| record_to_entry(r).map(|e| e.value))
            .collect::<crate::Result<Vec<_>>>()?;
        let filtered: Vec<String> = existing
            .data
            .iter()
            .filter(|v| !to_remove.iter().any(|t| txt_equivalent(v, t, type_str)))
            .cloned()
            .collect();

        if filtered.len() == existing.data.len() {
            return Ok(());
        }

        if filtered.is_empty() {
            return self.upsert(&zone.id, &[existing], &[], &[]).await;
        }

        let replacement = RecordSet {
            name: existing.name.clone(),
            record_type: type_str,
            ttl: existing.ttl,
            data: filtered,
        };
        self.upsert(&zone.id, &[], &[replacement], &[]).await
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let type_str = record_type_str(record_type)?;
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone = self.resolve_zone(&origin).await?;
        let subdomain = strip_origin_from_name(&name, &zone.zone, None);

        let Some(existing) = self.get_record_set(&zone.id, &subdomain, type_str).await? else {
            return Ok(Vec::new());
        };

        existing
            .data
            .iter()
            .map(|s| parse_rrdata(record_type, s))
            .collect()
    }

    async fn resolve_zone(&self, origin: &str) -> crate::Result<ResolvedZone> {
        let token = self.ensure_token().await?;
        let target = format!("{}.", origin.trim_end_matches('.'));
        let filter = format!("zone=\"{}\"", target);
        let mut page_token: Option<String> = None;

        loop {
            let mut query: Vec<(String, String)> = vec![
                ("folderId".to_string(), self.config.folder_id.clone()),
                ("pageSize".to_string(), ZONE_PAGE_SIZE.to_string()),
                ("filter".to_string(), filter.clone()),
            ];
            if let Some(ref tok) = page_token {
                query.push(("pageToken".to_string(), tok.clone()));
            }
            let qs = serde_urlencoded::to_string(&query)
                .map_err(|e| Error::Api(format!("Failed to encode zones query: {}", e)))?;
            let url = format!("{}/dns/v1/zones?{}", self.endpoints.dns_base_url, qs);

            let value: Value = self
                .http
                .get(url)
                .with_header("authorization", format!("Bearer {}", token))
                .send_with_retry(3)
                .await?;

            let zones = value
                .get("dnsZones")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for zone in zones {
                let zone_name = zone
                    .get("zone")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if zone_name == target {
                    let id = zone
                        .get("id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| Error::Api("Yandex DNS zone missing id".into()))?
                        .to_string();
                    return Ok(ResolvedZone {
                        id,
                        zone: zone_name,
                    });
                }
            }

            page_token = value
                .get("nextPageToken")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            if page_token.is_none() {
                break;
            }
        }

        Err(Error::Api(format!(
            "No Yandex Cloud DNS zone matches origin {}",
            origin
        )))
    }

    async fn get_record_set(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
    ) -> crate::Result<Option<RecordSet>> {
        let token = self.ensure_token().await?;
        let query = serde_urlencoded::to_string([("name", name), ("type", record_type)])
            .map_err(|e| Error::Api(format!("Failed to encode query: {}", e)))?;
        let url = format!(
            "{}/dns/v1/zones/{}:getRecordSet?{}",
            self.endpoints.dns_base_url, zone_id, query
        );
        let result: crate::Result<Value> = self
            .http
            .get(url)
            .with_header("authorization", format!("Bearer {}", token))
            .send_with_retry(3)
            .await;
        match result {
            Ok(value) => parse_record_set(&value).map(Some),
            Err(Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn upsert(
        &self,
        zone_id: &str,
        deletions: &[RecordSet],
        replacements: &[RecordSet],
        merges: &[RecordSet],
    ) -> crate::Result<()> {
        let token = self.ensure_token().await?;
        let url = format!(
            "{}/dns/v1/zones/{}:upsertRecordSets",
            self.endpoints.dns_base_url, zone_id
        );
        let body = serde_json::json!({
            "deletions": deletions.iter().map(RecordSet::to_json).collect::<Vec<_>>(),
            "replacements": replacements.iter().map(RecordSet::to_json).collect::<Vec<_>>(),
            "merges": merges.iter().map(RecordSet::to_json).collect::<Vec<_>>(),
        });
        let _: Value = self
            .http
            .post(url)
            .with_header("authorization", format!("Bearer {}", token))
            .with_body(body)?
            .send_with_retry(3)
            .await?;
        Ok(())
    }

    fn token_lock(&self) -> crate::Result<std::sync::MutexGuard<'_, Option<(String, Instant)>>> {
        self.token
            .lock()
            .map_err(|_| Error::Client("Yandex Cloud token cache poisoned".into()))
    }
}

#[derive(Debug, Clone)]
struct ResolvedZone {
    id: String,
    zone: String,
}

#[derive(Debug)]
#[allow(dead_code)]
struct RecordEntry {
    record_type: &'static str,
    value: String,
}

fn record_to_entry(record: &DnsRecord) -> crate::Result<RecordEntry> {
    let entry = match record {
        DnsRecord::A(ip) => RecordEntry {
            record_type: "A",
            value: ip.to_string(),
        },
        DnsRecord::AAAA(ip) => RecordEntry {
            record_type: "AAAA",
            value: ip.to_string(),
        },
        DnsRecord::CNAME(target) => RecordEntry {
            record_type: "CNAME",
            value: format!("{}.", target.trim_end_matches('.')),
        },
        DnsRecord::NS(target) => RecordEntry {
            record_type: "NS",
            value: format!("{}.", target.trim_end_matches('.')),
        },
        DnsRecord::MX(mx) => RecordEntry {
            record_type: "MX",
            value: format!("{} {}.", mx.priority, mx.exchange.trim_end_matches('.')),
        },
        DnsRecord::TXT(txt) => RecordEntry {
            record_type: "TXT",
            value: encode_txt(txt),
        },
        DnsRecord::SRV(srv) => RecordEntry {
            record_type: "SRV",
            value: format!(
                "{} {} {} {}.",
                srv.priority,
                srv.weight,
                srv.port,
                srv.target.trim_end_matches('.')
            ),
        },
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            RecordEntry {
                record_type: "CAA",
                value: format!("{} {} \"{}\"", flags, tag, value),
            }
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Yandex Cloud".into(),
            ));
        }
    };
    Ok(entry)
}

fn encode_txt(txt: &str) -> String {
    if txt.len() <= MAX_TXT_RDATA_BYTES && !txt.contains('"') && !txt.contains('\\') {
        txt.to_string()
    } else {
        let mut buf = String::new();
        txt_chunks_to_text(&mut buf, txt, " ");
        buf
    }
}

fn txt_equivalent(a: &str, b: &str, record_type: &str) -> bool {
    if a == b {
        return true;
    }
    if record_type != "TXT" {
        return false;
    }
    decode_txt(a) == decode_txt(b)
}

fn decode_txt(text: &str) -> String {
    let trimmed = text.trim();
    if !trimmed.starts_with('"') {
        return trimmed.to_string();
    }
    let mut out = String::new();
    let bytes = trimmed.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push(bytes[i + 1] as char);
                    i += 2;
                } else {
                    out.push(bytes[i] as char);
                    i += 1;
                }
            }
            if i < bytes.len() {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

fn record_type_str(record_type: DnsRecordType) -> crate::Result<&'static str> {
    Ok(match record_type {
        DnsRecordType::A => "A",
        DnsRecordType::AAAA => "AAAA",
        DnsRecordType::CNAME => "CNAME",
        DnsRecordType::NS => "NS",
        DnsRecordType::MX => "MX",
        DnsRecordType::TXT => "TXT",
        DnsRecordType::SRV => "SRV",
        DnsRecordType::CAA => "CAA",
        DnsRecordType::TLSA => {
            return Err(Error::Api(
                "TLSA records are not supported by Yandex Cloud".into(),
            ));
        }
    })
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

fn parse_record_set(value: &Value) -> crate::Result<RecordSet> {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let record_type_owned = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let record_type = static_type_str(&record_type_owned).unwrap_or("");
    let ttl = value
        .get("ttl")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0) as u32;
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(RecordSet {
        name,
        record_type,
        ttl,
        data,
    })
}

fn static_type_str(s: &str) -> Option<&'static str> {
    Some(match s {
        "A" => "A",
        "AAAA" => "AAAA",
        "CNAME" => "CNAME",
        "NS" => "NS",
        "MX" => "MX",
        "TXT" => "TXT",
        "SRV" => "SRV",
        "CAA" => "CAA",
        _ => return None,
    })
}

fn parse_rrdata(record_type: DnsRecordType, text: &str) -> crate::Result<DnsRecord> {
    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(
            text.parse::<Ipv4Addr>()
                .map_err(|e| Error::Parse(format!("Invalid A rrdata '{text}': {e}")))?,
        ),
        DnsRecordType::AAAA => DnsRecord::AAAA(
            text.parse::<Ipv6Addr>()
                .map_err(|e| Error::Parse(format!("Invalid AAAA rrdata '{text}': {e}")))?,
        ),
        DnsRecordType::CNAME => DnsRecord::CNAME(text.trim_end_matches('.').to_string()),
        DnsRecordType::NS => DnsRecord::NS(text.trim_end_matches('.').to_string()),
        DnsRecordType::MX => {
            let (prio, exchange) = text
                .split_once(' ')
                .ok_or_else(|| Error::Parse(format!("Invalid MX rrdata '{text}'")))?;
            let priority = prio
                .parse::<u16>()
                .map_err(|e| Error::Parse(format!("Invalid MX priority '{prio}': {e}")))?;
            DnsRecord::MX(MXRecord {
                priority,
                exchange: exchange.trim().trim_end_matches('.').to_string(),
            })
        }
        DnsRecordType::TXT => DnsRecord::TXT(decode_txt(text)),
        DnsRecordType::SRV => {
            let mut parts = text.split_whitespace();
            let priority = parts
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .ok_or_else(|| Error::Parse(format!("Invalid SRV priority in '{text}'")))?;
            let weight = parts
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .ok_or_else(|| Error::Parse(format!("Invalid SRV weight in '{text}'")))?;
            let port = parts
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .ok_or_else(|| Error::Parse(format!("Invalid SRV port in '{text}'")))?;
            let target = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("Invalid SRV target in '{text}'")))?;
            DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target: target.trim_end_matches('.').to_string(),
            })
        }
        DnsRecordType::CAA => parse_caa_rrdata(text)?,
        DnsRecordType::TLSA => {
            return Err(Error::Api(
                "TLSA records are not supported by Yandex Cloud".into(),
            ));
        }
    })
}

fn parse_caa_rrdata(text: &str) -> crate::Result<DnsRecord> {
    let mut parts = text.splitn(3, ' ');
    let flags = parts
        .next()
        .and_then(|p| p.parse::<u8>().ok())
        .ok_or_else(|| Error::Parse(format!("Invalid CAA flags in '{text}'")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("Invalid CAA tag in '{text}'")))?;
    let value_raw = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("Invalid CAA value in '{text}'")))?;
    let value = value_raw.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(value)
        .to_string();
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
        other => {
            return Err(Error::Parse(format!("unknown CAA tag: {other}")));
        }
    }))
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

fn decode_service_account_key(encoded: &str) -> crate::Result<ServiceAccountKey> {
    let trimmed = encoded.trim();
    let parsed: ServiceAccountKey = if trimmed.starts_with('{') {
        serde_json::from_str(trimmed).map_err(|e| {
            Error::Api(format!(
                "Failed to parse Yandex service account JSON: {}",
                e
            ))
        })?
    } else {
        let decoded = BASE64_STD.decode(trimmed).map_err(|e| {
            Error::Api(format!(
                "Failed to base64-decode Yandex service account key: {}",
                e
            ))
        })?;
        serde_json::from_slice(&decoded).map_err(|e| {
            Error::Api(format!(
                "Failed to parse Yandex service account JSON: {}",
                e
            ))
        })?
    };
    Ok(parsed)
}
