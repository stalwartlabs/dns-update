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

use crate::jwt::{JwtSignAlgorithm, sign_jwt};
use crate::utils::txt_chunks_to_text;
use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct YandexCloudConfig {
    pub iam_token_b64: String,
    pub folder_id: String,
    pub request_timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct YandexCloudProvider {
    client: Client,
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
        let client = builder
            .build()
            .map_err(|e| Error::Client(format!("Failed to build reqwest client: {}", e)))?;

        Ok(Self {
            client,
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
            .client
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

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone = self.resolve_zone(&origin).await?;
        let subdomain = subdomain_for(&name, &zone.zone);
        let entry = record_to_entry(&record)?;
        let token = self.ensure_token().await?;

        let existing = self
            .get_record_set(&token, &zone.id, &subdomain, entry.record_type)
            .await?;
        let mut data = existing
            .as_ref()
            .and_then(|rs| {
                rs.get("data")
                    .and_then(Value::as_array)
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
            })
            .unwrap_or_default();
        if !data.contains(&entry.value) {
            data.push(entry.value.clone());
        }
        let new_record = serde_json::json!({
            "name": subdomain,
            "type": entry.record_type,
            "ttl": ttl,
            "data": data,
        });
        let mut body = serde_json::json!({});
        if let Some(existing_rs) = existing {
            body["deletions"] = Value::Array(vec![existing_rs]);
        }
        body["additions"] = Value::Array(vec![new_record]);
        self.update_record_sets(&token, &zone.id, body).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone = self.resolve_zone(&origin).await?;
        let subdomain = subdomain_for(&name, &zone.zone);
        let entry = record_to_entry(&record)?;
        let token = self.ensure_token().await?;

        let existing = self
            .get_record_set(&token, &zone.id, &subdomain, entry.record_type)
            .await?;
        let new_record = serde_json::json!({
            "name": subdomain,
            "type": entry.record_type,
            "ttl": ttl,
            "data": [entry.value],
        });
        let mut body = serde_json::json!({});
        if let Some(existing_rs) = existing {
            body["deletions"] = Value::Array(vec![existing_rs]);
        }
        body["additions"] = Value::Array(vec![new_record]);
        self.update_record_sets(&token, &zone.id, body).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone = self.resolve_zone(&origin).await?;
        let subdomain = subdomain_for(&name, &zone.zone);
        let type_str = record_type_str(record_type)?;
        let token = self.ensure_token().await?;
        let Some(existing) = self
            .get_record_set(&token, &zone.id, &subdomain, type_str)
            .await?
        else {
            return Ok(());
        };

        let body = serde_json::json!({ "deletions": [existing] });
        self.update_record_sets(&token, &zone.id, body).await
    }

    async fn resolve_zone(&self, origin: &str) -> crate::Result<ResolvedZone> {
        let token = self.ensure_token().await?;
        let url = format!(
            "{}/dns/v1/zones?folderId={}",
            self.endpoints.dns_base_url, self.config.folder_id
        );
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| Error::Api(format!("Yandex Cloud list zones failed: {}", e)))?;
        let value: Value = self.parse_response(resp, "list zones").await?;
        let zones = value
            .get("dnsZones")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let target = format!("{}.", origin.trim_end_matches('.'));
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
        Err(Error::Api(format!(
            "No Yandex Cloud DNS zone matches origin {}",
            origin
        )))
    }

    async fn get_record_set(
        &self,
        token: &str,
        zone_id: &str,
        name: &str,
        record_type: &str,
    ) -> crate::Result<Option<Value>> {
        let query = serde_urlencoded::to_string([("name", name), ("type", record_type)])
            .map_err(|e| Error::Api(format!("Failed to encode query: {}", e)))?;
        let url = format!(
            "{}/dns/v1/zones/{}:getRecordSet?{}",
            self.endpoints.dns_base_url, zone_id, query
        );
        let resp = self
            .client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| Error::Api(format!("Yandex Cloud get record set failed: {}", e)))?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        let value: Value = self.parse_response(resp, "get record set").await?;
        Ok(Some(value))
    }

    async fn update_record_sets(
        &self,
        token: &str,
        zone_id: &str,
        body: Value,
    ) -> crate::Result<()> {
        let url = format!(
            "{}/dns/v1/zones/{}:updateRecordSets",
            self.endpoints.dns_base_url, zone_id
        );
        let resp = self
            .client
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Api(format!("Yandex Cloud update record sets failed: {}", e)))?;
        let _: Value = self.parse_response(resp, "update record sets").await?;
        Ok(())
    }

    async fn parse_response<T>(&self, response: reqwest::Response, context: &str) -> crate::Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| Error::Api(format!("Failed to read response ({}): {}", context, e)))?;
        if !status.is_success() {
            return Err(match status.as_u16() {
                400 => Error::Api(format!("BadRequest {}", text)),
                401 | 403 => Error::Unauthorized,
                404 => Error::NotFound,
                _ => Error::Api(format!(
                    "Yandex Cloud API error {} ({}): {}",
                    status, context, text
                )),
            });
        }
        if text.is_empty() {
            return serde_json::from_str("{}")
                .map_err(|e| Error::Serialize(format!("Failed to parse empty response: {}", e)));
        }
        serde_json::from_str(&text)
            .map_err(|e| Error::Serialize(format!("Failed to parse {} response: {}", context, e)))
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

#[derive(Debug, Serialize, Deserialize)]
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
            value: format!(
                "{} {}.",
                mx.priority,
                mx.exchange.trim_end_matches('.')
            ),
        },
        DnsRecord::TXT(txt) => {
            let mut buf = String::new();
            txt_chunks_to_text(&mut buf, txt, " ");
            RecordEntry {
                record_type: "TXT",
                value: buf,
            }
        }
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

fn subdomain_for(name: &str, zone_name: &str) -> String {
    let name = name.trim_end_matches('.');
    let zone = zone_name.trim_end_matches('.');
    if name == zone {
        "@".to_string()
    } else if let Some(stripped) = name.strip_suffix(&format!(".{}", zone)) {
        stripped.to_string()
    } else {
        name.to_string()
    }
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
