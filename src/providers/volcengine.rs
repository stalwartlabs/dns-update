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

use crate::crypto::{hmac_sha256, sha256_digest};
use crate::utils::txt_chunks_to_text;
use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn};
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

const VOLCENGINE_DEFAULT_HOST: &str = "open.volcengineapi.com";
const VOLCENGINE_DEFAULT_REGION: &str = "cn-north-1";
const VOLCENGINE_SERVICE: &str = "DNS";
const VOLCENGINE_API_VERSION: &str = "2018-08-01";
const VOLCENGINE_SIGN_ALGORITHM: &str = "HMAC-SHA256";

#[derive(Debug, Clone)]
pub struct VolcengineConfig {
    pub access_key: String,
    pub secret_key: String,
    pub region: Option<String>,
    pub host: Option<String>,
    pub scheme: Option<String>,
    pub request_timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct VolcengineProvider {
    client: Client,
    config: VolcengineConfig,
    region: String,
    host: String,
    scheme: String,
}

impl VolcengineProvider {
    pub(crate) fn new(config: VolcengineConfig) -> crate::Result<Self> {
        if config.access_key.is_empty() || config.secret_key.is_empty() {
            return Err(Error::Api(
                "Volcengine credentials are required (access_key and secret_key)".into(),
            ));
        }

        let region = config
            .region
            .clone()
            .unwrap_or_else(|| VOLCENGINE_DEFAULT_REGION.to_string());
        let host = config
            .host
            .clone()
            .unwrap_or_else(|| VOLCENGINE_DEFAULT_HOST.to_string());
        let scheme = config.scheme.clone().unwrap_or_else(|| "https".to_string());

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
            region,
            host,
            scheme,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        let endpoint = endpoint.as_ref();
        if let Some(rest) = endpoint.strip_prefix("https://") {
            self.scheme = "https".to_string();
            self.host = rest.trim_end_matches('/').to_string();
        } else if let Some(rest) = endpoint.strip_prefix("http://") {
            self.scheme = "http".to_string();
            self.host = rest.trim_end_matches('/').to_string();
        } else {
            self.host = endpoint.trim_end_matches('/').to_string();
        }
        self
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
        let zone = self.get_zone(&origin).await?;
        let host = subdomain_for(&name, &zone.name);
        let entry = record_to_entry(&record)?;

        let body = serde_json::json!({
            "ZID": zone.id,
            "Host": host,
            "Type": entry.record_type,
            "Value": entry.value,
            "TTL": ttl,
        });

        let final_body = if let Some(priority) = entry.priority {
            let mut value = body;
            value["Weight"] = priority.into();
            value
        } else {
            body
        };

        self.send_action("CreateRecord", final_body).await.map(|_| ())
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
        let zone = self.get_zone(&origin).await?;
        let host = subdomain_for(&name, &zone.name);
        let entry = record_to_entry(&record)?;
        let record_id = self
            .find_record_id(&zone.id, &host, &entry.record_type)
            .await?;

        let body = serde_json::json!({
            "RecordID": record_id,
            "Host": host,
            "Type": entry.record_type,
            "Value": entry.value,
            "TTL": ttl,
        });

        let final_body = if let Some(priority) = entry.priority {
            let mut value = body;
            value["Weight"] = priority.into();
            value
        } else {
            body
        };

        self.send_action("UpdateRecord", final_body).await.map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone = self.get_zone(&origin).await?;
        let host = subdomain_for(&name, &zone.name);
        let type_str = record_type_str(record_type)?;
        let record_id = self.find_record_id(&zone.id, &host, type_str).await?;

        let body = serde_json::json!({ "RecordID": record_id });
        self.send_action("DeleteRecord", body).await.map(|_| ())
    }

    async fn get_zone(&self, origin: &str) -> crate::Result<ResolvedZone> {
        let trimmed = origin.trim_end_matches('.').to_string();
        let body = serde_json::json!({
            "Key": trimmed,
            "SearchMode": "exact",
        });
        let response = self.send_action("ListZones", body).await?;
        let result = response
            .get("Result")
            .ok_or_else(|| Error::Api("Volcengine ListZones response missing Result".into()))?;
        let total = result
            .get("Total")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if total == 0 {
            return Err(Error::Api(format!(
                "No Volcengine zone found for origin {}",
                origin
            )));
        }
        if total > 1 {
            return Err(Error::Api(format!(
                "Multiple Volcengine zones matched origin {}",
                origin
            )));
        }
        let zones = result
            .get("Zones")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Api("Volcengine ListZones response missing Zones".into()))?;
        let zone = zones.first().ok_or_else(|| {
            Error::Api(format!("Volcengine zone list empty for origin {}", origin))
        })?;
        let id = zone
            .get("ZID")
            .and_then(Value::as_i64)
            .ok_or_else(|| Error::Api("Volcengine zone missing ZID".into()))?;
        let name = zone
            .get("ZoneName")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Api("Volcengine zone missing ZoneName".into()))?
            .trim_end_matches('.')
            .to_string();
        Ok(ResolvedZone { id, name })
    }

    async fn find_record_id(
        &self,
        zone_id: &i64,
        host: &str,
        record_type: &str,
    ) -> crate::Result<String> {
        let body = serde_json::json!({
            "ZID": zone_id,
            "Host": host,
            "Type": record_type,
            "PageSize": 100,
        });
        let response = self.send_action("ListRecords", body).await?;
        let result = response
            .get("Result")
            .ok_or_else(|| Error::Api("Volcengine ListRecords response missing Result".into()))?;
        let records = result
            .get("Records")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Api("Volcengine ListRecords response missing Records".into()))?;
        let record = records
            .iter()
            .find(|r| {
                let h = r.get("Host").and_then(Value::as_str).unwrap_or("");
                let t = r.get("Type").and_then(Value::as_str).unwrap_or("");
                h == host && t == record_type
            })
            .ok_or_else(|| {
                Error::Api(format!(
                    "Volcengine record {} of type {} not found",
                    host, record_type
                ))
            })?;
        record
            .get("RecordID")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .ok_or_else(|| Error::Api("Volcengine record missing RecordID".into()))
    }

    async fn send_action(&self, action: &str, body: Value) -> crate::Result<Value> {
        let body_text = serde_json::to_string(&body)
            .map_err(|e| Error::Serialize(format!("Failed to serialize request: {}", e)))?;
        let query = format!("Action={}&Version={}", action, VOLCENGINE_API_VERSION);
        let canonical_query = canonical_query_string(&query);

        let datetime = Utc::now();
        let amz_date = datetime.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = datetime.format("%Y%m%d").to_string();
        let payload_hash = hex::encode(sha256_digest(body_text.as_bytes()));

        let canonical_headers = format!(
            "content-type:application/json\nhost:{}\nx-content-sha256:{}\nx-date:{}\n",
            self.host, payload_hash, amz_date
        );
        let signed_headers = "content-type;host;x-content-sha256;x-date";

        let canonical_request = format!(
            "POST\n/\n{}\n{}\n{}\n{}",
            canonical_query, canonical_headers, signed_headers, payload_hash
        );

        let credential_scope = format!(
            "{}/{}/{}/request",
            date_stamp, self.region, VOLCENGINE_SERVICE
        );
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            VOLCENGINE_SIGN_ALGORITHM,
            amz_date,
            credential_scope,
            hex::encode(sha256_digest(canonical_request.as_bytes()))
        );

        let signing_key = self.derive_signing_key(&date_stamp);
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let authorization = format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            VOLCENGINE_SIGN_ALGORITHM,
            self.config.access_key,
            credential_scope,
            signed_headers,
            signature
        );

        let url = format!("{}://{}/?{}", self.scheme, self.host, query);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Host", &self.host)
            .header("X-Date", &amz_date)
            .header("X-Content-Sha256", &payload_hash)
            .header("Authorization", &authorization)
            .body(body_text)
            .send()
            .await
            .map_err(|e| Error::Api(format!("Volcengine request failed: {}", e)))?;

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| Error::Api(format!("Failed to read Volcengine response: {}", e)))?;

        if !status.is_success() {
            return Err(match status.as_u16() {
                400 => Error::Api(format!("BadRequest {}", text)),
                401 | 403 => Error::Unauthorized,
                404 => Error::NotFound,
                _ => Error::Api(format!("Volcengine API error {}: {}", status, text)),
            });
        }

        let parsed: Value = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text)
                .map_err(|e| Error::Api(format!("Failed to parse Volcengine response: {}", e)))?
        };

        if let Some(error) = parsed.get("ResponseMetadata").and_then(|m| m.get("Error")) {
            let code = error
                .get("CodeN")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            let message = error
                .get("Message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(Error::Api(format!(
                "Volcengine API error {}: {}",
                code, message
            )));
        }

        Ok(parsed)
    }

    fn derive_signing_key(&self, date_stamp: &str) -> Vec<u8> {
        let k_date = hmac_sha256(self.config.secret_key.as_bytes(), date_stamp.as_bytes());
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, VOLCENGINE_SERVICE.as_bytes());
        hmac_sha256(&k_service, b"request")
    }
}

#[derive(Debug, Clone)]
struct ResolvedZone {
    id: i64,
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RecordEntry {
    record_type: String,
    value: String,
    priority: Option<u16>,
}

fn record_to_entry(record: &DnsRecord) -> crate::Result<RecordEntry> {
    let entry = match record {
        DnsRecord::A(ip) => RecordEntry {
            record_type: "A".into(),
            value: ip.to_string(),
            priority: None,
        },
        DnsRecord::AAAA(ip) => RecordEntry {
            record_type: "AAAA".into(),
            value: ip.to_string(),
            priority: None,
        },
        DnsRecord::CNAME(target) => RecordEntry {
            record_type: "CNAME".into(),
            value: target.trim_end_matches('.').to_string(),
            priority: None,
        },
        DnsRecord::NS(target) => RecordEntry {
            record_type: "NS".into(),
            value: target.trim_end_matches('.').to_string(),
            priority: None,
        },
        DnsRecord::MX(mx) => RecordEntry {
            record_type: "MX".into(),
            value: mx.exchange.trim_end_matches('.').to_string(),
            priority: Some(mx.priority),
        },
        DnsRecord::TXT(txt) => {
            let mut buf = String::new();
            txt_chunks_to_text(&mut buf, txt, " ");
            RecordEntry {
                record_type: "TXT".into(),
                value: buf,
                priority: None,
            }
        }
        DnsRecord::SRV(srv) => RecordEntry {
            record_type: "SRV".into(),
            value: format!(
                "{} {} {} {}",
                srv.priority,
                srv.weight,
                srv.port,
                srv.target.trim_end_matches('.')
            ),
            priority: None,
        },
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            RecordEntry {
                record_type: "CAA".into(),
                value: format!("{} {} \"{}\"", flags, tag, value),
                priority: None,
            }
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Volcengine".into(),
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
                "TLSA records are not supported by Volcengine".into(),
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

fn canonical_query_string(query: &str) -> String {
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|p| {
            let mut iter = p.splitn(2, '=');
            let k = iter.next().unwrap_or("");
            let v = iter.next().unwrap_or("");
            (
                volc_uri_encode(k, true),
                volc_uri_encode(v, true),
            )
        })
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

fn volc_uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        let ch = b as char;
        let unreserved = ch.is_ascii_alphanumeric()
            || ch == '-'
            || ch == '_'
            || ch == '.'
            || ch == '~'
            || (!encode_slash && ch == '/');
        if unreserved {
            out.push(ch);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}
