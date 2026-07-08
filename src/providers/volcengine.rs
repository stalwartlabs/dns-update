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
use crate::http::{HttpClient, HttpClientBuilder};
use crate::utils::split_caa_value;
use crate::utils::unquote_txt;
use crate::utils::{strip_origin_from_name, txt_chunks_to_text};
use crate::{CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord};
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;

const VOLCENGINE_DEFAULT_HOST: &str = "open.volcengineapi.com";
const VOLCENGINE_DEFAULT_REGION: &str = "cn-north-1";
const VOLCENGINE_SERVICE: &str = "dns";
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
    access_key: String,
    secret_key: String,
    region: String,
    host: String,
    scheme: String,
    client: HttpClient,
}

#[derive(Debug, Clone, Deserialize)]
struct ListedRecord {
    #[serde(rename = "RecordID")]
    record_id: String,
    #[serde(rename = "Host")]
    host: String,
    #[serde(rename = "Type")]
    record_type: String,
    #[serde(rename = "Value", default)]
    value: String,
}

#[derive(Debug, Clone)]
struct ResolvedZone {
    id: i64,
    name: String,
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
            .unwrap_or_else(|| VOLCENGINE_DEFAULT_REGION.to_string());
        let host = config
            .host
            .unwrap_or_else(|| VOLCENGINE_DEFAULT_HOST.to_string());
        let scheme = config.scheme.unwrap_or_else(|| "https".to_string());

        let client = HttpClientBuilder::default()
            .with_timeout(config.request_timeout)
            .build();
        Ok(Self {
            access_key: config.access_key,
            secret_key: config.secret_key,
            region,
            host,
            scheme,
            client,
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

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let type_str = record_type_str(record_type)?;
        let desired = build_values(record_type, records)?;
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone = self.get_zone(&origin).await?;
        let host = strip_origin_from_name(&name, &zone.name, None);
        let existing = self.list_records(zone.id, &host, type_str).await?;

        let mut pool = existing;
        let mut to_add: Vec<String> = Vec::new();
        for value in desired {
            if let Some(idx) = pool.iter().position(|r| r.value == value) {
                pool.swap_remove(idx);
            } else if !to_add.contains(&value) {
                to_add.push(value);
            }
        }

        for stale in pool {
            self.delete_record(&stale.record_id).await?;
        }
        for value in to_add {
            self.create_record(zone.id, &host, type_str, &value, ttl)
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
        let type_str = record_type_str(record_type)?;
        let desired = build_values(record_type, records)?;
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone = self.get_zone(&origin).await?;
        let host = strip_origin_from_name(&name, &zone.name, None);
        let existing = self.list_records(zone.id, &host, type_str).await?;

        let mut queued: Vec<String> = Vec::new();
        for value in desired {
            if existing.iter().any(|r| r.value == value) {
                continue;
            }
            if queued.contains(&value) {
                continue;
            }
            self.create_record(zone.id, &host, type_str, &value, ttl)
                .await?;
            queued.push(value);
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
        let type_str = record_type_str(record_type)?;
        let to_remove = build_values(record_type, records)?;
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone = self.get_zone(&origin).await?;
        let host = strip_origin_from_name(&name, &zone.name, None);
        let existing = self.list_records(zone.id, &host, type_str).await?;

        for value in to_remove {
            if let Some(entry) = existing.iter().find(|r| r.value == value) {
                self.delete_record(&entry.record_id).await?;
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
        let type_str = record_type_str(record_type)?;
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone = self.get_zone(&origin).await?;
        let host = strip_origin_from_name(&name, &zone.name, None);
        let existing = self.list_records(zone.id, &host, type_str).await?;
        existing
            .into_iter()
            .map(|r| value_to_record(record_type, &r.value))
            .collect()
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
        let zones = result
            .get("Zones")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Api("Volcengine ListZones response missing Zones".into()))?;
        let matched = zones
            .iter()
            .find(|z| {
                z.get("ZoneName")
                    .and_then(Value::as_str)
                    .map(|n| n.trim_end_matches('.') == trimmed)
                    .unwrap_or(false)
            })
            .ok_or_else(|| Error::Api(format!("No Volcengine zone found for origin {}", origin)))?;
        let id = matched
            .get("ZID")
            .and_then(Value::as_i64)
            .ok_or_else(|| Error::Api("Volcengine zone missing ZID".into()))?;
        let name = matched
            .get("ZoneName")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Api("Volcengine zone missing ZoneName".into()))?
            .trim_end_matches('.')
            .to_string();
        Ok(ResolvedZone { id, name })
    }

    async fn list_records(
        &self,
        zone_id: i64,
        host: &str,
        record_type: &str,
    ) -> crate::Result<Vec<ListedRecord>> {
        let body = serde_json::json!({
            "ZID": zone_id,
            "Host": host,
            "Type": record_type,
            "SearchMode": "exact",
            "PageSize": "100",
        });
        let response = self.send_action("ListRecords", body).await?;
        let records = response
            .get("Result")
            .and_then(|r| r.get("Records"))
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        let parsed: Vec<ListedRecord> = serde_json::from_value(records).map_err(|e| {
            Error::Serialize(format!("Failed to parse Volcengine record list: {}", e))
        })?;
        Ok(parsed
            .into_iter()
            .filter(|r| r.host == host && r.record_type == record_type)
            .collect())
    }

    async fn create_record(
        &self,
        zone_id: i64,
        host: &str,
        record_type: &str,
        value: &str,
        ttl: u32,
    ) -> crate::Result<()> {
        let body = serde_json::json!({
            "ZID": zone_id,
            "Host": host,
            "Type": record_type,
            "Value": value,
            "TTL": ttl,
        });
        self.send_action("CreateRecord", body).await.map(|_| ())
    }

    async fn delete_record(&self, record_id: &str) -> crate::Result<()> {
        let body = serde_json::json!({ "RecordID": record_id });
        self.send_action("DeleteRecord", body).await.map(|_| ())
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
            VOLCENGINE_SIGN_ALGORITHM, self.access_key, credential_scope, signed_headers, signature
        );

        let url = format!("{}://{}/?{}", self.scheme, self.host, query);
        let text = self
            .client
            .post(url)
            .with_header("Host", &self.host)
            .with_header("X-Date", &amz_date)
            .with_header("X-Content-Sha256", &payload_hash)
            .with_header("Authorization", &authorization)
            .with_raw_body(body_text)
            .send_raw()
            .await?;

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
        let k_date = hmac_sha256(self.secret_key.as_bytes(), date_stamp.as_bytes());
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, VOLCENGINE_SERVICE.as_bytes());
        hmac_sha256(&k_service, b"request")
    }
}

fn record_to_value(record: &DnsRecord) -> crate::Result<(&'static str, String)> {
    Ok(match record {
        DnsRecord::A(ip) => ("A", ip.to_string()),
        DnsRecord::AAAA(ip) => ("AAAA", ip.to_string()),
        DnsRecord::CNAME(target) => ("CNAME", target.trim_end_matches('.').to_string()),
        DnsRecord::NS(target) => ("NS", target.trim_end_matches('.').to_string()),
        DnsRecord::MX(mx) => (
            "MX",
            format!("{} {}", mx.priority, mx.exchange.trim_end_matches('.')),
        ),
        DnsRecord::TXT(txt) => {
            let mut buf = String::new();
            txt_chunks_to_text(&mut buf, txt, " ");
            ("TXT", buf)
        }
        DnsRecord::SRV(srv) => (
            "SRV",
            format!(
                "{} {} {} {}",
                srv.priority,
                srv.weight,
                srv.port,
                srv.target.trim_end_matches('.')
            ),
        ),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            ("CAA", format!("{} {} \"{}\"", flags, tag, value))
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Unsupported(
                "TLSA records are not supported by Volcengine".into(),
            ));
        }
    })
}

fn build_values(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<String>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        let (_, value) = record_to_value(&record)?;
        out.push(value);
    }
    Ok(out)
}

fn value_to_record(record_type: DnsRecordType, value: &str) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => value
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("Invalid A value {}: {}", value, e))),
        DnsRecordType::AAAA => value
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("Invalid AAAA value {}: {}", value, e))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(value.to_string())),
        DnsRecordType::NS => Ok(DnsRecord::NS(value.to_string())),
        DnsRecordType::MX => {
            let (priority, exchange) = value
                .split_once(' ')
                .ok_or_else(|| Error::Parse(format!("Invalid MX value (no space): {}", value)))?;
            let priority: u16 = priority
                .parse()
                .map_err(|e| Error::Parse(format!("Invalid MX priority {}: {}", priority, e)))?;
            Ok(DnsRecord::MX(MXRecord {
                priority,
                exchange: exchange.to_string(),
            }))
        }
        DnsRecordType::TXT => Ok(DnsRecord::TXT(unquote_txt(value))),
        DnsRecordType::SRV => {
            let parts: Vec<&str> = value.splitn(4, ' ').collect();
            if parts.len() != 4 {
                return Err(Error::Parse(format!("Invalid SRV value: {}", value)));
            }
            Ok(DnsRecord::SRV(SRVRecord {
                priority: parts[0]
                    .parse()
                    .map_err(|e| Error::Parse(format!("Invalid SRV priority: {}", e)))?,
                weight: parts[1]
                    .parse()
                    .map_err(|e| Error::Parse(format!("Invalid SRV weight: {}", e)))?,
                port: parts[2]
                    .parse()
                    .map_err(|e| Error::Parse(format!("Invalid SRV port: {}", e)))?,
                target: parts[3].to_string(),
            }))
        }
        DnsRecordType::CAA => parse_caa_value(value).map(DnsRecord::CAA),
        DnsRecordType::TLSA => Err(Error::Unsupported(
            "TLSA records are not supported by Volcengine".into(),
        )),
    }
}

fn parse_caa_value(value: &str) -> crate::Result<CAARecord> {
    let trimmed = value.trim();
    let (flags_str, rest) = trimmed
        .split_once(' ')
        .ok_or_else(|| Error::Parse(format!("Invalid CAA value: {}", value)))?;
    let flags: u8 = flags_str
        .parse()
        .map_err(|e| Error::Parse(format!("Invalid CAA flags {}: {}", flags_str, e)))?;
    let issuer_critical = flags & 0x80 != 0;
    let (tag, raw_value) = rest
        .trim_start()
        .split_once(' ')
        .ok_or_else(|| Error::Parse(format!("Invalid CAA tag/value: {}", value)))?;
    let raw_value = raw_value.trim();
    let stripped = raw_value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(raw_value);
    match tag {
        "issue" => {
            let (name, options) = split_caa_value(stripped);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = split_caa_value(stripped);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: stripped.to_string(),
        }),
        other => Err(Error::Parse(format!("Unknown CAA tag: {}", other))),
    }
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
            return Err(Error::Unsupported(
                "TLSA records are not supported by Volcengine".into(),
            ));
        }
    })
}

fn canonical_query_string(query: &str) -> String {
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|p| {
            let mut iter = p.splitn(2, '=');
            let k = iter.next().unwrap_or("");
            let v = iter.next().unwrap_or("");
            (volc_uri_encode(k, true), volc_uri_encode(v, true))
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
