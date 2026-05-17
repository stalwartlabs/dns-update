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

use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn,
    crypto::{hmac_sha256, sha256_digest},
    http::HttpClientBuilder,
    utils::strip_origin_from_name,
};

const DEFAULT_HOST: &str = "dnspod.tencentcloudapi.com";
const SERVICE: &str = "dnspod";
const API_VERSION: &str = "2021-03-23";
const ALGORITHM: &str = "TC3-HMAC-SHA256";
const DEFAULT_RECORD_LINE: &str = "默认";

#[derive(Clone)]
pub struct TencentCloudProvider {
    client: HttpClientBuilder,
    secret_id: String,
    secret_key: String,
    region: String,
    session_token: Option<String>,
    endpoint: String,
    host: String,
}

#[derive(Deserialize, Debug)]
struct ApiResponse<T> {
    #[serde(rename = "Response")]
    response: ApiResponseBody<T>,
}

#[derive(Deserialize, Debug)]
struct ApiResponseBody<T> {
    #[serde(rename = "Error", default)]
    error: Option<ApiError>,
    #[serde(flatten)]
    data: Option<T>,
}

#[derive(Deserialize, Debug, Clone)]
struct ApiError {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}

#[derive(Deserialize, Debug)]
struct DomainListResult {
    #[serde(rename = "DomainList", default)]
    domain_list: Vec<DomainListItem>,
    #[serde(rename = "DomainCountInfo", default)]
    domain_count_info: Option<DomainCountInfo>,
}

#[derive(Deserialize, Debug)]
struct DomainCountInfo {
    #[serde(rename = "AllTotal")]
    all_total: u64,
}

#[derive(Deserialize, Debug, Clone)]
struct DomainListItem {
    #[serde(rename = "DomainId")]
    domain_id: u64,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Punycode", default)]
    punycode: String,
}

#[derive(Deserialize, Debug)]
struct RecordListResult {
    #[serde(rename = "RecordList", default)]
    record_list: Vec<RecordListItem>,
}

#[derive(Deserialize, Debug, Clone)]
struct RecordListItem {
    #[serde(rename = "RecordId")]
    record_id: u64,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Type")]
    record_type: String,
}

impl TencentCloudProvider {
    pub(crate) fn new(
        secret_id: impl AsRef<str>,
        secret_key: impl AsRef<str>,
        region: Option<impl AsRef<str>>,
        session_token: Option<impl AsRef<str>>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let client = HttpClientBuilder::default().with_timeout(timeout);
        Ok(Self {
            client,
            secret_id: secret_id.as_ref().to_string(),
            secret_key: secret_key.as_ref().to_string(),
            region: region.map(|r| r.as_ref().to_string()).unwrap_or_default(),
            session_token: session_token.map(|s| s.as_ref().to_string()),
            endpoint: format!("https://{}", DEFAULT_HOST),
            host: DEFAULT_HOST.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        let url = endpoint.as_ref().to_string();
        let host = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .map(|s| s.split('/').next().unwrap_or(s).to_string())
            .unwrap_or_else(|| DEFAULT_HOST.to_string());
        Self {
            endpoint: url,
            host,
            ..self
        }
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let origin = origin.into_name();
        let zone = self.find_zone(&origin).await?;
        let subdomain = strip_origin_from_name(&name, &zone.name, Some("@"));
        let record_repr = TencentRecord::try_from(record)?;

        let payload = json!({
            "Domain": zone.name,
            "DomainId": zone.domain_id,
            "SubDomain": subdomain,
            "RecordType": record_repr.record_type,
            "RecordLine": DEFAULT_RECORD_LINE,
            "Value": record_repr.value,
            "TTL": ttl,
            "MX": record_repr.priority,
        });

        let body = serialize_payload(&payload)?;
        let _ = self
            .send::<Value>("CreateRecord", &body)
            .await?;
        Ok(())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let origin = origin.into_name();
        let zone = self.find_zone(&origin).await?;
        let subdomain = strip_origin_from_name(&name, &zone.name, Some("@"));
        let record_repr = TencentRecord::try_from(record)?;
        let record_id = self
            .find_record_id(&zone, &subdomain, &record_repr.record_type)
            .await?;

        let payload = json!({
            "Domain": zone.name,
            "DomainId": zone.domain_id,
            "RecordId": record_id,
            "SubDomain": subdomain,
            "RecordType": record_repr.record_type,
            "RecordLine": DEFAULT_RECORD_LINE,
            "Value": record_repr.value,
            "TTL": ttl,
            "MX": record_repr.priority,
        });

        let body = serialize_payload(&payload)?;
        let _ = self
            .send::<Value>("ModifyRecord", &body)
            .await?;
        Ok(())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let origin = origin.into_name();
        let zone = self.find_zone(&origin).await?;
        let subdomain = strip_origin_from_name(&name, &zone.name, Some("@"));
        let type_str = record_type.as_str();
        let record_id = self.find_record_id(&zone, &subdomain, type_str).await?;

        let payload = json!({
            "Domain": zone.name,
            "DomainId": zone.domain_id,
            "RecordId": record_id,
        });

        let body = serialize_payload(&payload)?;
        let _ = self
            .send::<Value>("DeleteRecord", &body)
            .await?;
        Ok(())
    }

    async fn find_zone(&self, origin: &str) -> crate::Result<DomainListItem> {
        let zone_name = origin.trim_end_matches('.').to_string();
        let mut offset: u64 = 0;
        let mut collected: Vec<DomainListItem> = Vec::new();
        loop {
            let payload = json!({
                "Offset": offset,
                "Limit": 100,
            });
            let body = serialize_payload(&payload)?;
            let resp = self
                .send::<DomainListResult>("DescribeDomainList", &body)
                .await?;
            collected.extend(resp.domain_list.iter().cloned());
            let total = resp
                .domain_count_info
                .as_ref()
                .map(|c| c.all_total)
                .unwrap_or(0);
            if (collected.len() as u64) >= total || resp.domain_list.is_empty() {
                break;
            }
            offset = collected.len() as u64;
        }

        collected
            .into_iter()
            .find(|d| d.name == zone_name || d.punycode == zone_name)
            .ok_or_else(|| {
                Error::Api(format!(
                    "TencentCloud DNSPod zone not found for {}",
                    zone_name
                ))
            })
    }

    async fn find_record_id(
        &self,
        zone: &DomainListItem,
        subdomain: &str,
        record_type: &str,
    ) -> crate::Result<u64> {
        let payload = json!({
            "Domain": zone.name,
            "DomainId": zone.domain_id,
            "Subdomain": subdomain,
            "RecordType": record_type,
            "RecordLine": DEFAULT_RECORD_LINE,
        });
        let body = serialize_payload(&payload)?;
        let resp = self
            .send::<RecordListResult>("DescribeRecordList", &body)
            .await?;
        resp.record_list
            .into_iter()
            .find(|r| r.name == subdomain && r.record_type == record_type)
            .map(|r| r.record_id)
            .ok_or_else(|| {
                Error::Api(format!(
                    "DNS Record {} of type {} not found",
                    subdomain, record_type
                ))
            })
    }

    async fn send<T>(&self, action: &str, body: &str) -> crate::Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let now = Utc::now();
        let timestamp = now.timestamp().to_string();
        let date_stamp = now.format("%Y-%m-%d").to_string();

        let content_type = "application/json; charset=utf-8";
        let action_header = action.to_ascii_lowercase();
        let payload_hash = hex::encode(sha256_digest(body.as_bytes()));

        let canonical_headers = format!(
            "content-type:{}\nhost:{}\nx-tc-action:{}\n",
            content_type, self.host, action_header
        );
        let signed_headers = "content-type;host;x-tc-action";

        let canonical_request = format!(
            "POST\n/\n\n{}\n{}\n{}",
            canonical_headers, signed_headers, payload_hash
        );
        let canonical_request_hash = hex::encode(sha256_digest(canonical_request.as_bytes()));

        let credential_scope = format!("{}/{}/tc3_request", date_stamp, SERVICE);
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            ALGORITHM, timestamp, credential_scope, canonical_request_hash
        );

        let secret_date = hmac_sha256(
            format!("TC3{}", self.secret_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let secret_service = hmac_sha256(&secret_date, SERVICE.as_bytes());
        let secret_signing = hmac_sha256(&secret_service, b"tc3_request");
        let signature = hex::encode(hmac_sha256(&secret_signing, string_to_sign.as_bytes()));

        let authorization = format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            ALGORITHM, self.secret_id, credential_scope, signed_headers, signature
        );

        let mut request = self
            .client
            .post(self.endpoint.clone())
            .with_header("Authorization", authorization)
            .with_header("Content-Type", content_type)
            .with_header("Host", self.host.clone())
            .with_header("X-TC-Action", action)
            .with_header("X-TC-Timestamp", timestamp)
            .with_header("X-TC-Version", API_VERSION);

        if !self.region.is_empty() {
            request = request.with_header("X-TC-Region", self.region.clone());
        }
        if let Some(token) = &self.session_token {
            request = request.with_header("X-TC-Token", token.clone());
        }

        let raw = request.with_raw_body(body.to_string()).send_raw().await?;
        let response: ApiResponse<T> = serde_json::from_str(&raw).map_err(|err| {
            Error::Serialize(format!("Failed to deserialize TencentCloud response: {err}"))
        })?;
        if let Some(err) = response.response.error {
            return Err(Error::Api(format!(
                "TencentCloud DNSPod error {}: {}",
                err.code, err.message
            )));
        }
        let data: T = serde_json::from_str(&raw)
            .map(|wrapper: ApiResponse<T>| wrapper.response.data)
            .map_err(|err| {
                Error::Serialize(format!(
                    "Failed to deserialize TencentCloud payload: {err}"
                ))
            })?
            .ok_or_else(|| Error::Api("TencentCloud response missing payload".to_string()))?;
        Ok(data)
    }
}

fn serialize_payload(value: &Value) -> crate::Result<String> {
    let stripped = strip_nulls(value);
    serde_json::to_string(&stripped)
        .map_err(|err| Error::Serialize(format!("Failed to serialize payload: {err}")))
}

fn strip_nulls(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                if !v.is_null() {
                    new_map.insert(k.clone(), strip_nulls(v));
                }
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(strip_nulls).collect()),
        other => other.clone(),
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct TencentRecord {
    pub record_type: String,
    pub value: String,
    pub priority: Option<u16>,
}

impl TryFrom<DnsRecord> for TencentRecord {
    type Error = Error;

    fn try_from(record: DnsRecord) -> Result<Self, Self::Error> {
        match record {
            DnsRecord::A(addr) => Ok(TencentRecord {
                record_type: "A".to_string(),
                value: addr.to_string(),
                priority: None,
            }),
            DnsRecord::AAAA(addr) => Ok(TencentRecord {
                record_type: "AAAA".to_string(),
                value: addr.to_string(),
                priority: None,
            }),
            DnsRecord::CNAME(target) => Ok(TencentRecord {
                record_type: "CNAME".to_string(),
                value: ensure_trailing_dot(target),
                priority: None,
            }),
            DnsRecord::NS(target) => Ok(TencentRecord {
                record_type: "NS".to_string(),
                value: ensure_trailing_dot(target),
                priority: None,
            }),
            DnsRecord::MX(mx) => Ok(TencentRecord {
                record_type: "MX".to_string(),
                value: ensure_trailing_dot(mx.exchange),
                priority: Some(mx.priority),
            }),
            DnsRecord::TXT(text) => Ok(TencentRecord {
                record_type: "TXT".to_string(),
                value: text,
                priority: None,
            }),
            DnsRecord::SRV(srv) => Ok(TencentRecord {
                record_type: "SRV".to_string(),
                value: format!(
                    "{} {} {} {}",
                    srv.priority,
                    srv.weight,
                    srv.port,
                    ensure_trailing_dot(srv.target)
                ),
                priority: None,
            }),
            DnsRecord::CAA(caa) => Ok(TencentRecord {
                record_type: "CAA".to_string(),
                value: caa.to_string(),
                priority: None,
            }),
            DnsRecord::TLSA(_) => Err(Error::Api(
                "TLSA records are not supported by TencentCloud DNSPod".to_string(),
            )),
        }
    }
}

fn ensure_trailing_dot(value: String) -> String {
    if value.ends_with('.') {
        value
    } else {
        format!("{}.", value)
    }
}
