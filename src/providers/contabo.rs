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

use crate::utils::{build_caa, strip_origin_from_name, unquote_txt};
use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord,
    http::{HttpClient, HttpClientBuilder},
};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    hash::{BuildHasher, Hasher, RandomState},
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const DEFAULT_API_ENDPOINT: &str = "https://api.contabo.com";
const DEFAULT_AUTH_ENDPOINT: &str =
    "https://auth.contabo.com/auth/realms/contabo/protocol/openid-connect/token";
const PAGE_SIZE: u32 = 1000;
const RETRIES: u32 = 3;

#[derive(Clone)]
pub struct ContaboProvider {
    client: HttpClient,
    client_id: String,
    client_secret: String,
    api_user: String,
    api_password: String,
    api_endpoint: String,
    auth_endpoint: String,
    token: Arc<Mutex<Option<(String, Instant)>>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct ListRecordsResponse {
    #[serde(default)]
    data: Vec<Record>,
    #[serde(rename = "_pagination", default)]
    pagination: Pagination,
}

#[derive(Deserialize, Default)]
struct Pagination {
    #[serde(rename = "totalPages", default, deserialize_with = "number")]
    total_pages: u64,
}

#[derive(Deserialize, Debug, Clone)]
struct Record {
    #[serde(rename = "recordId", deserialize_with = "number")]
    id: u64,
    #[serde(default)]
    name: String,
    #[serde(rename = "type", default)]
    record_type: String,
    #[serde(default, deserialize_with = "number")]
    ttl: u64,
    #[serde(default, deserialize_with = "number")]
    prio: u64,
    #[serde(default)]
    data: String,
    #[serde(default, deserialize_with = "number")]
    port: u64,
    #[serde(default, deserialize_with = "number")]
    weight: u64,
    #[serde(default, deserialize_with = "number")]
    flag: u64,
    #[serde(default, deserialize_with = "optional_string")]
    tag: String,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
struct RecordData {
    #[serde(rename = "type")]
    record_type: &'static str,
    prio: u16,
    data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flag: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
}

#[derive(Serialize)]
struct CreateRecord<'a> {
    name: &'a str,
    ttl: u32,
    #[serde(flatten)]
    data: &'a RecordData,
}

#[derive(Serialize)]
struct UpdateRecord<'a> {
    ttl: u32,
    #[serde(flatten)]
    data: &'a RecordData,
}

struct Existing {
    id: u64,
    ttl: u64,
    data: RecordData,
}

impl ContaboProvider {
    pub(crate) fn new(
        client_id: impl AsRef<str>,
        client_secret: impl AsRef<str>,
        api_user: impl AsRef<str>,
        api_password: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let client_id = client_id.as_ref().to_string();
        let client_secret = client_secret.as_ref().to_string();
        let api_user = api_user.as_ref().to_string();
        let api_password = api_password.as_ref().to_string();
        if client_id.is_empty()
            || client_secret.is_empty()
            || api_user.is_empty()
            || api_password.is_empty()
        {
            return Err(Error::Api(
                "Contabo client ID, client secret, API user and API password must not be empty"
                    .to_string(),
            ));
        }

        let client = HttpClientBuilder::default()
            .without_header("content-type")
            .with_header("Accept", "application/json")
            .with_timeout(timeout)
            .build();

        Ok(Self {
            client,
            client_id,
            client_secret,
            api_user,
            api_password,
            api_endpoint: DEFAULT_API_ENDPOINT.to_string(),
            auth_endpoint: DEFAULT_AUTH_ENDPOINT.to_string(),
            token: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoints(
        self,
        api_endpoint: impl AsRef<str>,
        auth_endpoint: impl AsRef<str>,
    ) -> Self {
        Self {
            api_endpoint: api_endpoint.as_ref().trim_end_matches('/').to_string(),
            auth_endpoint: auth_endpoint.as_ref().to_string(),
            ..self
        }
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let desired = build_record_data(record_type, records)?;
        let name = normalize(&name.into_name());
        let token = self.ensure_token().await?;
        let (zone, mut existing) = self
            .find_records(&name, record_type, &origin.into_name(), &token)
            .await?;

        let mut to_create = Vec::new();
        let mut to_update = Vec::new();
        for data in desired {
            if let Some(idx) = existing.iter().position(|r| r.data == data) {
                let record = existing.swap_remove(idx);
                if record.ttl != ttl as u64 {
                    to_update.push((record.id, data));
                }
            } else {
                to_create.push(data);
            }
        }

        let subdomain = record_name(&name, &zone);
        for record in existing {
            self.delete_record(&zone, record.id, &token).await?;
        }
        for (id, data) in to_update {
            self.update_record(&zone, id, ttl, &data, &token).await?;
        }
        for data in to_create {
            self.create_record(&zone, &subdomain, ttl, &data, &token)
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
        let desired = build_record_data(record_type, records)?;
        if desired.is_empty() {
            return Ok(());
        }
        let name = normalize(&name.into_name());
        let token = self.ensure_token().await?;
        let (zone, existing) = self
            .find_records(&name, record_type, &origin.into_name(), &token)
            .await?;

        let subdomain = record_name(&name, &zone);
        for data in desired {
            if existing.iter().any(|r| r.data == data) {
                continue;
            }
            self.create_record(&zone, &subdomain, ttl, &data, &token)
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
        let to_remove = build_record_data(record_type, records)?;
        if to_remove.is_empty() {
            return Ok(());
        }
        let name = normalize(&name.into_name());
        let token = self.ensure_token().await?;
        let (zone, existing) = self
            .find_records(&name, record_type, &origin.into_name(), &token)
            .await?;

        for record in existing {
            if to_remove.contains(&record.data) {
                self.delete_record(&zone, record.id, &token).await?;
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
        check_supported(record_type)?;
        let name = normalize(&name.into_name());
        let token = self.ensure_token().await?;
        let (_, existing) = self
            .find_records(&name, record_type, &origin.into_name(), &token)
            .await?;
        existing
            .into_iter()
            .map(|record| record.data.try_into())
            .collect()
    }

    async fn find_records(
        &self,
        name: &str,
        record_type: DnsRecordType,
        origin: &str,
        token: &str,
    ) -> crate::Result<(String, Vec<Existing>)> {
        let mut zone = normalize(origin);
        loop {
            match self.list_records(&zone, token).await {
                Ok(records) => {
                    let existing = records
                        .into_iter()
                        .filter(|r| {
                            r.record_type.eq_ignore_ascii_case(record_type.as_str())
                                && record_fqdn(&r.name, &zone) == name
                        })
                        .map(|r| {
                            Ok(Existing {
                                id: r.id,
                                ttl: r.ttl,
                                data: RecordData::from_record(record_type, r)?,
                            })
                        })
                        .collect::<crate::Result<Vec<_>>>()?;
                    return Ok((zone, existing));
                }
                Err(Error::NotFound) => match zone.split_once('.') {
                    Some((_, parent)) if parent.contains('.') => zone = parent.to_string(),
                    _ => {
                        return Err(Error::Api(format!(
                            "Contabo DNS zone not found for {origin}"
                        )));
                    }
                },
                Err(err) => return Err(err),
            }
        }
    }

    async fn list_records(&self, zone: &str, token: &str) -> crate::Result<Vec<Record>> {
        let mut out = Vec::new();
        let mut page = 1u64;
        loop {
            let response: ListRecordsResponse = self
                .client
                .get(format!(
                    "{}/v1/dns/zones/{zone}/records?page={page}&size={PAGE_SIZE}",
                    self.api_endpoint
                ))
                .with_header("Authorization", format!("Bearer {token}"))
                .with_header("x-request-id", request_id())
                .send_with_retry(RETRIES)
                .await?;
            out.extend(response.data);
            if page >= response.pagination.total_pages {
                return Ok(out);
            }
            page += 1;
        }
    }

    async fn create_record(
        &self,
        zone: &str,
        name: &str,
        ttl: u32,
        data: &RecordData,
        token: &str,
    ) -> crate::Result<()> {
        self.client
            .post(format!("{}/v1/dns/zones/{zone}/records", self.api_endpoint))
            .with_header("Authorization", format!("Bearer {token}"))
            .with_header("x-request-id", request_id())
            .with_header("content-type", "application/json")
            .with_body(CreateRecord { name, ttl, data })?
            .send_with_retry::<serde_json::Value>(RETRIES)
            .await
            .map(|_| ())
    }

    async fn update_record(
        &self,
        zone: &str,
        id: u64,
        ttl: u32,
        data: &RecordData,
        token: &str,
    ) -> crate::Result<()> {
        self.client
            .patch(format!(
                "{}/v1/dns/zones/{zone}/records/{id}",
                self.api_endpoint
            ))
            .with_header("Authorization", format!("Bearer {token}"))
            .with_header("x-request-id", request_id())
            .with_header("content-type", "application/json")
            .with_body(UpdateRecord { ttl, data })?
            .send_with_retry::<serde_json::Value>(RETRIES)
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, zone: &str, id: u64, token: &str) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/v1/dns/zones/{zone}/records/{id}",
                self.api_endpoint
            ))
            .with_header("Authorization", format!("Bearer {token}"))
            .with_header("x-request-id", request_id())
            .send_with_retry::<serde_json::Value>(RETRIES)
            .await
            .map(|_| ())
    }

    async fn ensure_token(&self) -> crate::Result<String> {
        if let Some((token, expiry)) = self.token_lock()?.as_ref()
            && Instant::now() < *expiry
        {
            return Ok(token.clone());
        }

        let form = serde_urlencoded::to_string([
            ("grant_type", "password"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("username", self.api_user.as_str()),
            ("password", self.api_password.as_str()),
        ])
        .map_err(|err| Error::Api(format!("Failed to encode token request: {err}")))?;

        let response: TokenResponse = self
            .client
            .post(&self.auth_endpoint)
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_raw_body(form)
            .send_with_retry(RETRIES)
            .await?;

        if response.access_token.is_empty() {
            return Err(Error::Api(
                "Contabo token response is missing access_token".to_string(),
            ));
        }

        let lifetime = response
            .expires_in
            .unwrap_or(300)
            .saturating_sub(60)
            .max(30);
        *self.token_lock()? = Some((
            response.access_token.clone(),
            Instant::now() + Duration::from_secs(lifetime),
        ));
        Ok(response.access_token)
    }

    fn token_lock(&self) -> crate::Result<std::sync::MutexGuard<'_, Option<(String, Instant)>>> {
        self.token
            .lock()
            .map_err(|_| Error::Client("Contabo token cache lock poisoned".to_string()))
    }
}

fn check_supported(record_type: DnsRecordType) -> crate::Result<()> {
    match record_type {
        DnsRecordType::TLSA | DnsRecordType::NS => Err(Error::Unsupported(format!(
            "{} records are not supported by Contabo",
            record_type.as_str()
        ))),
        _ => Ok(()),
    }
}

fn build_record_data(
    record_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<RecordData>> {
    check_supported(record_type)?;
    records
        .into_iter()
        .map(|record| {
            if record.as_type() != record_type {
                return Err(Error::Api(format!(
                    "RRSet record type mismatch: expected {}, got {}",
                    record_type.as_str(),
                    record.as_type().as_str(),
                )));
            }
            RecordData::try_from(record)
        })
        .try_fold(Vec::new(), |mut out, data| {
            let data = data?;
            if !out.contains(&data) {
                out.push(data);
            }
            Ok(out)
        })
}

fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn record_fqdn(name: &str, zone: &str) -> String {
    let name = normalize(name);
    if name.is_empty() || name == "@" {
        zone.to_string()
    } else if name == zone || name.ends_with(&format!(".{zone}")) {
        name
    } else {
        format!("{name}.{zone}")
    }
}

fn record_name(name: &str, zone: &str) -> String {
    strip_origin_from_name(name, zone, Some(zone))
}

fn request_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let state = RandomState::new();
    let mut bytes = [0u8; 16];
    for (idx, chunk) in bytes.chunks_mut(8).enumerate() {
        let mut hasher = state.build_hasher();
        hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
        hasher.write_usize(idx);
        chunk.copy_from_slice(&hasher.finish().to_le_bytes());
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn unquote(value: &str) -> String {
    if value.trim_start().starts_with('"') {
        unquote_txt(value)
    } else {
        value.to_string()
    }
}

fn strip_dot(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

fn to_u16(value: u64, field: &str) -> crate::Result<u16> {
    u16::try_from(value).map_err(|_| Error::Parse(format!("Contabo {field} out of range: {value}")))
}

impl RecordData {
    fn new(record_type: &'static str, prio: u16, data: String) -> Self {
        Self {
            record_type,
            prio,
            data,
            port: None,
            weight: None,
            flag: None,
            tag: None,
        }
    }

    fn from_record(record_type: DnsRecordType, record: Record) -> crate::Result<Self> {
        let record_type = record_type.as_str();
        Ok(match record_type {
            "A" | "AAAA" => Self::new(record_type, 0, record.data.trim().to_string()),
            "CNAME" => Self::new(record_type, 0, strip_dot(&record.data)),
            "MX" => Self::new(
                record_type,
                to_u16(record.prio, "MX priority")?,
                strip_dot(&record.data),
            ),
            "TXT" => Self::new(record_type, 0, unquote(&record.data)),
            "SRV" => Self {
                port: Some(to_u16(record.port, "SRV port")?),
                weight: Some(to_u16(record.weight, "SRV weight")?),
                ..Self::new(
                    record_type,
                    to_u16(record.prio, "SRV priority")?,
                    strip_dot(&record.data),
                )
            },
            "CAA" => Self {
                flag: Some(u8::try_from(record.flag).map_err(|_| {
                    Error::Parse(format!("Contabo CAA flag out of range: {}", record.flag))
                })?),
                tag: Some(record.tag.to_ascii_lowercase()),
                ..Self::new(record_type, 0, unquote(&record.data))
            },
            other => {
                return Err(Error::Unsupported(format!(
                    "{other} records are not supported by Contabo"
                )));
            }
        })
    }
}

impl TryFrom<DnsRecord> for RecordData {
    type Error = Error;

    fn try_from(record: DnsRecord) -> crate::Result<Self> {
        Ok(match record {
            DnsRecord::A(addr) => Self::new("A", 0, addr.to_string()),
            DnsRecord::AAAA(addr) => Self::new("AAAA", 0, addr.to_string()),
            DnsRecord::CNAME(target) => Self::new("CNAME", 0, strip_dot(&target)),
            DnsRecord::MX(mx) => Self::new("MX", mx.priority, strip_dot(&mx.exchange)),
            DnsRecord::TXT(text) => Self::new("TXT", 0, text),
            DnsRecord::SRV(srv) => Self {
                port: Some(srv.port),
                weight: Some(srv.weight),
                ..Self::new("SRV", srv.priority, strip_dot(&srv.target))
            },
            DnsRecord::CAA(caa) => {
                let (flag, tag, value) = caa.decompose();
                Self {
                    flag: Some(flag),
                    tag: Some(tag.to_ascii_lowercase()),
                    ..Self::new("CAA", 0, value)
                }
            }
            DnsRecord::NS(_) | DnsRecord::TLSA(_) => {
                return Err(Error::Unsupported(format!(
                    "{} records are not supported by Contabo",
                    record.as_type().as_str()
                )));
            }
        })
    }
}

impl TryFrom<RecordData> for DnsRecord {
    type Error = Error;

    fn try_from(data: RecordData) -> crate::Result<Self> {
        Ok(match data.record_type {
            "A" => {
                DnsRecord::A(data.data.parse::<Ipv4Addr>().map_err(|err| {
                    Error::Parse(format!("Invalid A record {}: {err}", data.data))
                })?)
            }
            "AAAA" => DnsRecord::AAAA(data.data.parse::<Ipv6Addr>().map_err(|err| {
                Error::Parse(format!("Invalid AAAA record {}: {err}", data.data))
            })?),
            "CNAME" => DnsRecord::CNAME(data.data),
            "MX" => DnsRecord::MX(MXRecord {
                exchange: data.data,
                priority: data.prio,
            }),
            "TXT" => DnsRecord::TXT(data.data),
            "SRV" => DnsRecord::SRV(SRVRecord {
                target: data.data,
                priority: data.prio,
                weight: data.weight.unwrap_or_default(),
                port: data.port.unwrap_or_default(),
            }),
            "CAA" => DnsRecord::CAA(build_caa(
                data.flag.unwrap_or_default(),
                data.tag.as_deref().unwrap_or_default(),
                &data.data,
            )?),
            other => {
                return Err(Error::Unsupported(format!(
                    "{other} records are not supported by Contabo"
                )));
            }
        })
    }
}

fn number<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        Int(u64),
        Float(f64),
        Text(String),
    }

    match Option::<Value>::deserialize(deserializer)? {
        None => Ok(0),
        Some(Value::Int(value)) => Ok(value),
        Some(Value::Float(value)) if value.is_finite() && value >= 0.0 => Ok(value.round() as u64),
        Some(Value::Float(value)) => {
            Err(serde::de::Error::custom(format!("invalid number {value}")))
        }
        Some(Value::Text(value)) if value.trim().is_empty() => Ok(0),
        Some(Value::Text(value)) => value
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite() && *value >= 0.0)
            .map(|value| value.round() as u64)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid number {value}"))),
    }
}

fn optional_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}
