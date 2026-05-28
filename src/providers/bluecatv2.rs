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
    http::{HttpClient, HttpClientBuilder},
    utils::strip_origin_from_name,
};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct BluecatV2Config {
    pub server_url: String,
    pub username: String,
    pub password: String,
    pub config_name: String,
    pub view_name: String,
    pub skip_deploy: bool,
    pub request_timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct BluecatV2Provider {
    client: HttpClient,
    config: BluecatV2Config,
    endpoint: String,
    token: Arc<Mutex<Option<(String, Instant)>>>,
}

#[derive(Serialize, Debug)]
struct LoginInfo<'a> {
    username: &'a str,
    password: &'a str,
}

#[derive(Deserialize, Debug)]
struct SessionResponse {
    #[serde(rename = "basicAuthenticationCredentials")]
    basic_authentication_credentials: String,
}

#[derive(Deserialize, Debug)]
struct ZoneResource {
    id: i64,
    #[serde(rename = "absoluteName")]
    absolute_name: String,
}

#[derive(Deserialize, Debug)]
struct Collection<T> {
    data: Vec<T>,
}

#[derive(Deserialize, Debug, Clone)]
struct ListedResourceRecord {
    id: i64,
    #[serde(rename = "absoluteName", default)]
    absolute_name: Option<String>,
    #[serde(rename = "recordType", default)]
    record_type: Option<String>,
    #[serde(default)]
    addresses: Option<Vec<String>>,
    #[serde(rename = "linkedRecord", default)]
    linked_record: Option<ListedLinkedRecord>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    priority: Option<u16>,
    #[serde(default)]
    weight: Option<u16>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    flags: Option<u8>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
struct ListedLinkedRecord {
    #[serde(rename = "absoluteName", default)]
    absolute_name: Option<String>,
}

#[derive(Serialize, Debug)]
struct ResourceRecordPayload<'a> {
    #[serde(rename = "type")]
    rr_type: &'static str,
    name: &'a str,
    #[serde(rename = "recordType")]
    record_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    #[serde(flatten)]
    data: RecordData,
}

#[derive(Serialize, Debug)]
#[serde(untagged)]
enum RecordData {
    Address {
        addresses: Vec<String>,
    },
    LinkedRecord {
        #[serde(rename = "linkedRecord")]
        linked_record: LinkedRecord,
    },
    Mx {
        priority: u16,
        #[serde(rename = "linkedRecord")]
        linked_record: LinkedRecord,
    },
    Text {
        text: String,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        #[serde(rename = "linkedRecord")]
        linked_record: LinkedRecord,
    },
    Caa {
        flags: u8,
        tag: String,
        value: String,
    },
}

#[derive(Serialize, Debug)]
struct LinkedRecord {
    #[serde(rename = "absoluteName")]
    absolute_name: String,
}

#[derive(Serialize, Debug)]
struct QuickDeploymentPayload {
    #[serde(rename = "type")]
    rr_type: &'static str,
}

impl BluecatV2Provider {
    pub(crate) fn new(config: BluecatV2Config) -> crate::Result<Self> {
        if config.server_url.is_empty() {
            return Err(Error::Api("Bluecat server URL is required".into()));
        }
        if config.username.is_empty() || config.password.is_empty() {
            return Err(Error::Api("Bluecat credentials are required".into()));
        }
        if config.config_name.is_empty() {
            return Err(Error::Api("Bluecat configuration name is required".into()));
        }
        if config.view_name.is_empty() {
            return Err(Error::Api("Bluecat view name is required".into()));
        }

        let endpoint = config.server_url.trim_end_matches('/').to_string();
        let client = HttpClientBuilder::default()
            .with_header("Accept", "application/json")
            .with_timeout(config.request_timeout)
            .build();

        Ok(Self {
            client,
            config,
            endpoint,
            token: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        self.endpoint = endpoint.as_ref().trim_end_matches('/').to_string();
        self
    }

    async fn ensure_token(&self) -> crate::Result<String> {
        {
            let guard = self
                .token
                .lock()
                .map_err(|_| Error::Api("Bluecat token mutex poisoned".into()))?;
            if let Some((ref token, expiry)) = *guard
                && Instant::now() < expiry
            {
                return Ok(token.clone());
            }
        }

        let url = format!("{}/api/v2/sessions", self.endpoint);
        let session: SessionResponse = self
            .client
            .post(url)
            .with_header("Content-Type", "application/json")
            .with_body(LoginInfo {
                username: &self.config.username,
                password: &self.config.password,
            })?
            .send()
            .await?;

        let expiry = Instant::now() + Duration::from_secs(25 * 60);
        let mut guard = self
            .token
            .lock()
            .map_err(|_| Error::Api("Bluecat token mutex poisoned".into()))?;
        *guard = Some((session.basic_authentication_credentials.clone(), expiry));
        Ok(session.basic_authentication_credentials)
    }

    fn authed_get(&self, url: String, token: &str) -> crate::http::HttpRequest {
        self.client
            .get(url)
            .with_header("Authorization", format!("Basic {token}"))
    }

    fn authed_post(&self, url: String, token: &str) -> crate::http::HttpRequest {
        self.client
            .post(url)
            .with_header("Authorization", format!("Basic {token}"))
    }

    fn authed_delete(&self, url: String, token: &str) -> crate::http::HttpRequest {
        self.client
            .delete(url)
            .with_header("Authorization", format!("Basic {token}"))
    }

    async fn find_zone(&self, token: &str, origin: &str) -> crate::Result<ZoneResource> {
        let origin = origin.trim_end_matches('.');
        let filter = format!(
            "absoluteName:eq('{}') and configuration.name:eq('{}') and view.name:eq('{}')",
            origin, self.config.config_name, self.config.view_name
        );
        let query = serde_urlencoded::to_string([
            ("fields", "id,absoluteName"),
            ("filter", filter.as_str()),
        ])
        .map_err(|err| Error::Serialize(err.to_string()))?;
        let url = format!("{}/api/v2/zones?{}", self.endpoint, query);
        let zones: Collection<ZoneResource> = self.authed_get(url, token).send().await?;
        zones
            .data
            .into_iter()
            .find(|z| z.absolute_name.trim_end_matches('.') == origin)
            .ok_or_else(|| Error::Api(format!("No Bluecat zone found for {origin}")))
    }

    async fn deploy_zone(&self, token: &str, zone_id: i64) -> crate::Result<()> {
        if self.config.skip_deploy {
            return Ok(());
        }
        let url = format!("{}/api/v2/zones/{}/deployments", self.endpoint, zone_id);
        self.authed_post(url, token)
            .with_header("Content-Type", "application/json")
            .with_body(QuickDeploymentPayload {
                rr_type: "QuickDeployment",
            })?
            .send_raw()
            .await
            .map(|_| ())
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
        let _ = bluecat_record_type(record_type)?;
        let token = self.ensure_token().await?;
        let origin = origin.into_name().to_string();
        let zone = self.find_zone(&token, &origin).await?;
        let name = name.into_name().to_string();
        let subdomain = strip_origin_from_name(&name, &origin, Some(""));

        let existing = self.list_at(&token, zone.id, &name, record_type).await?;

        if records.is_empty() {
            if existing.is_empty() {
                return Ok(());
            }
            for entry in existing {
                self.delete_record(&token, entry.id).await?;
            }
            return self.deploy_zone(&token, zone.id).await;
        }

        let desired = build_normalized(record_type, records)?;
        let mut existing_pool: Vec<(i64, NormalizedContent)> = existing
            .into_iter()
            .filter_map(|r| normalize_listed(record_type, &r).map(|c| (r.id, c)))
            .collect();

        let mut to_add: Vec<NormalizedContent> = Vec::new();
        for content in desired {
            if let Some(idx) = existing_pool.iter().position(|(_, c)| c == &content) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(content);
            }
        }

        if to_add.is_empty() && existing_pool.is_empty() {
            return Ok(());
        }

        for (id, _) in existing_pool {
            self.delete_record(&token, id).await?;
        }
        for content in to_add {
            self.create_normalized(&token, zone.id, &subdomain, ttl, content)
                .await?;
        }

        self.deploy_zone(&token, zone.id).await
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
        let _ = bluecat_record_type(record_type)?;
        let token = self.ensure_token().await?;
        let origin = origin.into_name().to_string();
        let zone = self.find_zone(&token, &origin).await?;
        let name = name.into_name().to_string();
        let subdomain = strip_origin_from_name(&name, &origin, Some(""));

        let desired = build_normalized(record_type, records)?;
        let existing = self.list_at(&token, zone.id, &name, record_type).await?;
        let existing_normalized: Vec<NormalizedContent> = existing
            .iter()
            .filter_map(|r| normalize_listed(record_type, r))
            .collect();

        let mut added = false;
        for content in desired {
            if existing_normalized.iter().any(|c| c == &content) {
                continue;
            }
            self.create_normalized(&token, zone.id, &subdomain, ttl, content)
                .await?;
            added = true;
        }

        if added {
            self.deploy_zone(&token, zone.id).await
        } else {
            Ok(())
        }
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
        let _ = bluecat_record_type(record_type)?;
        let token = self.ensure_token().await?;
        let origin = origin.into_name().to_string();
        let zone = self.find_zone(&token, &origin).await?;
        let name = name.into_name().to_string();

        let to_remove = build_normalized(record_type, records)?;
        let existing = self.list_at(&token, zone.id, &name, record_type).await?;

        let mut removed = false;
        for content in to_remove {
            if let Some(entry) = existing
                .iter()
                .find(|r| normalize_listed(record_type, r).as_ref() == Some(&content))
            {
                self.delete_record(&token, entry.id).await?;
                removed = true;
            }
        }

        if removed {
            self.deploy_zone(&token, zone.id).await
        } else {
            Ok(())
        }
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let _ = bluecat_record_type(record_type)?;
        let token = self.ensure_token().await?;
        let origin = origin.into_name().to_string();
        let zone = self.find_zone(&token, &origin).await?;
        let name = name.into_name().to_string();

        let existing = self.list_at(&token, zone.id, &name, record_type).await?;
        let mut out = Vec::with_capacity(existing.len());
        for listed in existing {
            if let Some(record) = listed_to_dns_record(record_type, &listed) {
                out.push(record);
            }
        }
        Ok(out)
    }

    async fn list_at(
        &self,
        token: &str,
        zone_id: i64,
        absolute_name: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ListedResourceRecord>> {
        let rtype = bluecat_record_type(record_type)?;
        let target_name = absolute_name.trim_end_matches('.');
        let filter = format!(
            "absoluteName:eq('{}') and recordType:eq('{}')",
            target_name, rtype
        );
        let query = serde_urlencoded::to_string([("filter", filter.as_str())])
            .map_err(|err| Error::Serialize(err.to_string()))?;
        let url = format!(
            "{}/api/v2/zones/{}/resourceRecords?{}",
            self.endpoint, zone_id, query
        );
        let records: Collection<ListedResourceRecord> = self.authed_get(url, token).send().await?;
        Ok(records
            .data
            .into_iter()
            .filter(|r| {
                let name_ok = r
                    .absolute_name
                    .as_deref()
                    .map(|n| n.trim_end_matches('.') == target_name)
                    .unwrap_or(false);
                let type_ok = r
                    .record_type
                    .as_deref()
                    .map(|t| t == rtype)
                    .unwrap_or(false);
                name_ok && type_ok
            })
            .collect())
    }

    async fn delete_record(&self, token: &str, record_id: i64) -> crate::Result<()> {
        let url = format!("{}/api/v2/resourceRecords/{}", self.endpoint, record_id);
        self.authed_delete(url, token).send_raw().await.map(|_| ())
    }

    async fn create_normalized(
        &self,
        token: &str,
        zone_id: i64,
        subdomain: &str,
        ttl: u32,
        content: NormalizedContent,
    ) -> crate::Result<()> {
        let payload = build_payload_from_normalized(subdomain, ttl, content);
        let url = format!("{}/api/v2/zones/{}/resourceRecords", self.endpoint, zone_id);
        self.authed_post(url, token)
            .with_header("Content-Type", "application/json")
            .with_body(payload)?
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn bluecat_record_type(record_type: DnsRecordType) -> crate::Result<&'static str> {
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
                "TLSA records are not supported by Bluecat".into(),
            ));
        }
    })
}

fn normalize_target(value: &str) -> String {
    value.trim_end_matches('.').to_string()
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> crate::Result<()> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum NormalizedContent {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ns(String),
    Mx {
        priority: u16,
        exchange: String,
    },
    Txt(String),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Caa {
        flags: u8,
        tag: String,
        value: String,
    },
}

fn build_normalized(
    expected: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<NormalizedContent>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(record_to_normalized(record)?);
    }
    Ok(out)
}

fn record_to_normalized(record: DnsRecord) -> crate::Result<NormalizedContent> {
    Ok(match record {
        DnsRecord::A(addr) => NormalizedContent::A(addr),
        DnsRecord::AAAA(addr) => NormalizedContent::Aaaa(addr),
        DnsRecord::CNAME(value) => NormalizedContent::Cname(normalize_target(&value)),
        DnsRecord::NS(value) => NormalizedContent::Ns(normalize_target(&value)),
        DnsRecord::MX(mx) => NormalizedContent::Mx {
            priority: mx.priority,
            exchange: normalize_target(&mx.exchange),
        },
        DnsRecord::TXT(text) => NormalizedContent::Txt(text),
        DnsRecord::SRV(srv) => NormalizedContent::Srv {
            priority: srv.priority,
            weight: srv.weight,
            port: srv.port,
            target: normalize_target(&srv.target),
        },
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.decompose();
            NormalizedContent::Caa { flags, tag, value }
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Unsupported(
                "TLSA records are not supported by Bluecat".into(),
            ));
        }
    })
}

fn normalize_listed(
    record_type: DnsRecordType,
    listed: &ListedResourceRecord,
) -> Option<NormalizedContent> {
    match record_type {
        DnsRecordType::A => {
            let addr = listed.addresses.as_ref()?.first()?;
            addr.parse::<Ipv4Addr>().ok().map(NormalizedContent::A)
        }
        DnsRecordType::AAAA => {
            let addr = listed.addresses.as_ref()?.first()?;
            addr.parse::<Ipv6Addr>().ok().map(NormalizedContent::Aaaa)
        }
        DnsRecordType::CNAME => {
            let target = listed.linked_record.as_ref()?.absolute_name.as_deref()?;
            Some(NormalizedContent::Cname(normalize_target(target)))
        }
        DnsRecordType::NS => {
            let target = listed.linked_record.as_ref()?.absolute_name.as_deref()?;
            Some(NormalizedContent::Ns(normalize_target(target)))
        }
        DnsRecordType::MX => {
            let exchange = listed.linked_record.as_ref()?.absolute_name.as_deref()?;
            let priority = listed.priority?;
            Some(NormalizedContent::Mx {
                priority,
                exchange: normalize_target(exchange),
            })
        }
        DnsRecordType::TXT => listed.text.clone().map(NormalizedContent::Txt),
        DnsRecordType::SRV => {
            let target = listed.linked_record.as_ref()?.absolute_name.as_deref()?;
            Some(NormalizedContent::Srv {
                priority: listed.priority?,
                weight: listed.weight?,
                port: listed.port?,
                target: normalize_target(target),
            })
        }
        DnsRecordType::CAA => Some(NormalizedContent::Caa {
            flags: listed.flags?,
            tag: listed.tag.clone()?,
            value: listed.value.clone()?,
        }),
        DnsRecordType::TLSA => None,
    }
}

fn listed_to_dns_record(
    record_type: DnsRecordType,
    listed: &ListedResourceRecord,
) -> Option<DnsRecord> {
    match normalize_listed(record_type, listed)? {
        NormalizedContent::A(addr) => Some(DnsRecord::A(addr)),
        NormalizedContent::Aaaa(addr) => Some(DnsRecord::AAAA(addr)),
        NormalizedContent::Cname(value) => Some(DnsRecord::CNAME(value)),
        NormalizedContent::Ns(value) => Some(DnsRecord::NS(value)),
        NormalizedContent::Mx { priority, exchange } => {
            Some(DnsRecord::MX(MXRecord { exchange, priority }))
        }
        NormalizedContent::Txt(text) => Some(DnsRecord::TXT(text)),
        NormalizedContent::Srv {
            priority,
            weight,
            port,
            target,
        } => Some(DnsRecord::SRV(SRVRecord {
            priority,
            weight,
            port,
            target,
        })),
        NormalizedContent::Caa { flags, tag, value } => caa_from_parts(flags, &tag, &value),
    }
}

fn caa_from_parts(flags: u8, tag: &str, value: &str) -> Option<DnsRecord> {
    let issuer_critical = flags & 0x80 != 0;
    let record = match tag {
        "issue" => {
            let (name, options) = parse_caa_value(value);
            CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(value);
            CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            }
        }
        "iodef" => CAARecord::Iodef {
            issuer_critical,
            url: value.to_string(),
        },
        _ => return None,
    };
    Some(DnsRecord::CAA(record))
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

fn build_payload_from_normalized(
    subdomain: &str,
    ttl: u32,
    content: NormalizedContent,
) -> ResourceRecordPayload<'_> {
    let (rr_type, record_type, data) = match content {
        NormalizedContent::A(addr) => (
            "GenericRecord",
            "A",
            RecordData::Address {
                addresses: vec![addr.to_string()],
            },
        ),
        NormalizedContent::Aaaa(addr) => (
            "GenericRecord",
            "AAAA",
            RecordData::Address {
                addresses: vec![addr.to_string()],
            },
        ),
        NormalizedContent::Cname(value) => (
            "AliasRecord",
            "CNAME",
            RecordData::LinkedRecord {
                linked_record: LinkedRecord {
                    absolute_name: value,
                },
            },
        ),
        NormalizedContent::Ns(value) => (
            "GenericRecord",
            "NS",
            RecordData::LinkedRecord {
                linked_record: LinkedRecord {
                    absolute_name: value,
                },
            },
        ),
        NormalizedContent::Mx { priority, exchange } => (
            "MXRecord",
            "MX",
            RecordData::Mx {
                priority,
                linked_record: LinkedRecord {
                    absolute_name: exchange,
                },
            },
        ),
        NormalizedContent::Txt(text) => ("TXTRecord", "TXT", RecordData::Text { text }),
        NormalizedContent::Srv {
            priority,
            weight,
            port,
            target,
        } => (
            "SRVRecord",
            "SRV",
            RecordData::Srv {
                priority,
                weight,
                port,
                linked_record: LinkedRecord {
                    absolute_name: target,
                },
            },
        ),
        NormalizedContent::Caa { flags, tag, value } => {
            ("CAARecord", "CAA", RecordData::Caa { flags, tag, value })
        }
    };

    ResourceRecordPayload {
        rr_type,
        name: subdomain,
        record_type,
        ttl: Some(ttl),
        data,
    }
}
