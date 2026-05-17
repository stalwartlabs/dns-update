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

use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, http::HttpClientBuilder};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.luadns.com";

#[derive(Clone)]
pub struct LuaDnsProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct LuaZone {
    pub id: i64,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LuaRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub name: String,
    #[serde(rename = "type")]
    pub rr_type: String,
    pub content: String,
    pub ttl: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<i64>,
}

impl LuaDnsProvider {
    pub(crate) fn new(
        api_username: impl AsRef<str>,
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let raw = format!("{}:{}", api_username.as_ref(), api_token.as_ref());
        let encoded = B64.encode(raw);
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {encoded}"))
            .with_header("Accept", "application/json")
            .with_timeout(timeout);
        Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    async fn list_zones(&self) -> crate::Result<Vec<LuaZone>> {
        self.client
            .get(format!("{}/v1/zones", self.endpoint))
            .send_with_retry::<Vec<LuaZone>>(3)
            .await
    }

    async fn find_zone(&self, origin: &str) -> crate::Result<LuaZone> {
        let zones = self.list_zones().await?;
        zones
            .into_iter()
            .find(|z| z.name == origin)
            .ok_or_else(|| Error::Api(format!("LuaDNS zone {origin} not found")))
    }

    async fn list_records(&self, zone_id: i64) -> crate::Result<Vec<LuaRecord>> {
        self.client
            .get(format!("{}/v1/zones/{zone_id}/records", self.endpoint))
            .send_with_retry::<Vec<LuaRecord>>(3)
            .await
    }

    async fn find_record(
        &self,
        zone_id: i64,
        fqdn: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<LuaRecord> {
        let target = fqdn.trim_end_matches('.');
        let rr_type = record_type.as_str();
        let records = self.list_records(zone_id).await?;
        records
            .into_iter()
            .find(|r| r.rr_type == rr_type && r.name.trim_end_matches('.') == target)
            .ok_or_else(|| Error::Api(format!("LuaDNS record {fqdn} of type {rr_type} not found")))
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let origin_name = origin.into_name().to_string();
        let zone = self.find_zone(&origin_name).await?;
        let body = build_record(name, record, ttl)?;

        self.client
            .post(format!(
                "{}/v1/zones/{}/records",
                self.endpoint, zone.id
            ))
            .with_body(&body)?
            .send_with_retry::<LuaRecord>(3)
            .await
            .map(|_| ())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let origin_name = origin.into_name().to_string();
        let zone = self.find_zone(&origin_name).await?;
        let fqdn = name.into_fqdn().to_string();
        let record_type = record.as_type();
        let existing = self.find_record(zone.id, &fqdn, record_type).await?;
        let id = existing.id.ok_or_else(|| {
            Error::Api("LuaDNS record missing id".to_string())
        })?;
        let body = build_record(fqdn.as_str(), record, ttl)?;

        self.client
            .put(format!(
                "{}/v1/zones/{}/records/{id}",
                self.endpoint, zone.id
            ))
            .with_body(&body)?
            .send_with_retry::<LuaRecord>(3)
            .await
            .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let origin_name = origin.into_name().to_string();
        let zone = self.find_zone(&origin_name).await?;
        let fqdn = name.into_fqdn().to_string();
        let existing = self.find_record(zone.id, &fqdn, record_type).await?;
        let id = existing.id.ok_or_else(|| {
            Error::Api("LuaDNS record missing id".to_string())
        })?;

        self.client
            .delete(format!(
                "{}/v1/zones/{}/records/{id}",
                self.endpoint, zone.id
            ))
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn ensure_dot(name: String) -> String {
    if name.ends_with('.') {
        name
    } else {
        format!("{name}.")
    }
}

fn build_record<'a>(name: impl IntoFqdn<'a>, record: DnsRecord, ttl: u32) -> crate::Result<LuaRecord> {
    let rr_type = record.as_type().as_str().to_string();
    let fqdn = name.into_fqdn().to_string();
    let content = match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => ensure_dot(content),
        DnsRecord::NS(content) => ensure_dot(content),
        DnsRecord::TXT(content) => format!("\"{}\"", content.replace('"', "\\\"")),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, ensure_dot(mx.exchange)),
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            ensure_dot(srv.target)
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    };

    Ok(LuaRecord {
        id: None,
        name: fqdn,
        rr_type,
        content,
        ttl,
        zone_id: None,
    })
}
