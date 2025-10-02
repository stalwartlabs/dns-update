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

use std::{
    hash::{Hash, Hasher},
    time::Duration,
};

use crate::{
    http::HttpClientBuilder, strip_origin_from_name, ApiCacheFetcher, ApiCacheManager, DnsRecord,
    DnsRecordTrait, Error, IntoFqdn,
};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct DigitalOceanProvider {
    client: HttpClientBuilder,
    record_cache: ApiCacheManager<i64>,
}

struct DigitalOceanRecordFetcher<'a> {
    client: &'a HttpClientBuilder,
    name: &'a str,
    domain: &'a str,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ListDomainRecord {
    domain_records: Vec<DomainRecord>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct UpdateDomainRecord<'a> {
    ttl: u32,
    name: &'a str,
    #[serde(flatten)]
    data: RecordData,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DomainRecord {
    id: i64,
    ttl: u32,
    name: String,
    #[serde(flatten)]
    data: RecordData,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct RecordData {
    #[serde(rename = "type")]
    rr_type: String,
    data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
}

#[derive(Serialize, Debug)]
pub struct Query<'a> {
    name: &'a str,
}

impl DigitalOceanProvider {
    pub(crate) fn new(auth_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", auth_token.as_ref()))
            .with_timeout(timeout);
        Self {
            client,
            record_cache: ApiCacheManager::default(),
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
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain);

        self.client
            .post(format!(
                "https://api.digitalocean.com/v2/domains/{domain}/records",
            ))
            .with_body(UpdateDomainRecord {
                ttl,
                name: &subdomain,
                data: record.into(),
            })?
            .send_raw()
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain);
        let record_id = self
            .record_cache
            .get_or_update(&mut DigitalOceanRecordFetcher {
                client: &self.client,
                name: name.as_ref(),
                domain: domain.as_ref(),
            })
            .await?;

        self.client
            .put(format!(
                "https://api.digitalocean.com/v2/domains/{domain}/records/{record_id}",
            ))
            .with_body(UpdateDomainRecord {
                ttl,
                name: &subdomain,
                data: record.into(),
            })?
            .send_raw()
            .await
            .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let record_id = self
            .record_cache
            .get_or_update(&mut DigitalOceanRecordFetcher {
                client: &self.client,
                name: name.as_ref(),
                domain: domain.as_ref(),
            })
            .await?;

        self.client
            .delete(format!(
                "https://api.digitalocean.com/v2/domains/{domain}/records/{record_id}",
            ))
            .send_raw()
            .await
            .map(|_| ())
    }
}

impl<'a> ApiCacheFetcher<i64> for DigitalOceanRecordFetcher<'a> {
    async fn fetch_api_response(&mut self) -> crate::Result<i64> {
        let subdomain = strip_origin_from_name(self.name, self.domain);
        self.client
            .get(format!(
                "https://api.digitalocean.com/v2/domains/{}/records?{}",
                self.domain,
                Query::name(self.name).serialize()
            ))
            .send_with_retry::<ListDomainRecord>(3)
            .await
            .and_then(|result| {
                result
                    .domain_records
                    .into_iter()
                    .find(|record| record.name == subdomain)
                    .map(|record| record.id)
                    .ok_or_else(|| Error::Api(format!("DNS Record {} not found", subdomain)))
            })
    }
}

impl Hash for DigitalOceanRecordFetcher<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.domain.hash(state);
    }
}

impl<'a> Query<'a> {
    pub fn name(name: impl Into<&'a str>) -> Self {
        Self { name: name.into() }
    }

    pub fn serialize(&self) -> String {
        serde_urlencoded::to_string(self).unwrap()
    }
}

impl From<DnsRecord> for RecordData {
    fn from(record: DnsRecord) -> Self {
        RecordData {
            rr_type: record.get_type().to_string(),
            data: record.get_content(),
            priority: record.get_priority(),
            weight: record.get_weight(),
            port: record.get_port(),
        }
    }
}
