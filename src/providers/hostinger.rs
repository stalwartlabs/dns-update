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
    DnsRecord, DnsRecordType, Error, IntoFqdn, http::HttpClientBuilder,
    utils::strip_origin_from_name,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://developers.hostinger.com";

#[derive(Clone)]
pub struct HostingerProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug)]
pub struct ZoneRequest {
    pub overwrite: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub zone: Vec<RecordSet>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecordSet {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub ttl: u32,
    pub records: Vec<RecordValue>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecordValue {
    pub content: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_disabled: bool,
}

#[derive(Serialize, Debug)]
pub struct Filters {
    pub filters: Vec<Filter>,
}

#[derive(Serialize, Debug)]
pub struct Filter {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl HostingerProvider {
    pub(crate) fn new(
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let token = api_token.as_ref();
        if token.is_empty() {
            return Err(Error::Api("Hostinger API token is empty".to_string()));
        }
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {token}"))
            .with_header("Accept", "application/json")
            .with_timeout(timeout);
        Ok(Self {
            client,
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

    fn zone_url(&self, domain: &str) -> String {
        format!("{}/api/dns/v1/zones/{}", self.endpoint, domain)
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
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let record_type = record.as_type();

        let new_value = encode_record(&record);

        let existing = self.fetch_record_set(&domain, &subdomain, record_type).await?;
        let mut records = existing.map(|r| r.records).unwrap_or_default();
        if !records.iter().any(|r| r.content == new_value) {
            records.push(RecordValue {
                content: new_value,
                is_disabled: false,
            });
        }

        let request = ZoneRequest {
            overwrite: true,
            zone: vec![RecordSet {
                name: subdomain,
                record_type: record_type.as_str().to_string(),
                ttl,
                records,
            }],
        };

        self.client
            .put(self.zone_url(&domain))
            .with_body(request)?
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
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let record_type = record.as_type();
        let new_value = encode_record(&record);

        let request = ZoneRequest {
            overwrite: true,
            zone: vec![RecordSet {
                name: subdomain,
                record_type: record_type.as_str().to_string(),
                ttl,
                records: vec![RecordValue {
                    content: new_value,
                    is_disabled: false,
                }],
            }],
        };

        self.client
            .put(self.zone_url(&domain))
            .with_body(request)?
            .send_raw()
            .await
            .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));

        let request = Filters {
            filters: vec![Filter {
                name: subdomain,
                record_type: record_type.as_str().to_string(),
            }],
        };

        self.client
            .delete(self.zone_url(&domain))
            .with_body(request)?
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn fetch_record_set(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Option<RecordSet>> {
        let response = self.client.get(self.zone_url(domain)).send_raw().await?;
        if response.is_empty() {
            return Ok(None);
        }
        let parsed: Vec<RecordSet> = serde_json::from_str(&response).map_err(|err| {
            Error::Serialize(format!("Failed to deserialize Hostinger zone: {err}"))
        })?;
        Ok(parsed
            .into_iter()
            .find(|r| r.name == subdomain && r.record_type == record_type.as_str()))
    }
}

fn encode_record(record: &DnsRecord) -> String {
    match record {
        DnsRecord::A(ip) => ip.to_string(),
        DnsRecord::AAAA(ip) => ip.to_string(),
        DnsRecord::CNAME(value) => value.clone(),
        DnsRecord::NS(value) => value.clone(),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, mx.exchange),
        DnsRecord::TXT(value) => value.clone(),
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority, srv.weight, srv.port, srv.target
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    }
}
