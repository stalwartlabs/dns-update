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
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api.netlify.com/api/v1";

#[derive(Clone)]
pub struct NetlifyProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecord<'a> {
    hostname: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    value: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flag: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct ListedRecord {
    #[serde(default)]
    id: String,
    #[serde(default)]
    hostname: String,
    #[serde(default, rename = "type")]
    record_type: String,
    #[serde(default)]
    value: String,
}

impl NetlifyProvider {
    pub(crate) fn new(access_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", access_token.as_ref()))
            .with_header("Accept", "application/json")
            .with_timeout(timeout);
        Self {
            client,
            endpoint: DEFAULT_ENDPOINT.to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().trim_end_matches('/').to_string(),
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
        let name = name.into_name().into_owned();
        let zone_id = zone_id_from_origin(&origin.into_name());
        let payload = build_create(&record, &name, ttl)?;

        self.client
            .post(format!(
                "{}/dns_zones/{}/dns_records",
                self.endpoint, zone_id
            ))
            .with_body(payload)?
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
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let zone_id = zone_id_from_origin(&origin);
        let record_type = record.as_type();
        let record_id = self
            .find_record_id(&zone_id, &name, record_type.as_str())
            .await?;

        self.client
            .delete(format!(
                "{}/dns_zones/{}/dns_records/{}",
                self.endpoint, zone_id, record_id
            ))
            .send_raw()
            .await?;

        let payload = build_create(&record, &name, ttl)?;
        self.client
            .post(format!(
                "{}/dns_zones/{}/dns_records",
                self.endpoint, zone_id
            ))
            .with_body(payload)?
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
        let name = name.into_name().into_owned();
        let zone_id = zone_id_from_origin(&origin.into_name());
        let record_id = self
            .find_record_id(&zone_id, &name, record_type.as_str())
            .await?;

        self.client
            .delete(format!(
                "{}/dns_zones/{}/dns_records/{}",
                self.endpoint, zone_id, record_id
            ))
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn find_record_id(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
    ) -> crate::Result<String> {
        let records: Vec<ListedRecord> = self
            .client
            .get(format!(
                "{}/dns_zones/{}/dns_records",
                self.endpoint, zone_id
            ))
            .send()
            .await?;
        records
            .into_iter()
            .find(|r| {
                r.hostname.trim_end_matches('.').eq_ignore_ascii_case(name)
                    && r.record_type.eq_ignore_ascii_case(record_type)
            })
            .map(|r| r.id)
            .ok_or_else(|| {
                Error::Api(format!(
                    "DNS Record {} of type {} not found in Netlify zone",
                    name, record_type
                ))
            })
    }
}

fn zone_id_from_origin(origin: &str) -> String {
    origin.trim_end_matches('.').replace('.', "_")
}

fn build_create<'a>(
    record: &'a DnsRecord,
    name: &'a str,
    ttl: u32,
) -> crate::Result<CreateRecord<'a>> {
    let mut payload = CreateRecord {
        hostname: name,
        record_type: "",
        value: String::new(),
        ttl,
        priority: None,
        weight: None,
        port: None,
        flag: None,
        tag: None,
    };

    match record {
        DnsRecord::A(addr) => {
            payload.record_type = "A";
            payload.value = addr.to_string();
        }
        DnsRecord::AAAA(addr) => {
            payload.record_type = "AAAA";
            payload.value = addr.to_string();
        }
        DnsRecord::CNAME(value) => {
            payload.record_type = "CNAME";
            payload.value = value.clone();
        }
        DnsRecord::NS(value) => {
            payload.record_type = "NS";
            payload.value = value.clone();
        }
        DnsRecord::MX(mx) => {
            payload.record_type = "MX";
            payload.value = mx.exchange.clone();
            payload.priority = Some(mx.priority);
        }
        DnsRecord::TXT(value) => {
            payload.record_type = "TXT";
            payload.value = value.clone();
        }
        DnsRecord::SRV(srv) => {
            payload.record_type = "SRV";
            payload.value = srv.target.clone();
            payload.priority = Some(srv.priority);
            payload.weight = Some(srv.weight);
            payload.port = Some(srv.port);
        }
        DnsRecord::CAA(caa) => {
            payload.record_type = "CAA";
            let (flags, tag, value) = caa.clone().decompose();
            payload.flag = Some(flags);
            payload.tag = Some(tag);
            payload.value = value;
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Netlify".to_string(),
            ));
        }
    }

    Ok(payload)
}
