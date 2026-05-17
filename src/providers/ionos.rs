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

const DEFAULT_ENDPOINT: &str = "https://api.hosting.ionos.com/dns";

#[derive(Clone)]
pub struct IonosProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Deserialize, Debug)]
struct Zone {
    id: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize, Debug, Default)]
struct CustomerZone {
    #[serde(default)]
    records: Vec<Record>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Record {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    name: String,
    content: String,
    ttl: u32,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default, skip_serializing_if = "is_zero_u16", rename = "prio")]
    priority: u16,
    #[serde(default, skip_serializing_if = "is_false")]
    disabled: bool,
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !*v
}

impl IonosProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("X-Api-Key", api_key.as_ref())
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
        let domain = origin.into_name().into_owned();
        let zone_id = self.find_zone_id(&domain).await?;
        let payload = vec![record_to_payload(&record, &name, ttl)?];

        self.client
            .post(format!("{}/v1/zones/{}/records", self.endpoint, zone_id))
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
        let domain = origin.into_name().into_owned();
        let zone_id = self.find_zone_id(&domain).await?;
        let record_type = record.as_type();
        let record_id = self
            .find_record_id(&zone_id, &name, record_type.as_str())
            .await?;
        let payload = record_to_payload(&record, &name, ttl)?;

        self.client
            .put(format!(
                "{}/v1/zones/{}/records/{}",
                self.endpoint, zone_id, record_id
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
        let domain = origin.into_name().into_owned();
        let zone_id = self.find_zone_id(&domain).await?;
        let record_id = self
            .find_record_id(&zone_id, &name, record_type.as_str())
            .await?;

        self.client
            .delete(format!(
                "{}/v1/zones/{}/records/{}",
                self.endpoint, zone_id, record_id
            ))
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn find_zone_id(&self, origin: &str) -> crate::Result<String> {
        let origin = origin.trim_end_matches('.');
        let zones = self
            .client
            .get(format!("{}/v1/zones", self.endpoint))
            .send::<Vec<Zone>>()
            .await?;

        let mut best: Option<Zone> = None;
        for zone in zones {
            if zone.name.is_empty() {
                continue;
            }
            if origin == zone.name || origin.ends_with(&format!(".{}", zone.name)) {
                if best
                    .as_ref()
                    .map(|b| zone.name.len() > b.name.len())
                    .unwrap_or(true)
                {
                    best = Some(zone);
                }
            }
        }

        best.map(|z| z.id)
            .ok_or_else(|| Error::Api(format!("No IONOS zone found for {}", origin)))
    }

    async fn find_record_id(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
    ) -> crate::Result<String> {
        let zone = self
            .client
            .get(format!(
                "{}/v1/zones/{}?recordName={}&recordType={}",
                self.endpoint, zone_id, name, record_type
            ))
            .send::<CustomerZone>()
            .await?;

        zone.records
            .into_iter()
            .find(|r| r.name == name && r.record_type.eq_ignore_ascii_case(record_type))
            .and_then(|r| r.id)
            .ok_or_else(|| {
                Error::Api(format!(
                    "DNS Record {} of type {} not found in IONOS zone",
                    name, record_type
                ))
            })
    }
}

fn record_to_payload(record: &DnsRecord, name: &str, ttl: u32) -> crate::Result<Record> {
    let (record_type, content, priority) = match record {
        DnsRecord::A(addr) => ("A", addr.to_string(), 0),
        DnsRecord::AAAA(addr) => ("AAAA", addr.to_string(), 0),
        DnsRecord::CNAME(value) => ("CNAME", value.clone(), 0),
        DnsRecord::NS(value) => ("NS", value.clone(), 0),
        DnsRecord::MX(mx) => ("MX", mx.exchange.clone(), mx.priority),
        DnsRecord::TXT(value) => ("TXT", format!("\"{}\"", value.replace('"', "\\\"")), 0),
        DnsRecord::SRV(srv) => (
            "SRV",
            format!("{} {} {}", srv.weight, srv.port, srv.target),
            srv.priority,
        ),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            (
                "CAA",
                format!("{} {} \"{}\"", flags, tag, value.replace('"', "\\\"")),
                0,
            )
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by IONOS".to_string(),
            ));
        }
    };

    Ok(Record {
        id: None,
        name: name.to_string(),
        content,
        ttl,
        record_type: record_type.to_string(),
        priority,
        disabled: false,
    })
}

