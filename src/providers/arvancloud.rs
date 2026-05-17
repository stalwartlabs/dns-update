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

const DEFAULT_API_ENDPOINT: &str = "https://napi.arvancloud.ir";

#[derive(Clone)]
pub struct ArvanCloudProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct ArvanRecordPayload {
    #[serde(rename = "type")]
    pub record_type: &'static str,
    pub name: String,
    pub value: serde_json::Value,
    pub ttl: u32,
    pub upstream_https: &'static str,
    pub ip_filter_mode: ArvanIpFilterMode,
}

#[derive(Serialize, Debug, Clone)]
pub struct ArvanIpFilterMode {
    pub count: &'static str,
    pub order: &'static str,
    pub geo_filter: &'static str,
}

impl Default for ArvanIpFilterMode {
    fn default() -> Self {
        Self {
            count: "single",
            order: "none",
            geo_filter: "none",
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct ArvanApiResponse<T> {
    pub data: T,
}

#[derive(Deserialize, Debug)]
pub struct ArvanExistingRecord {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
}

pub struct ArvanRecordContent {
    pub record_type: &'static str,
    pub value: serde_json::Value,
}

impl ArvanCloudProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", api_key.as_ref())
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

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let fqdn = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&fqdn, &domain, Some("@"));
        let content = ArvanRecordContent::try_from(record)?;
        let body = ArvanRecordPayload {
            record_type: content.record_type,
            name: subdomain,
            value: content.value,
            ttl,
            upstream_https: "default",
            ip_filter_mode: ArvanIpFilterMode::default(),
        };

        self.client
            .post(format!(
                "{endpoint}/cdn/4.0/domains/{domain}/dns-records",
                endpoint = self.endpoint
            ))
            .with_body(&body)?
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
        let fqdn = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&fqdn, &domain, Some("@"));
        let record_type = record.as_type();
        let record_id = self
            .find_record_id(&domain, &subdomain, record_type)
            .await?;
        let content = ArvanRecordContent::try_from(record)?;
        let body = ArvanRecordPayload {
            record_type: content.record_type,
            name: subdomain,
            value: content.value,
            ttl,
            upstream_https: "default",
            ip_filter_mode: ArvanIpFilterMode::default(),
        };

        self.client
            .put(format!(
                "{endpoint}/cdn/4.0/domains/{domain}/dns-records/{record_id}",
                endpoint = self.endpoint
            ))
            .with_body(&body)?
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
        let fqdn = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&fqdn, &domain, Some("@"));
        let record_id = self
            .find_record_id(&domain, &subdomain, record_type)
            .await?;

        self.client
            .delete(format!(
                "{endpoint}/cdn/4.0/domains/{domain}/dns-records/{record_id}",
                endpoint = self.endpoint
            ))
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn find_record_id(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<String> {
        let response: ArvanApiResponse<Vec<ArvanExistingRecord>> = self
            .client
            .get(format!(
                "{endpoint}/cdn/4.0/domains/{domain}/dns-records",
                endpoint = self.endpoint
            ))
            .send()
            .await?;
        let wire_type = record_type_to_wire(record_type);
        response
            .data
            .into_iter()
            .find(|r| r.name == subdomain && r.record_type == wire_type)
            .map(|r| r.id)
            .ok_or_else(|| {
                Error::Api(format!(
                    "DNS Record {subdomain} of type {wire_type} not found"
                ))
            })
    }
}

fn record_type_to_wire(record_type: DnsRecordType) -> &'static str {
    match record_type {
        DnsRecordType::A => "a",
        DnsRecordType::AAAA => "aaaa",
        DnsRecordType::CNAME => "cname",
        DnsRecordType::NS => "ns",
        DnsRecordType::MX => "mx",
        DnsRecordType::TXT => "txt",
        DnsRecordType::SRV => "srv",
        DnsRecordType::TLSA => "tlsa",
        DnsRecordType::CAA => "caa",
    }
}

impl TryFrom<DnsRecord> for ArvanRecordContent {
    type Error = Error;

    fn try_from(record: DnsRecord) -> Result<Self, Self::Error> {
        match record {
            DnsRecord::A(addr) => Ok(ArvanRecordContent {
                record_type: "a",
                value: serde_json::json!([{ "ip": addr.to_string() }]),
            }),
            DnsRecord::AAAA(addr) => Ok(ArvanRecordContent {
                record_type: "aaaa",
                value: serde_json::json!([{ "ip": addr.to_string() }]),
            }),
            DnsRecord::CNAME(target) => Ok(ArvanRecordContent {
                record_type: "cname",
                value: serde_json::json!({ "host": target }),
            }),
            DnsRecord::NS(target) => Ok(ArvanRecordContent {
                record_type: "ns",
                value: serde_json::json!({ "host": target }),
            }),
            DnsRecord::MX(mx) => Ok(ArvanRecordContent {
                record_type: "mx",
                value: serde_json::json!({ "host": mx.exchange, "priority": mx.priority }),
            }),
            DnsRecord::TXT(text) => Ok(ArvanRecordContent {
                record_type: "txt",
                value: serde_json::json!({ "text": text }),
            }),
            DnsRecord::SRV(srv) => Ok(ArvanRecordContent {
                record_type: "srv",
                value: serde_json::json!({
                    "target": srv.target,
                    "priority": srv.priority,
                    "weight": srv.weight,
                    "port": srv.port,
                }),
            }),
            DnsRecord::TLSA(_) => Err(Error::Api(
                "TLSA records are not supported by ArvanCloud".to_string(),
            )),
            DnsRecord::CAA(caa) => {
                let (flags, tag, value) = caa.decompose();
                Ok(ArvanRecordContent {
                    record_type: "caa",
                    value: serde_json::json!({
                        "flag": flags,
                        "tag": tag,
                        "value": value,
                    }),
                })
            }
        }
    }
}
