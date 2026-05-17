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

const DEFAULT_ENDPOINT: &str = "https://secure.hosting.de/api/dns/v1/json";

#[derive(Clone)]
pub struct HostingDeProvider {
    client: HttpClientBuilder,
    endpoint: String,
    api_key: String,
}

#[derive(Serialize, Debug)]
struct ZoneConfigsFindRequest<'a> {
    #[serde(rename = "authToken")]
    auth_token: &'a str,
    filter: Filter<'a>,
    limit: u32,
    page: u32,
}

#[derive(Serialize, Debug)]
struct Filter<'a> {
    field: &'a str,
    value: &'a str,
}

#[derive(Serialize, Debug)]
struct ZoneUpdateRequest<'a> {
    #[serde(rename = "authToken")]
    auth_token: &'a str,
    #[serde(rename = "zoneConfig")]
    zone_config: ZoneConfig,
    #[serde(rename = "recordsToAdd", skip_serializing_if = "Vec::is_empty")]
    records_to_add: Vec<DnsRecordPayload>,
    #[serde(rename = "recordsToDelete", skip_serializing_if = "Vec::is_empty")]
    records_to_delete: Vec<DnsRecordPayload>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ZoneConfig {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    status: String,
    #[serde(default, flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct DnsRecordPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    record_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    content: String,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    ttl: u32,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    priority: u16,
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

#[derive(Deserialize, Debug)]
struct BaseResponse<T> {
    #[serde(default)]
    status: String,
    #[serde(default)]
    errors: Vec<ApiError>,
    response: Option<T>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ApiError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    text: String,
}

#[derive(Deserialize, Debug)]
struct ZoneResponse {
    #[serde(default)]
    data: Vec<ZoneConfig>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Zone {
    #[serde(default)]
    records: Vec<DnsRecordPayload>,
    #[serde(rename = "zoneConfig", default)]
    zone_config: Option<ZoneConfig>,
}

impl HostingDeProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default().with_timeout(timeout);
        Self {
            client,
            endpoint: DEFAULT_ENDPOINT.to_string(),
            api_key: api_key.as_ref().to_string(),
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
        let zone_config = self.fetch_zone_config(&domain).await?;
        let payload = record_to_payload(&record, &name, ttl)?;

        let request = ZoneUpdateRequest {
            auth_token: &self.api_key,
            zone_config,
            records_to_add: vec![payload],
            records_to_delete: vec![],
        };

        self.zone_update(request).await
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
        let zone_config = self.fetch_zone_config(&domain).await?;
        let new_record = record_to_payload(&record, &name, ttl)?;
        let record_type = record.as_type();
        let existing = self
            .fetch_existing_record(&zone_config.id, &name, record_type.as_str())
            .await?;

        let request = ZoneUpdateRequest {
            auth_token: &self.api_key,
            zone_config,
            records_to_add: vec![new_record],
            records_to_delete: vec![existing],
        };

        self.zone_update(request).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let zone_config = self.fetch_zone_config(&domain).await?;
        let existing = self
            .fetch_existing_record(&zone_config.id, &name, record_type.as_str())
            .await?;

        let request = ZoneUpdateRequest {
            auth_token: &self.api_key,
            zone_config,
            records_to_add: vec![],
            records_to_delete: vec![existing],
        };

        self.zone_update(request).await
    }

    async fn fetch_zone_config(&self, zone_name: &str) -> crate::Result<ZoneConfig> {
        let body = ZoneConfigsFindRequest {
            auth_token: &self.api_key,
            filter: Filter {
                field: "zoneName",
                value: zone_name,
            },
            limit: 1,
            page: 1,
        };

        let response: BaseResponse<ZoneResponse> = self
            .client
            .post(format!("{}/zoneConfigsFind", self.endpoint))
            .with_body(body)?
            .send()
            .await?;

        if response.status != "success" && response.status != "pending" {
            return Err(Error::Api(format!(
                "hosting.de: unexpected status: {} {:?}",
                response.status, response.errors
            )));
        }

        let mut zones = response
            .response
            .map(|r| r.data)
            .unwrap_or_default();

        if zones.is_empty() {
            return Err(Error::Api(format!(
                "hosting.de: zone {} not found",
                zone_name
            )));
        }

        let mut config = zones.remove(0);
        if config.status != "active" {
            return Err(Error::Api(format!(
                "hosting.de: zone {} is not active (status={})",
                zone_name, config.status
            )));
        }
        config.name = zone_name.to_string();
        Ok(config)
    }

    async fn fetch_existing_record(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
    ) -> crate::Result<DnsRecordPayload> {
        let body = serde_json::json!({
            "authToken": &self.api_key,
            "filter": {
                "subFilterConnective": "AND",
                "subFilter": [
                    { "field": "zoneConfigId", "value": zone_id },
                    { "field": "recordName", "value": name },
                    { "field": "recordType", "value": record_type },
                ],
            },
            "limit": 25,
            "page": 1,
        });

        let response: BaseResponse<RecordsResponse> = self
            .client
            .post(format!("{}/recordsFind", self.endpoint))
            .with_body(body)?
            .send()
            .await?;

        if response.status != "success" && response.status != "pending" {
            return Err(Error::Api(format!(
                "hosting.de: unexpected status: {} {:?}",
                response.status, response.errors
            )));
        }

        let records = response
            .response
            .map(|r| r.data)
            .unwrap_or_default();

        records
            .into_iter()
            .find(|r| {
                r.name == name && r.record_type.eq_ignore_ascii_case(record_type)
            })
            .ok_or_else(|| {
                Error::Api(format!(
                    "DNS Record {} of type {} not found in hosting.de zone",
                    name, record_type
                ))
            })
    }

    async fn zone_update(&self, request: ZoneUpdateRequest<'_>) -> crate::Result<()> {
        let response: BaseResponse<serde_json::Value> = self
            .client
            .post(format!("{}/zoneUpdate", self.endpoint))
            .with_body(request)?
            .send()
            .await?;

        if response.status != "success" && response.status != "pending" {
            return Err(Error::Api(format!(
                "hosting.de: unexpected status: {} {:?}",
                response.status, response.errors
            )));
        }

        Ok(())
    }
}

#[derive(Deserialize, Debug)]
struct RecordsResponse {
    #[serde(default)]
    data: Vec<DnsRecordPayload>,
}

fn record_to_payload(record: &DnsRecord, name: &str, ttl: u32) -> crate::Result<DnsRecordPayload> {
    let (record_type, content, priority) = match record {
        DnsRecord::A(addr) => ("A", addr.to_string(), 0u16),
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
                "TLSA records are not supported by hosting.de".to_string(),
            ));
        }
    };

    Ok(DnsRecordPayload {
        id: None,
        name: name.to_string(),
        record_type: record_type.to_string(),
        content,
        ttl,
        priority,
    })
}
