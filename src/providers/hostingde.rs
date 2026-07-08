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

use crate::utils::parse_tlsa;
use crate::utils::split_caa_value;
use crate::utils::unquote_txt;
use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord,
    http::{HttpClient, HttpClientBuilder},
    utils::txt_chunks_to_text,
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, time::Duration};

const DEFAULT_ENDPOINT: &str = "https://secure.hosting.de/api/dns/v1/json";

#[derive(Clone)]
pub struct HostingDeProvider {
    client: HttpClient,
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
struct RecordsResponse {
    #[serde(default)]
    data: Vec<DnsRecordPayload>,
}

impl HostingDeProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default().with_timeout(timeout).build();
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

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let zone_config = self.fetch_zone_config(&domain).await?;
        let existing = self
            .fetch_records_at(&zone_config.id, &name, record_type.as_str())
            .await?;

        let desired: Vec<DnsRecordPayload> = records
            .iter()
            .map(|r| record_to_payload(r, &name, ttl))
            .collect::<crate::Result<_>>()?;

        let mut existing_pool = existing;
        let mut to_add: Vec<DnsRecordPayload> = Vec::new();

        for want in desired {
            if let Some(pos) = existing_pool.iter().position(|cur| same_rdata(cur, &want)) {
                existing_pool.swap_remove(pos);
            } else {
                to_add.push(want);
            }
        }

        if to_add.is_empty() && existing_pool.is_empty() {
            return Ok(());
        }

        let request = ZoneUpdateRequest {
            auth_token: &self.api_key,
            zone_config,
            records_to_add: to_add,
            records_to_delete: existing_pool,
        };
        self.zone_update(request).await
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let zone_config = self.fetch_zone_config(&domain).await?;
        let existing = self
            .fetch_records_at(&zone_config.id, &name, record_type.as_str())
            .await?;

        let mut to_add: Vec<DnsRecordPayload> = Vec::new();
        for record in &records {
            let payload = record_to_payload(record, &name, ttl)?;
            if existing.iter().any(|cur| same_rdata(cur, &payload)) {
                continue;
            }
            to_add.push(payload);
        }

        if to_add.is_empty() {
            return Ok(());
        }

        let request = ZoneUpdateRequest {
            auth_token: &self.api_key,
            zone_config,
            records_to_add: to_add,
            records_to_delete: vec![],
        };
        self.zone_update(request).await
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let zone_config = self.fetch_zone_config(&domain).await?;
        let existing = self
            .fetch_records_at(&zone_config.id, &name, record_type.as_str())
            .await?;

        let targets: Vec<DnsRecordPayload> = records
            .iter()
            .map(|r| record_to_payload(r, &name, 0))
            .collect::<crate::Result<_>>()?;

        let to_delete: Vec<DnsRecordPayload> = existing
            .into_iter()
            .filter(|cur| targets.iter().any(|t| same_rdata(cur, t)))
            .collect();

        if to_delete.is_empty() {
            return Ok(());
        }

        let request = ZoneUpdateRequest {
            auth_token: &self.api_key,
            zone_config,
            records_to_add: vec![],
            records_to_delete: to_delete,
        };
        self.zone_update(request).await
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let zone_config = self.fetch_zone_config(&domain).await?;
        let existing = self
            .fetch_records_at(&zone_config.id, &name, record_type.as_str())
            .await?;
        existing
            .into_iter()
            .map(|p| payload_to_record(&p))
            .collect()
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

        let mut zones = response.response.map(|r| r.data).unwrap_or_default();

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

    async fn fetch_records_at(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
    ) -> crate::Result<Vec<DnsRecordPayload>> {
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
            "limit": 100,
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

        let records = response.response.map(|r| r.data).unwrap_or_default();

        Ok(records
            .into_iter()
            .filter(|r| r.name == name && r.record_type.eq_ignore_ascii_case(record_type))
            .collect())
    }

    async fn zone_update(&self, request: ZoneUpdateRequest<'_>) -> crate::Result<()> {
        let response: BaseResponse<serde_json::Value> = self
            .client
            .post(format!("{}/zoneUpdate", self.endpoint))
            .with_body(request)?
            .send_with_retry(3)
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

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> crate::Result<()> {
    for r in records {
        if r.as_type() != expected {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected.as_str(),
                r.as_type().as_str(),
            )));
        }
    }
    Ok(())
}

fn same_rdata(a: &DnsRecordPayload, b: &DnsRecordPayload) -> bool {
    a.record_type.eq_ignore_ascii_case(&b.record_type)
        && a.content == b.content
        && a.priority == b.priority
}

fn record_to_payload(record: &DnsRecord, name: &str, ttl: u32) -> crate::Result<DnsRecordPayload> {
    let (record_type, content, priority) = match record {
        DnsRecord::A(addr) => ("A", addr.to_string(), 0u16),
        DnsRecord::AAAA(addr) => ("AAAA", addr.to_string(), 0),
        DnsRecord::CNAME(value) => ("CNAME", value.clone(), 0),
        DnsRecord::NS(value) => ("NS", value.clone(), 0),
        DnsRecord::MX(mx) => ("MX", mx.exchange.clone(), mx.priority),
        DnsRecord::TXT(value) => {
            let mut out = String::new();
            txt_chunks_to_text(&mut out, value, " ");
            ("TXT", out, 0)
        }
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
        DnsRecord::TLSA(tlsa) => ("TLSA", format!("{}", tlsa), 0),
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

fn payload_to_record(payload: &DnsRecordPayload) -> crate::Result<DnsRecord> {
    match payload.record_type.to_ascii_uppercase().as_str() {
        "A" => {
            let addr: IpAddr = payload
                .content
                .parse()
                .map_err(|e| Error::Parse(format!("invalid A content {}: {e}", payload.content)))?;
            match addr {
                IpAddr::V4(v4) => Ok(DnsRecord::A(v4)),
                IpAddr::V6(_) => Err(Error::Parse(format!(
                    "expected IPv4 for A record, got {}",
                    payload.content
                ))),
            }
        }
        "AAAA" => {
            let addr: IpAddr = payload.content.parse().map_err(|e| {
                Error::Parse(format!("invalid AAAA content {}: {e}", payload.content))
            })?;
            match addr {
                IpAddr::V6(v6) => Ok(DnsRecord::AAAA(v6)),
                IpAddr::V4(_) => Err(Error::Parse(format!(
                    "expected IPv6 for AAAA record, got {}",
                    payload.content
                ))),
            }
        }
        "CNAME" => Ok(DnsRecord::CNAME(payload.content.clone())),
        "NS" => Ok(DnsRecord::NS(payload.content.clone())),
        "MX" => Ok(DnsRecord::MX(MXRecord {
            exchange: payload.content.clone(),
            priority: payload.priority,
        })),
        "TXT" => Ok(DnsRecord::TXT(unquote_txt(&payload.content))),
        "SRV" => parse_srv(&payload.content, payload.priority).map(DnsRecord::SRV),
        "CAA" => parse_caa(&payload.content).map(DnsRecord::CAA),
        "TLSA" => parse_tlsa(&payload.content),
        other => Err(Error::Parse(format!("unsupported record type: {other}"))),
    }
}

fn parse_srv(content: &str, priority: u16) -> crate::Result<SRVRecord> {
    let mut parts = content.split_ascii_whitespace();
    let weight: u16 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV content: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV weight: {e}")))?;
    let port: u16 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV content: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV port: {e}")))?;
    let target = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV content: {content}")))?
        .to_string();
    Ok(SRVRecord {
        priority,
        weight,
        port,
        target,
    })
}

fn parse_caa(content: &str) -> crate::Result<CAARecord> {
    let mut parts = content.splitn(3, ' ');
    let flags: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA content: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags: {e}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA content: {content}")))?;
    let raw_value = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA content: {content}")))?;
    let value = strip_quotes(raw_value).replace("\\\"", "\"");
    let issuer_critical = flags & 0x80 != 0;
    match tag {
        "issue" => {
            let (name, options) = split_caa_value(&value);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = split_caa_value(&value);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: value,
        }),
        other => Err(Error::Parse(format!("unknown CAA tag: {other}"))),
    }
}

fn strip_quotes(s: &str) -> String {
    s.strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .unwrap_or(s)
        .to_string()
}
