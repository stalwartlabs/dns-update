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
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord,
    http::{HttpClient, HttpClientBuilder},
    utils::{
        build_caa, parse_srv, parse_tlsa, strip_origin_from_name, strip_trailing_dot, unquote_txt,
    },
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://dns.de-fra.ionos.com";
const RETRY_ATTEMPTS: u32 = 3;

#[derive(Clone)]
pub struct IonosCloudProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Deserialize)]
struct ZoneCollection {
    items: Vec<Zone>,
    #[serde(default)]
    pagination: Option<Pagination>,
}

#[derive(Deserialize)]
struct Zone {
    id: String,
    properties: ZoneProperties,
}

#[derive(Deserialize)]
struct ZoneProperties {
    #[serde(rename = "zoneName")]
    zone_name: String,
}

#[derive(Deserialize)]
struct RecordCollection {
    items: Vec<ApiRecord>,
    #[serde(default)]
    pagination: Option<Pagination>,
}

#[derive(Deserialize)]
struct ApiRecord {
    id: String,
    properties: RecordProperties,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordProperties {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
    #[serde(default = "default_ttl")]
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

#[derive(Deserialize)]
struct Pagination {
    token: String,
}

#[derive(Deserialize)]
struct EmptyResponse {}

impl IonosCloudProvider {
    pub(crate) fn new(api_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", api_token.as_ref()))
            .with_header("Accept", "application/json")
            .with_timeout(timeout)
            .build();
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
        let origin = origin.into_name().into_owned();
        let zone = self.find_zone(&name, &origin).await?;
        let subdomain = subdomain(&name, &zone.properties.zone_name)?;
        let mut existing = self
            .list_records(&zone.id, &subdomain, record_type)
            .await?
            .into_iter()
            .map(|record| {
                let value = normalize_record(record_from_api(&record.properties, record_type)?);
                Ok((record, value))
            })
            .collect::<crate::Result<Vec<_>>>()?;
        let mut desired = Vec::new();
        for record in &records {
            let properties = build_record(record, &subdomain, ttl)?;
            let value = normalize_record(record_from_api(&properties, record_type)?);
            if !desired.iter().any(|(_, existing)| existing == &value) {
                desired.push((properties, value));
            }
        }

        let mut unmatched = Vec::new();
        for (properties, value) in desired {
            if let Some(index) = existing.iter().position(|(_, current)| *current == value) {
                let (record, _) = existing.swap_remove(index);
                if record.properties.ttl != properties.ttl || !record.properties.enabled {
                    self.update_record(&zone.id, &record.id, properties).await?;
                }
            } else {
                unmatched.push(properties);
            }
        }

        for properties in unmatched {
            if let Some((record, _)) = existing.pop() {
                self.update_record(&zone.id, &record.id, properties).await?;
            } else {
                self.create_record(&zone.id, properties).await?;
            }
        }

        for (record, _) in existing {
            self.delete_record(&zone.id, &record.id).await?;
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
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }

        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let zone = self.find_zone(&name, &origin).await?;
        let subdomain = subdomain(&name, &zone.properties.zone_name)?;
        let existing = self
            .list_records(&zone.id, &subdomain, record_type)
            .await?
            .into_iter()
            .map(|record| {
                let value = normalize_record(record_from_api(&record.properties, record_type)?);
                Ok((record, value))
            })
            .collect::<crate::Result<Vec<_>>>()?;
        let desired = records
            .iter()
            .map(|record| {
                let properties = build_record(record, &subdomain, ttl)?;
                let value = normalize_record(record_from_api(&properties, record_type)?);
                Ok((properties, value))
            })
            .collect::<crate::Result<Vec<_>>>()?;
        let mut added = Vec::new();

        for (properties, value) in desired {
            if added.contains(&value) {
                continue;
            }
            if existing
                .iter()
                .any(|(entry, current)| *current == value && entry.properties.enabled)
            {
                added.push(value);
                continue;
            }

            if let Some(record_id) = existing
                .iter()
                .find(|(_, current)| *current == value)
                .map(|(entry, _)| &entry.id)
            {
                self.update_record(&zone.id, record_id, properties).await?;
            } else {
                self.create_record(&zone.id, properties).await?;
            }
            added.push(value);
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
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }

        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let zone = self.find_zone(&name, &origin).await?;
        let subdomain = subdomain(&name, &zone.properties.zone_name)?;
        let existing = self
            .list_records(&zone.id, &subdomain, record_type)
            .await?
            .into_iter()
            .map(|record| {
                let value = normalize_record(record_from_api(&record.properties, record_type)?);
                Ok((record, value))
            })
            .collect::<crate::Result<Vec<_>>>()?;
        let desired = records
            .iter()
            .map(|record| {
                let properties = build_record(record, &subdomain, 0)?;
                record_from_api(&properties, record_type).map(normalize_record)
            })
            .collect::<crate::Result<Vec<_>>>()?;

        for (entry, value) in existing {
            if desired.contains(&value) {
                self.delete_record(&zone.id, &entry.id).await?;
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
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let zone = self.find_zone(&name, &origin).await?;
        let subdomain = subdomain(&name, &zone.properties.zone_name)?;
        self.list_records(&zone.id, &subdomain, record_type)
            .await?
            .iter()
            .map(|record| record_from_api(&record.properties, record_type))
            .collect()
    }

    async fn find_zone(&self, name: &str, origin: &str) -> crate::Result<Zone> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let origin = origin.trim_end_matches('.').to_ascii_lowercase();
        if !is_within_zone(&name, &origin) {
            return Err(Error::Api(format!(
                "DNS name {name} is not within origin {origin}"
            )));
        }
        let mut token: Option<String> = None;
        let mut best: Option<Zone> = None;

        loop {
            let query = match token.as_deref() {
                Some(token) => {
                    serde_urlencoded::to_string([("limit", "1000"), ("pagination.token", token)])
                }
                None => serde_urlencoded::to_string([("limit", "1000")]),
            }
            .map_err(|err| {
                Error::Serialize(format!("Failed to encode IONOS Cloud query: {err}"))
            })?;
            let mut page = self
                .client
                .get(format!("{}/zones?{}", self.endpoint, query))
                .send_with_retry::<ZoneCollection>(RETRY_ATTEMPTS)
                .await?;

            for zone in page.items.drain(..) {
                let zone_name = zone
                    .properties
                    .zone_name
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if is_within_zone(&name, &zone_name)
                    && best
                        .as_ref()
                        .map(|candidate| {
                            zone_name.len()
                                > candidate.properties.zone_name.trim_end_matches('.').len()
                        })
                        .unwrap_or(true)
                {
                    best = Some(zone);
                }
            }

            token = page.pagination.map(|pagination| pagination.token);
            if token.is_none() {
                break;
            }
        }

        best.ok_or_else(|| Error::Api(format!("No IONOS Cloud DNS zone found for {name}")))
    }

    async fn list_records(
        &self,
        zone_id: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ApiRecord>> {
        let mut token: Option<String> = None;
        let mut records = Vec::new();

        loop {
            let query = match token.as_deref() {
                Some(token) => {
                    serde_urlencoded::to_string([("limit", "1000"), ("pagination.token", token)])
                }
                None => serde_urlencoded::to_string([("limit", "1000")]),
            }
            .map_err(|err| {
                Error::Serialize(format!("Failed to encode IONOS Cloud query: {err}"))
            })?;
            let mut page = self
                .client
                .get(format!(
                    "{}/zones/{}/records?{}",
                    self.endpoint, zone_id, query
                ))
                .send_with_retry::<RecordCollection>(RETRY_ATTEMPTS)
                .await?;

            records.extend(page.items.drain(..).filter(|record| {
                same_subdomain(&record.properties.name, subdomain)
                    && record
                        .properties
                        .record_type
                        .eq_ignore_ascii_case(record_type.as_str())
            }));

            token = page.pagination.map(|pagination| pagination.token);
            if token.is_none() {
                break;
            }
        }

        Ok(records)
    }

    async fn create_record(
        &self,
        zone_id: &str,
        properties: RecordProperties,
    ) -> crate::Result<()> {
        self.client
            .post(format!("{}/zones/{zone_id}/records", self.endpoint))
            .with_body(RecordBody { properties })?
            .send_with_retry::<ApiRecord>(RETRY_ATTEMPTS)
            .await
            .map(|_| ())
    }

    async fn update_record(
        &self,
        zone_id: &str,
        record_id: &str,
        properties: RecordProperties,
    ) -> crate::Result<()> {
        self.client
            .put(format!(
                "{}/zones/{zone_id}/records/{record_id}",
                self.endpoint
            ))
            .with_body(RecordBody { properties })?
            .send_with_retry::<ApiRecord>(RETRY_ATTEMPTS)
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, zone_id: &str, record_id: &str) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/zones/{zone_id}/records/{record_id}",
                self.endpoint
            ))
            .send_with_retry::<EmptyResponse>(RETRY_ATTEMPTS)
            .await
            .map(|_| ())
    }
}

#[derive(Serialize)]
struct RecordBody {
    properties: RecordProperties,
}

fn default_ttl() -> u32 {
    3600
}

fn default_enabled() -> bool {
    true
}

fn is_within_zone(name: &str, zone: &str) -> bool {
    !zone.is_empty() && (name == zone || name.ends_with(&format!(".{zone}")))
}

fn subdomain(name: &str, zone_name: &str) -> crate::Result<String> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let zone_name = zone_name.trim_end_matches('.').to_ascii_lowercase();
    if is_within_zone(&name, &zone_name) {
        return Ok(strip_origin_from_name(&name, &zone_name, Some("")));
    }
    Err(Error::Api(format!(
        "DNS name {name} is not within IONOS Cloud DNS zone {zone_name}"
    )))
}

fn same_subdomain(name: &str, subdomain: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let subdomain = subdomain.trim_end_matches('.').to_ascii_lowercase();
    name == subdomain || (subdomain.is_empty() && name == "@")
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

fn normalize_record(mut record: DnsRecord) -> DnsRecord {
    let hostname = match &mut record {
        DnsRecord::CNAME(name) | DnsRecord::NS(name) => Some(name),
        DnsRecord::MX(record) => Some(&mut record.exchange),
        DnsRecord::SRV(record) => Some(&mut record.target),
        _ => None,
    };
    if let Some(hostname) = hostname {
        *hostname = strip_trailing_dot(hostname).to_ascii_lowercase();
    }
    record
}

pub(crate) fn build_record(
    record: &DnsRecord,
    subdomain: &str,
    ttl: u32,
) -> crate::Result<RecordProperties> {
    let (content, priority) = match record {
        DnsRecord::A(address) => (address.to_string(), None),
        DnsRecord::AAAA(address) => (address.to_string(), None),
        DnsRecord::CNAME(target) | DnsRecord::NS(target) => {
            (strip_trailing_dot(target).to_string(), None)
        }
        DnsRecord::MX(record) => (
            strip_trailing_dot(&record.exchange).to_string(),
            Some(record.priority),
        ),
        DnsRecord::TXT(content) => (content.clone(), None),
        DnsRecord::SRV(record) => (
            format!(
                "{} {} {}",
                record.weight,
                record.port,
                strip_trailing_dot(&record.target)
            ),
            Some(record.priority),
        ),
        DnsRecord::TLSA(record) => (record.to_string(), None),
        DnsRecord::CAA(record) => (record.to_string(), None),
    };

    Ok(RecordProperties {
        name: subdomain.to_string(),
        record_type: record.as_type().as_str().to_string(),
        content,
        ttl: ttl.clamp(60, 604_800),
        priority,
        enabled: true,
    })
}

pub(crate) fn record_from_api(
    record: &RecordProperties,
    record_type: DnsRecordType,
) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => record
            .content
            .parse()
            .map(DnsRecord::A)
            .map_err(|err| Error::Parse(format!("invalid IONOS Cloud A record: {err}"))),
        DnsRecordType::AAAA => record
            .content
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|err| Error::Parse(format!("invalid IONOS Cloud AAAA record: {err}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(
            strip_trailing_dot(&record.content).to_string(),
        )),
        DnsRecordType::NS => Ok(DnsRecord::NS(
            strip_trailing_dot(&record.content).to_string(),
        )),
        DnsRecordType::MX => Ok(DnsRecord::MX(MXRecord {
            exchange: strip_trailing_dot(&record.content).to_string(),
            priority: record.priority.ok_or_else(|| {
                Error::Parse("IONOS Cloud MX record is missing priority".to_string())
            })?,
        })),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(record.content.clone())),
        DnsRecordType::SRV => {
            let priority = record.priority.ok_or_else(|| {
                Error::Parse("IONOS Cloud SRV record is missing priority".to_string())
            })?;
            parse_srv(&format!("{priority} {}", record.content))
        }
        DnsRecordType::TLSA => parse_tlsa(&record.content),
        DnsRecordType::CAA => parse_caa(&record.content).map(DnsRecord::CAA),
    }
}

fn parse_caa(content: &str) -> crate::Result<CAARecord> {
    let (flags, rest) = content
        .trim_start()
        .split_once(char::is_whitespace)
        .ok_or_else(|| Error::Parse(format!("invalid IONOS Cloud CAA flags: {content}")))?;
    let flags = flags
        .parse::<u8>()
        .ok()
        .ok_or_else(|| Error::Parse(format!("invalid IONOS Cloud CAA flags: {content}")))?;
    let (tag, raw_value) = rest
        .trim_start()
        .split_once(char::is_whitespace)
        .ok_or_else(|| Error::Parse(format!("invalid IONOS Cloud CAA tag: {content}")))?;
    let raw_value = raw_value.trim_start();
    let raw_value = (!raw_value.is_empty())
        .then_some(raw_value)
        .ok_or_else(|| Error::Parse(format!("invalid IONOS Cloud CAA value: {content}")))?;
    let value = if raw_value.starts_with('"') && raw_value.ends_with('"') {
        unquote_txt(raw_value)
    } else {
        raw_value.to_string()
    };
    build_caa(flags, tag, &value)
}
