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
    utils::txt_chunks_to_text,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api.hosting.ionos.com/dns";
const RETRY_ATTEMPTS: u32 = 3;

#[derive(Clone)]
pub struct IonosProvider {
    client: HttpClient,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordContent {
    content: String,
    priority: u16,
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
        let domain = origin.into_name().into_owned();
        let zone_id = self.find_zone_id(&domain).await?;
        let existing = self
            .list_records(&zone_id, &name, record_type.as_str())
            .await?;

        if records.is_empty() {
            for entry in existing {
                if let Some(id) = entry.id.as_deref() {
                    self.delete_record(&zone_id, id).await?;
                }
            }
            return Ok(());
        }

        let desired = build_contents(&records)?;
        let mut existing_pool = existing;
        let mut to_add: Vec<Record> = Vec::new();

        for (record, content) in records.iter().zip(desired.iter()) {
            if let Some(idx) = existing_pool
                .iter()
                .position(|r| record_to_content(r) == *content)
            {
                existing_pool.swap_remove(idx);
            } else {
                let mut payloads = build_records(record, &name, ttl)?;
                to_add.append(&mut payloads);
            }
        }

        for entry in existing_pool {
            if let Some(id) = entry.id.as_deref() {
                self.delete_record(&zone_id, id).await?;
            }
        }

        if !to_add.is_empty() {
            self.client
                .post(format!("{}/v1/zones/{}/records", self.endpoint, zone_id))
                .with_body(to_add)?
                .send_with_retry::<Value>(RETRY_ATTEMPTS)
                .await
                .map(|_| ())?;
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
        let domain = origin.into_name().into_owned();
        let zone_id = self.find_zone_id(&domain).await?;
        let existing = self
            .list_records(&zone_id, &name, record_type.as_str())
            .await?;
        let existing_contents: Vec<RecordContent> =
            existing.iter().map(record_to_content).collect();
        let desired = build_contents(&records)?;

        let mut to_add: Vec<Record> = Vec::new();
        for (record, content) in records.iter().zip(desired.iter()) {
            if existing_contents.iter().any(|c| c == content) {
                continue;
            }
            let mut payloads = build_records(record, &name, ttl)?;
            to_add.append(&mut payloads);
        }

        if !to_add.is_empty() {
            self.client
                .post(format!("{}/v1/zones/{}/records", self.endpoint, zone_id))
                .with_body(to_add)?
                .send_with_retry::<Value>(RETRY_ATTEMPTS)
                .await
                .map(|_| ())?;
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
        let domain = origin.into_name().into_owned();
        let zone_id = self.find_zone_id(&domain).await?;
        let existing = self
            .list_records(&zone_id, &name, record_type.as_str())
            .await?;
        let to_remove = build_contents(&records)?;

        for content in to_remove {
            if let Some(entry) = existing
                .iter()
                .find(|r| record_to_content(r) == content && r.id.is_some())
                && let Some(id) = entry.id.as_deref()
            {
                self.delete_record(&zone_id, id).await?;
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
        let domain = origin.into_name().into_owned();
        let zone_id = self.find_zone_id(&domain).await?;
        let existing = self
            .list_records(&zone_id, &name, record_type.as_str())
            .await?;
        existing
            .into_iter()
            .map(|r| record_from_api(&r, record_type))
            .collect()
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
            if (origin == zone.name || origin.ends_with(&format!(".{}", zone.name)))
                && best
                    .as_ref()
                    .map(|b| zone.name.len() > b.name.len())
                    .unwrap_or(true)
            {
                best = Some(zone);
            }
        }

        best.map(|z| z.id)
            .ok_or_else(|| Error::Api(format!("No IONOS zone found for {}", origin)))
    }

    async fn list_records(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
    ) -> crate::Result<Vec<Record>> {
        let query =
            serde_urlencoded::to_string([("recordName", name), ("recordType", record_type)])
                .map_err(|err| Error::Serialize(format!("Failed to encode IONOS query: {err}")))?;
        let zone = self
            .client
            .get(format!("{}/v1/zones/{}?{}", self.endpoint, zone_id, query))
            .send_with_retry::<CustomerZone>(RETRY_ATTEMPTS)
            .await?;
        Ok(zone
            .records
            .into_iter()
            .filter(|r| r.name == name && r.record_type.eq_ignore_ascii_case(record_type))
            .collect())
    }

    async fn delete_record(&self, zone_id: &str, record_id: &str) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/v1/zones/{}/records/{}",
                self.endpoint, zone_id, record_id
            ))
            .send_with_retry::<Value>(RETRY_ATTEMPTS)
            .await
            .map(|_| ())
    }
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
        if matches!(record, DnsRecord::TLSA(_)) {
            return Err(Error::Api(
                "TLSA records are not supported by IONOS".to_string(),
            ));
        }
    }
    Ok(())
}

fn build_contents(records: &[DnsRecord]) -> crate::Result<Vec<RecordContent>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        let payloads = build_records(record, "_", 0)?;
        for payload in payloads {
            out.push(RecordContent {
                content: payload.content,
                priority: payload.priority,
            });
        }
    }
    Ok(out)
}

fn record_to_content(record: &Record) -> RecordContent {
    RecordContent {
        content: record.content.clone(),
        priority: record.priority,
    }
}

fn build_records(record: &DnsRecord, name: &str, ttl: u32) -> crate::Result<Vec<Record>> {
    let (record_type, contents, priority) = match record {
        DnsRecord::A(addr) => ("A", vec![addr.to_string()], 0),
        DnsRecord::AAAA(addr) => ("AAAA", vec![addr.to_string()], 0),
        DnsRecord::CNAME(value) => ("CNAME", vec![value.clone()], 0),
        DnsRecord::NS(value) => ("NS", vec![value.clone()], 0),
        DnsRecord::MX(mx) => ("MX", vec![mx.exchange.clone()], mx.priority),
        DnsRecord::TXT(value) => {
            let mut buf = String::new();
            txt_chunks_to_text(&mut buf, value, " ");
            ("TXT", vec![buf], 0)
        }
        DnsRecord::SRV(srv) => (
            "SRV",
            vec![format!("{} {} {}", srv.weight, srv.port, srv.target)],
            srv.priority,
        ),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            (
                "CAA",
                vec![format!(
                    "{} {} \"{}\"",
                    flags,
                    tag,
                    value.replace('"', "\\\"")
                )],
                0,
            )
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by IONOS".to_string(),
            ));
        }
    };

    Ok(contents
        .into_iter()
        .map(|content| Record {
            id: None,
            name: name.to_string(),
            content,
            ttl,
            record_type: record_type.to_string(),
            priority,
            disabled: false,
        })
        .collect())
}

fn record_from_api(record: &Record, record_type: DnsRecordType) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => record
            .content
            .parse()
            .map(DnsRecord::A)
            .map_err(|err| Error::Parse(format!("invalid IONOS A record: {err}"))),
        DnsRecordType::AAAA => record
            .content
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|err| Error::Parse(format!("invalid IONOS AAAA record: {err}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(record.content.clone())),
        DnsRecordType::NS => Ok(DnsRecord::NS(record.content.clone())),
        DnsRecordType::MX => Ok(DnsRecord::MX(MXRecord {
            exchange: record.content.clone(),
            priority: record.priority,
        })),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(unquote_txt(&record.content))),
        DnsRecordType::SRV => parse_srv(&record.content, record.priority).map(DnsRecord::SRV),
        DnsRecordType::CAA => parse_caa(&record.content).map(DnsRecord::CAA),
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by IONOS".to_string(),
        )),
    }
}

fn unquote_txt(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut in_quotes = false;
    let mut escape = false;
    for ch in content.chars() {
        if escape {
            out.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escape = true,
            '"' => in_quotes = !in_quotes,
            _ => {
                if in_quotes {
                    out.push(ch);
                }
            }
        }
    }
    if out.is_empty() && !content.contains('"') {
        content.to_string()
    } else {
        out
    }
}

fn parse_srv(content: &str, priority: u16) -> crate::Result<SRVRecord> {
    let mut parts = content.split_whitespace();
    let weight = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("invalid IONOS SRV weight: {content}")))?;
    let port = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("invalid IONOS SRV port: {content}")))?;
    let target = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid IONOS SRV target: {content}")))?
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
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("invalid IONOS CAA flags: {content}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid IONOS CAA tag: {content}")))?;
    let value_raw = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid IONOS CAA value: {content}")))?;
    let value = value_raw
        .trim()
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .map(|s| s.replace("\\\"", "\""))
        .unwrap_or_else(|| value_raw.trim().to_string());
    let issuer_critical = flags & 0x80 != 0;
    match tag {
        "issue" => {
            let (name, options) = parse_caa_value(&value);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(&value);
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
        other => Err(Error::Parse(format!("unknown IONOS CAA tag: {other}"))),
    }
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
