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
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api.netlify.com/api/v1";

#[derive(Clone)]
pub struct NetlifyProvider {
    client: HttpClient,
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
    #[serde(default)]
    ttl: u32,
    #[serde(default)]
    priority: Option<u16>,
    #[serde(default)]
    weight: Option<u16>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    flag: Option<u8>,
    #[serde(default)]
    tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordContent {
    value: String,
    priority: Option<u16>,
    weight: Option<u16>,
    port: Option<u16>,
    flag: Option<u8>,
    tag: Option<String>,
}

impl NetlifyProvider {
    pub(crate) fn new(access_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", access_token.as_ref()))
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
        reject_tlsa(record_type)?;
        let name = name.into_name().into_owned();
        let zone_id = zone_id_from_origin(&origin.into_name());

        let desired = build_contents(&records)?;
        let mut existing = self.list_at(&zone_id, &name, record_type.as_str()).await?;

        let mut to_add: Vec<RecordContent> = Vec::new();
        for content in desired {
            if let Some(idx) = existing
                .iter()
                .position(|r| listed_to_content(r) == content)
            {
                existing.swap_remove(idx);
            } else {
                to_add.push(content);
            }
        }

        for entry in existing {
            self.delete_by_id(&zone_id, &entry.id).await?;
        }
        for content in to_add {
            self.post_content(&zone_id, &name, record_type.as_str(), ttl, &content)
                .await?;
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
        reject_tlsa(record_type)?;
        let name = name.into_name().into_owned();
        let zone_id = zone_id_from_origin(&origin.into_name());

        let desired = build_contents(&records)?;
        let existing = self.list_at(&zone_id, &name, record_type.as_str()).await?;

        for content in desired {
            if existing.iter().any(|r| listed_to_content(r) == content) {
                continue;
            }
            self.post_content(&zone_id, &name, record_type.as_str(), ttl, &content)
                .await?;
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
        reject_tlsa(record_type)?;
        let name = name.into_name().into_owned();
        let zone_id = zone_id_from_origin(&origin.into_name());

        let to_remove = build_contents(&records)?;
        let existing = self.list_at(&zone_id, &name, record_type.as_str()).await?;

        for content in to_remove {
            if let Some(entry) = existing.iter().find(|r| listed_to_content(r) == content) {
                self.delete_by_id(&zone_id, &entry.id).await?;
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
        reject_tlsa(record_type)?;
        let name = name.into_name().into_owned();
        let zone_id = zone_id_from_origin(&origin.into_name());
        let existing = self.list_at(&zone_id, &name, record_type.as_str()).await?;
        existing
            .into_iter()
            .map(|r| listed_to_record(record_type, &r))
            .collect()
    }

    async fn list_all(&self, zone_id: &str) -> crate::Result<Vec<ListedRecord>> {
        self.client
            .get(format!(
                "{}/dns_zones/{}/dns_records",
                self.endpoint, zone_id
            ))
            .send()
            .await
    }

    async fn list_at(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
    ) -> crate::Result<Vec<ListedRecord>> {
        let records = self.list_all(zone_id).await?;
        Ok(records
            .into_iter()
            .filter(|r| {
                r.hostname.trim_end_matches('.').eq_ignore_ascii_case(name)
                    && r.record_type.eq_ignore_ascii_case(record_type)
            })
            .collect())
    }

    async fn delete_by_id(&self, zone_id: &str, record_id: &str) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/dns_zones/{}/dns_records/{}",
                self.endpoint, zone_id, record_id
            ))
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }

    async fn post_content(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
        ttl: u32,
        content: &RecordContent,
    ) -> crate::Result<()> {
        let payload = CreateRecord {
            hostname: name,
            record_type,
            value: content.value.clone(),
            ttl,
            priority: content.priority,
            weight: content.weight,
            port: content.port,
            flag: content.flag,
            tag: content.tag.clone(),
        };
        self.client
            .post(format!(
                "{}/dns_zones/{}/dns_records",
                self.endpoint, zone_id
            ))
            .with_body(payload)?
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }
}

fn zone_id_from_origin(origin: &str) -> String {
    origin.trim_end_matches('.').replace('.', "_")
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

fn reject_tlsa(record_type: DnsRecordType) -> crate::Result<()> {
    if record_type == DnsRecordType::TLSA {
        return Err(Error::Api(
            "TLSA records are not supported by Netlify".to_string(),
        ));
    }
    Ok(())
}

fn build_contents(records: &[DnsRecord]) -> crate::Result<Vec<RecordContent>> {
    records.iter().map(record_to_content).collect()
}

fn record_to_content(record: &DnsRecord) -> crate::Result<RecordContent> {
    let mut content = RecordContent {
        value: String::new(),
        priority: None,
        weight: None,
        port: None,
        flag: None,
        tag: None,
    };
    match record {
        DnsRecord::A(addr) => content.value = addr.to_string(),
        DnsRecord::AAAA(addr) => content.value = addr.to_string(),
        DnsRecord::CNAME(value) => content.value = value.clone(),
        DnsRecord::NS(value) => content.value = value.clone(),
        DnsRecord::MX(mx) => {
            content.value = mx.exchange.clone();
            content.priority = Some(mx.priority);
        }
        DnsRecord::TXT(value) => content.value = value.clone(),
        DnsRecord::SRV(srv) => {
            content.value = srv.target.clone();
            content.priority = Some(srv.priority);
            content.weight = Some(srv.weight);
            content.port = Some(srv.port);
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            content.flag = Some(flags);
            content.tag = Some(tag);
            content.value = value;
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Netlify".to_string(),
            ));
        }
    }
    Ok(content)
}

fn listed_to_content(r: &ListedRecord) -> RecordContent {
    RecordContent {
        value: r.value.clone(),
        priority: r.priority,
        weight: r.weight,
        port: r.port,
        flag: r.flag,
        tag: r.tag.clone(),
    }
}

fn listed_to_record(record_type: DnsRecordType, r: &ListedRecord) -> crate::Result<DnsRecord> {
    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(
            r.value
                .parse()
                .map_err(|e| Error::Parse(format!("invalid A record value {}: {}", r.value, e)))?,
        ),
        DnsRecordType::AAAA => {
            DnsRecord::AAAA(r.value.parse().map_err(|e| {
                Error::Parse(format!("invalid AAAA record value {}: {}", r.value, e))
            })?)
        }
        DnsRecordType::CNAME => DnsRecord::CNAME(r.value.clone()),
        DnsRecordType::NS => DnsRecord::NS(r.value.clone()),
        DnsRecordType::MX => DnsRecord::MX(MXRecord {
            exchange: r.value.clone(),
            priority: r.priority.unwrap_or(0),
        }),
        DnsRecordType::TXT => DnsRecord::TXT(r.value.clone()),
        DnsRecordType::SRV => DnsRecord::SRV(SRVRecord {
            target: r.value.clone(),
            priority: r.priority.unwrap_or(0),
            weight: r.weight.unwrap_or(0),
            port: r.port.unwrap_or(0),
        }),
        DnsRecordType::CAA => DnsRecord::CAA(build_caa(r)?),
        DnsRecordType::TLSA => {
            return Err(Error::Api(
                "TLSA records are not supported by Netlify".to_string(),
            ));
        }
    })
}

fn build_caa(r: &ListedRecord) -> crate::Result<CAARecord> {
    let flags = r.flag.unwrap_or(0);
    let tag = r.tag.clone().unwrap_or_default();
    let issuer_critical = flags & 0x80 != 0;
    match tag.as_str() {
        "issue" => {
            let (name, options) = parse_caa_value(&r.value);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(&r.value);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: r.value.clone(),
        }),
        other => Err(Error::Parse(format!("unknown CAA tag: {other}"))),
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
