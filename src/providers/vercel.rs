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
    utils::strip_origin_from_name,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, time::Duration};

const DEFAULT_API_ENDPOINT: &str = "https://api.vercel.com";
const LIST_PAGE_LIMIT: u32 = 100;

#[derive(Clone)]
pub struct VercelProvider {
    client: HttpClient,
    endpoint: Cow<'static, str>,
    team_id: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ListRecordsResponse {
    records: Vec<ListedRecord>,
    #[serde(default)]
    pagination: Pagination,
}

#[derive(Deserialize, Debug, Default)]
struct Pagination {
    #[serde(default)]
    next: Option<u64>,
}

#[derive(Deserialize, Debug, Clone)]
struct ListedRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default)]
    value: Option<String>,
    #[serde(default, rename = "mxPriority")]
    mx_priority: Option<u16>,
    #[serde(default)]
    srv: Option<SrvData>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
struct SrvData {
    priority: u16,
    weight: u16,
    port: u16,
    target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VercelContent {
    Value(String),
    Mx { value: String, priority: u16 },
    Srv(SrvData),
}

#[derive(Serialize, Debug)]
struct CreateBody<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<&'a str>,
    ttl: u32,
    #[serde(rename = "mxPriority", skip_serializing_if = "Option::is_none")]
    mx_priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    srv: Option<&'a SrvData>,
}

impl VercelProvider {
    pub(crate) fn new(
        auth_token: impl AsRef<str>,
        team_id: Option<impl AsRef<str>>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", auth_token.as_ref()))
            .with_timeout(timeout)
            .build();
        Self {
            client,
            endpoint: Cow::Borrowed(DEFAULT_API_ENDPOINT),
            team_id: team_id.map(|t| t.as_ref().to_string()),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl Into<Cow<'static, str>>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..self
        }
    }

    fn append_team_query(&self, mut url: String) -> String {
        if let Some(team_id) = &self.team_id {
            if url.contains('?') {
                url.push('&');
            } else {
                url.push('?');
            }
            url.push_str("teamId=");
            url.push_str(team_id);
        }
        url
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let domain = origin.into_name().into_owned();
        let name = name.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let desired = build_contents(record_type, records)?;
        let existing = self.list_at(&domain, &subdomain, record_type).await?;

        let mut existing_pool: Vec<(String, VercelContent)> = existing
            .into_iter()
            .filter_map(|r| {
                let id = r.id.clone();
                listed_to_content(&r, record_type).map(|c| (id, c))
            })
            .collect();
        let mut to_add: Vec<VercelContent> = Vec::new();

        for content in desired {
            if let Some(idx) = existing_pool.iter().position(|(_, c)| *c == content) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(content);
            }
        }

        for (id, _) in existing_pool {
            self.delete_record(&domain, &id).await?;
        }
        for content in to_add {
            self.create_record(&domain, &subdomain, record_type, ttl, &content)
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
        if records.is_empty() {
            return Ok(());
        }
        let domain = origin.into_name().into_owned();
        let name = name.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let desired = build_contents(record_type, records)?;
        let existing = self.list_at(&domain, &subdomain, record_type).await?;
        let mut effective: Vec<VercelContent> = existing
            .iter()
            .filter_map(|r| listed_to_content(r, record_type))
            .collect();

        for content in desired {
            if effective.contains(&content) {
                continue;
            }
            self.create_record(&domain, &subdomain, record_type, ttl, &content)
                .await?;
            effective.push(content);
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
        if records.is_empty() {
            return Ok(());
        }
        let domain = origin.into_name().into_owned();
        let name = name.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let to_remove = build_contents(record_type, records)?;
        let existing = self.list_at(&domain, &subdomain, record_type).await?;
        let existing_pairs: Vec<(String, VercelContent)> = existing
            .into_iter()
            .filter_map(|r| {
                let id = r.id.clone();
                listed_to_content(&r, record_type).map(|c| (id, c))
            })
            .collect();

        for content in to_remove {
            if let Some((id, _)) = existing_pairs.iter().find(|(_, c)| *c == content) {
                self.delete_record(&domain, id).await?;
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
        if record_type == DnsRecordType::TLSA {
            return Err(Error::Api(
                "TLSA records are not supported by Vercel".to_string(),
            ));
        }
        let domain = origin.into_name().into_owned();
        let name = name.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let listed = self.list_at(&domain, &subdomain, record_type).await?;
        listed
            .into_iter()
            .map(|r| listed_to_dns_record(&r, record_type))
            .collect()
    }

    async fn list_at(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ListedRecord>> {
        let wanted_type = record_type.as_str();
        let mut out: Vec<ListedRecord> = Vec::new();
        let mut until: Option<u64> = None;
        loop {
            let mut url = format!(
                "{}/v5/domains/{domain}/records?limit={LIST_PAGE_LIMIT}",
                self.endpoint
            );
            if let Some(cursor) = until {
                url.push_str("&until=");
                url.push_str(&cursor.to_string());
            }
            url = self.append_team_query(url);

            let response: ListRecordsResponse = self.client.get(url).send_with_retry(3).await?;
            for record in response.records {
                if record.name == subdomain && record.record_type == wanted_type {
                    out.push(record);
                }
            }
            match response.pagination.next {
                Some(cursor) => until = Some(cursor),
                None => break,
            }
        }
        Ok(out)
    }

    async fn create_record(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
        content: &VercelContent,
    ) -> crate::Result<()> {
        let body = build_create_body(subdomain, record_type, ttl, content);
        let url = self.append_team_query(format!("{}/v2/domains/{domain}/records", self.endpoint));
        self.client
            .post(url)
            .with_body(body)?
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, domain: &str, record_id: &str) -> crate::Result<()> {
        let url = self.append_team_query(format!(
            "{}/v2/domains/{domain}/records/{record_id}",
            self.endpoint
        ));
        self.client
            .delete(url)
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }
}

fn build_create_body<'a>(
    subdomain: &'a str,
    record_type: DnsRecordType,
    ttl: u32,
    content: &'a VercelContent,
) -> CreateBody<'a> {
    match content {
        VercelContent::Value(value) => CreateBody {
            name: subdomain,
            record_type: record_type.as_str(),
            value: Some(value.as_str()),
            ttl,
            mx_priority: None,
            srv: None,
        },
        VercelContent::Mx { value, priority } => CreateBody {
            name: subdomain,
            record_type: record_type.as_str(),
            value: Some(value.as_str()),
            ttl,
            mx_priority: Some(*priority),
            srv: None,
        },
        VercelContent::Srv(data) => CreateBody {
            name: subdomain,
            record_type: record_type.as_str(),
            value: None,
            ttl,
            mx_priority: None,
            srv: Some(data),
        },
    }
}

fn build_contents(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<VercelContent>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(vercel_content_from_record(&record)?);
    }
    Ok(out)
}

fn vercel_content_from_record(record: &DnsRecord) -> crate::Result<VercelContent> {
    Ok(match record {
        DnsRecord::A(addr) => VercelContent::Value(addr.to_string()),
        DnsRecord::AAAA(addr) => VercelContent::Value(addr.to_string()),
        DnsRecord::CNAME(content) => VercelContent::Value(content.clone()),
        DnsRecord::NS(content) => VercelContent::Value(content.clone()),
        DnsRecord::MX(mx) => VercelContent::Mx {
            value: mx.exchange.clone(),
            priority: mx.priority,
        },
        DnsRecord::TXT(content) => VercelContent::Value(content.clone()),
        DnsRecord::SRV(srv) => VercelContent::Srv(SrvData {
            priority: srv.priority,
            weight: srv.weight,
            port: srv.port,
            target: srv.target.clone(),
        }),
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Vercel".to_string(),
            ));
        }
        DnsRecord::CAA(caa) => VercelContent::Value(caa.to_string()),
    })
}

fn listed_to_content(record: &ListedRecord, record_type: DnsRecordType) -> Option<VercelContent> {
    match record_type {
        DnsRecordType::MX => Some(VercelContent::Mx {
            value: record.value.clone().unwrap_or_default(),
            priority: record.mx_priority.unwrap_or(0),
        }),
        DnsRecordType::SRV => {
            if let Some(srv) = &record.srv {
                Some(VercelContent::Srv(srv.clone()))
            } else {
                parse_srv_value(record.value.as_deref()?).map(VercelContent::Srv)
            }
        }
        DnsRecordType::TLSA => None,
        _ => Some(VercelContent::Value(
            record.value.clone().unwrap_or_default(),
        )),
    }
}

fn parse_srv_value(value: &str) -> Option<SrvData> {
    let mut parts = value.split_whitespace();
    let priority = parts.next()?.parse().ok()?;
    let weight = parts.next()?.parse().ok()?;
    let port = parts.next()?.parse().ok()?;
    let target = parts.next()?.to_string();
    if parts.next().is_some() {
        return None;
    }
    Some(SrvData {
        priority,
        weight,
        port,
        target,
    })
}

fn listed_to_dns_record(
    record: &ListedRecord,
    record_type: DnsRecordType,
) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => {
            let value = record.value.as_deref().unwrap_or("");
            value
                .parse()
                .map(DnsRecord::A)
                .map_err(|err| Error::Parse(format!("invalid A value {value}: {err}")))
        }
        DnsRecordType::AAAA => {
            let value = record.value.as_deref().unwrap_or("");
            value
                .parse()
                .map(DnsRecord::AAAA)
                .map_err(|err| Error::Parse(format!("invalid AAAA value {value}: {err}")))
        }
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(record.value.clone().unwrap_or_default())),
        DnsRecordType::NS => Ok(DnsRecord::NS(record.value.clone().unwrap_or_default())),
        DnsRecordType::MX => Ok(DnsRecord::MX(MXRecord {
            exchange: record.value.clone().unwrap_or_default(),
            priority: record.mx_priority.unwrap_or(0),
        })),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(record.value.clone().unwrap_or_default())),
        DnsRecordType::SRV => {
            let srv = record
                .srv
                .clone()
                .or_else(|| parse_srv_value(record.value.as_deref()?))
                .ok_or_else(|| {
                    Error::Parse(format!(
                        "invalid SRV record {}: missing srv data",
                        record.id
                    ))
                })?;
            Ok(DnsRecord::SRV(SRVRecord {
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
                target: srv.target,
            }))
        }
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by Vercel".to_string(),
        )),
        DnsRecordType::CAA => parse_caa_value(record.value.as_deref().unwrap_or("")),
    }
}

fn parse_caa_value(value: &str) -> crate::Result<DnsRecord> {
    let mut parts = value.splitn(3, char::is_whitespace);
    let flags_str = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value: {value}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value: {value}")))?;
    let raw_value = parts.next().unwrap_or("");
    let flags: u8 = flags_str
        .parse()
        .map_err(|err| Error::Parse(format!("invalid CAA flags {flags_str}: {err}")))?;
    let issuer_critical = flags & 0x80 != 0;
    let stripped = raw_value
        .trim()
        .trim_start_matches('"')
        .trim_end_matches('"');

    Ok(DnsRecord::CAA(match tag {
        "issue" => {
            let (name, options) = split_caa_value(stripped);
            CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }
        }
        "issuewild" => {
            let (name, options) = split_caa_value(stripped);
            CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            }
        }
        "iodef" => CAARecord::Iodef {
            issuer_critical,
            url: stripped.to_string(),
        },
        other => return Err(Error::Parse(format!("unknown CAA tag: {other}"))),
    }))
}

fn split_caa_value(value: &str) -> (Option<String>, Vec<KeyValue>) {
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
