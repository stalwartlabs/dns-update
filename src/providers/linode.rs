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

const DEFAULT_API_ENDPOINT: &str = "https://api.linode.com/v4";
const LIST_PAGE_SIZE: u32 = 500;

#[derive(Clone)]
pub struct LinodeProvider {
    client: HttpClient,
    endpoint: Cow<'static, str>,
}

#[derive(Deserialize, Debug)]
struct PagedDomains {
    data: Vec<Domain>,
}

#[derive(Deserialize, Debug)]
struct Domain {
    id: i64,
    domain: String,
}

#[derive(Deserialize, Debug)]
struct PagedDomainRecords {
    data: Vec<DomainRecord>,
    page: u32,
    pages: u32,
}

#[derive(Deserialize, Debug, Clone)]
struct DomainRecord {
    id: i64,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    priority: u16,
    #[serde(default)]
    weight: u16,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    tag: Option<String>,
}

#[derive(Serialize, Debug)]
struct DomainRecordRequest<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'static str,
    target: String,
    ttl_sec: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordValue {
    target: String,
    priority: Option<u16>,
    weight: Option<u16>,
    port: Option<u16>,
    service: Option<String>,
    protocol: Option<String>,
    tag: Option<String>,
}

impl LinodeProvider {
    pub(crate) fn new(auth_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", auth_token.as_ref()))
            .with_timeout(timeout)
            .build();
        Self {
            client,
            endpoint: Cow::Borrowed(DEFAULT_API_ENDPOINT),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl Into<Cow<'static, str>>) -> Self {
        Self {
            endpoint: endpoint.into(),
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
        reject_unsupported(record_type)?;
        let domain = origin.into_name().into_owned();
        let name = name.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let domain_id = self.obtain_domain_id(&domain).await?;
        let desired = build_values(record_type, records)?;
        let existing = self.list_at(domain_id, &subdomain, record_type).await?;

        let mut existing_pool = existing;
        let mut to_add: Vec<RecordValue> = Vec::new();

        for value in desired {
            if let Some(idx) = existing_pool
                .iter()
                .position(|r| listed_to_value(r) == value)
            {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(value);
            }
        }

        for entry in existing_pool {
            self.delete_record(domain_id, entry.id).await?;
        }
        for value in to_add {
            self.create_record(domain_id, &subdomain, record_type, ttl, value)
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
        reject_unsupported(record_type)?;
        let domain = origin.into_name().into_owned();
        let name = name.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let domain_id = self.obtain_domain_id(&domain).await?;
        let desired = build_values(record_type, records)?;
        let existing = self.list_at(domain_id, &subdomain, record_type).await?;

        for value in desired {
            if existing.iter().any(|r| listed_to_value(r) == value) {
                continue;
            }
            self.create_record(domain_id, &subdomain, record_type, ttl, value)
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
        if records.is_empty() {
            return Ok(());
        }
        reject_unsupported(record_type)?;
        let domain = origin.into_name().into_owned();
        let name = name.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let domain_id = self.obtain_domain_id(&domain).await?;
        let to_remove = build_values(record_type, records)?;
        let existing = self.list_at(domain_id, &subdomain, record_type).await?;

        for value in to_remove {
            if let Some(entry) = existing.iter().find(|r| listed_to_value(r) == value) {
                self.delete_record(domain_id, entry.id).await?;
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
        reject_unsupported(record_type)?;
        let domain = origin.into_name().into_owned();
        let name = name.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let domain_id = self.obtain_domain_id(&domain).await?;
        let listed = self.list_at(domain_id, &subdomain, record_type).await?;
        listed
            .into_iter()
            .map(|r| value_to_record(record_type, listed_to_value(&r)))
            .collect()
    }

    async fn obtain_domain_id(&self, domain: &str) -> crate::Result<i64> {
        self.client
            .get(format!("{}/domains", self.endpoint))
            .with_header("X-Filter", format!(r#"{{"domain":"{}"}}"#, domain))
            .send_with_retry::<PagedDomains>(3)
            .await
            .and_then(|response| {
                response
                    .data
                    .into_iter()
                    .find(|d| d.domain == domain)
                    .map(|d| d.id)
                    .ok_or_else(|| Error::Api(format!("Linode domain {domain} not found")))
            })
    }

    async fn list_at(
        &self,
        domain_id: i64,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<DomainRecord>> {
        let wanted_type = record_type.as_str();
        let mut out: Vec<DomainRecord> = Vec::new();
        let mut page: u32 = 1;
        loop {
            let url = format!(
                "{}/domains/{}/records?page={}&page_size={}",
                self.endpoint, domain_id, page, LIST_PAGE_SIZE
            );
            let response: PagedDomainRecords = self
                .client
                .get(url)
                .with_header("X-Filter", format!(r#"{{"type":"{}"}}"#, wanted_type))
                .send_with_retry(3)
                .await?;
            let total_pages = response.pages.max(response.page);
            for r in response.data {
                if r.record_type == wanted_type && published_name(&r) == subdomain {
                    out.push(r);
                }
            }
            if page >= total_pages {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    async fn create_record(
        &self,
        domain_id: i64,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
        value: RecordValue,
    ) -> crate::Result<()> {
        let (rest_name, service, protocol) = split_srv_name(subdomain, &value);
        let body = build_request(
            rest_name,
            record_type.as_str(),
            ttl,
            value,
            service,
            protocol,
        );
        self.client
            .post(format!("{}/domains/{}/records", self.endpoint, domain_id))
            .with_body(body)?
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, domain_id: i64, record_id: i64) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/domains/{}/records/{}",
                self.endpoint, domain_id, record_id
            ))
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn reject_unsupported(record_type: DnsRecordType) -> crate::Result<()> {
    match record_type {
        DnsRecordType::TLSA => Err(Error::Unsupported(
            "TLSA records are not supported by Linode".to_string(),
        )),
        _ => Ok(()),
    }
}

fn build_values(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<RecordValue>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(record_to_value(record)?);
    }
    Ok(out)
}

fn record_to_value(record: DnsRecord) -> crate::Result<RecordValue> {
    match record {
        DnsRecord::A(addr) => Ok(RecordValue {
            target: addr.to_string(),
            priority: None,
            weight: None,
            port: None,
            service: None,
            protocol: None,
            tag: None,
        }),
        DnsRecord::AAAA(addr) => Ok(RecordValue {
            target: addr.to_string(),
            priority: None,
            weight: None,
            port: None,
            service: None,
            protocol: None,
            tag: None,
        }),
        DnsRecord::CNAME(content) => Ok(RecordValue {
            target: content,
            priority: None,
            weight: None,
            port: None,
            service: None,
            protocol: None,
            tag: None,
        }),
        DnsRecord::NS(content) => Ok(RecordValue {
            target: content,
            priority: None,
            weight: None,
            port: None,
            service: None,
            protocol: None,
            tag: None,
        }),
        DnsRecord::MX(mx) => Ok(RecordValue {
            target: mx.exchange,
            priority: Some(mx.priority),
            weight: None,
            port: None,
            service: None,
            protocol: None,
            tag: None,
        }),
        DnsRecord::TXT(content) => Ok(RecordValue {
            target: content,
            priority: None,
            weight: None,
            port: None,
            service: None,
            protocol: None,
            tag: None,
        }),
        DnsRecord::SRV(srv) => Ok(RecordValue {
            target: srv.target,
            priority: Some(srv.priority),
            weight: Some(srv.weight),
            port: Some(srv.port),
            service: None,
            protocol: None,
            tag: None,
        }),
        DnsRecord::TLSA(_) => Err(Error::Unsupported(
            "TLSA records are not supported by Linode".to_string(),
        )),
        DnsRecord::CAA(caa) => {
            let (_flags, tag, value) = caa.decompose();
            Ok(RecordValue {
                target: value,
                priority: None,
                weight: None,
                port: None,
                service: None,
                protocol: None,
                tag: Some(tag),
            })
        }
    }
}

fn listed_to_value(record: &DomainRecord) -> RecordValue {
    let is_srv = record.record_type == "SRV";
    let is_mx = record.record_type == "MX";
    let is_caa = record.record_type == "CAA";
    RecordValue {
        target: record.target.clone(),
        priority: if is_mx || is_srv {
            Some(record.priority)
        } else {
            None
        },
        weight: if is_srv { Some(record.weight) } else { None },
        port: if is_srv { Some(record.port) } else { None },
        service: None,
        protocol: None,
        tag: if is_caa { record.tag.clone() } else { None },
    }
}

fn value_to_record(record_type: DnsRecordType, value: RecordValue) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => value
            .target
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A target {}: {e}", value.target))),
        DnsRecordType::AAAA => value
            .target
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA target {}: {e}", value.target))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(value.target)),
        DnsRecordType::NS => Ok(DnsRecord::NS(value.target)),
        DnsRecordType::MX => Ok(DnsRecord::MX(MXRecord {
            exchange: value.target,
            priority: value.priority.unwrap_or_default(),
        })),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(value.target)),
        DnsRecordType::SRV => Ok(DnsRecord::SRV(SRVRecord {
            target: value.target,
            priority: value.priority.unwrap_or_default(),
            weight: value.weight.unwrap_or_default(),
            port: value.port.unwrap_or_default(),
        })),
        DnsRecordType::TLSA => Err(Error::Unsupported(
            "TLSA records are not supported by Linode".to_string(),
        )),
        DnsRecordType::CAA => {
            let tag = value.tag.unwrap_or_default();
            build_caa(tag, value.target).map(DnsRecord::CAA)
        }
    }
}

fn build_request<'a>(
    name: &'a str,
    record_type: &'static str,
    ttl: u32,
    value: RecordValue,
    service: Option<String>,
    protocol: Option<String>,
) -> DomainRecordRequest<'a> {
    DomainRecordRequest {
        name,
        record_type,
        target: value.target,
        ttl_sec: ttl,
        priority: value.priority,
        weight: value.weight,
        port: value.port,
        service,
        protocol,
        tag: value.tag,
    }
}

fn split_srv_name<'a>(
    subdomain: &'a str,
    value: &RecordValue,
) -> (&'a str, Option<String>, Option<String>) {
    if value.port.is_none() && value.weight.is_none() {
        return (subdomain, None, None);
    }
    let mut parts = subdomain.splitn(3, '.');
    let first = parts.next().unwrap_or("");
    let second = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("");
    if first.starts_with('_') && second.starts_with('_') {
        (rest, Some(first.to_string()), Some(second.to_string()))
    } else {
        (subdomain, None, None)
    }
}

fn published_name(record: &DomainRecord) -> String {
    match (record.service.as_deref(), record.protocol.as_deref()) {
        (Some(service), Some(protocol)) if !service.is_empty() && !protocol.is_empty() => {
            if record.name.is_empty() {
                format!("{service}.{protocol}")
            } else {
                format!("{service}.{protocol}.{}", record.name)
            }
        }
        _ => record.name.clone(),
    }
}

fn build_caa(tag: String, value: String) -> crate::Result<CAARecord> {
    match tag.as_str() {
        "issue" => {
            let (name, options) = parse_caa_value(&value);
            Ok(CAARecord::Issue {
                issuer_critical: false,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(&value);
            Ok(CAARecord::IssueWild {
                issuer_critical: false,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical: false,
            url: value,
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
