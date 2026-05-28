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
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.glesys.com";

#[derive(Clone)]
pub struct GlesysProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct AddRecordRequest<'a> {
    domainname: &'a str,
    host: &'a str,
    #[serde(rename = "type")]
    rr_type: &'a str,
    data: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

#[derive(Serialize, Debug)]
struct DeleteRecordRequest {
    recordid: i64,
}

#[derive(Serialize, Debug)]
struct ListRecordsRequest<'a> {
    domainname: &'a str,
}

#[derive(Deserialize, Debug)]
struct ApiEnvelope<T> {
    response: T,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct AddRecordResponse {
    record: AddedRecord,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct AddedRecord {
    recordid: i64,
}

#[derive(Deserialize, Debug)]
struct ListRecordsResponse {
    records: Vec<ListedRecord>,
}

#[derive(Deserialize, Debug, Clone)]
struct ListedRecord {
    recordid: i64,
    #[serde(rename = "type")]
    rr_type: String,
    host: String,
    #[serde(default)]
    data: String,
}

#[derive(Deserialize, Debug)]
struct GenericResponse {
    #[allow(dead_code)]
    #[serde(default)]
    status: Option<serde_json::Value>,
}

impl GlesysProvider {
    pub(crate) fn new(
        api_user: impl AsRef<str>,
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let raw = format!("{}:{}", api_user.as_ref(), api_key.as_ref());
        let encoded = B64.encode(raw);
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {encoded}"))
            .with_header("Accept", "application/json")
            .with_timeout(timeout)
            .build();
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

    async fn list_records(&self, domain: &str) -> crate::Result<Vec<ListedRecord>> {
        let envelope: ApiEnvelope<ListRecordsResponse> = self
            .client
            .post(format!("{}/domain/listrecords", self.endpoint))
            .with_body(ListRecordsRequest { domainname: domain })?
            .send_with_retry(3)
            .await?;
        Ok(envelope.response.records)
    }

    async fn list_at(
        &self,
        domain: &str,
        host: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ListedRecord>> {
        let type_str = record_type.as_str();
        let all = self.list_records(domain).await?;
        Ok(all
            .into_iter()
            .filter(|r| r.host == host && r.rr_type.eq_ignore_ascii_case(type_str))
            .collect())
    }

    async fn add_record(
        &self,
        domain: &str,
        host: &str,
        rr_type: &str,
        data: &str,
        ttl: u32,
    ) -> crate::Result<()> {
        let _: ApiEnvelope<AddRecordResponse> = self
            .client
            .post(format!("{}/domain/addrecord", self.endpoint))
            .with_body(AddRecordRequest {
                domainname: domain,
                host,
                rr_type,
                data,
                ttl: Some(ttl),
            })?
            .send_with_retry(3)
            .await?;
        Ok(())
    }

    async fn delete_record_by_id(&self, record_id: i64) -> crate::Result<()> {
        let _: GenericResponse = self
            .client
            .post(format!("{}/domain/deleterecord", self.endpoint))
            .with_body(DeleteRecordRequest {
                recordid: record_id,
            })?
            .send_with_retry(3)
            .await?;
        Ok(())
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let zone = origin.into_name().to_string();
        let host = strip_origin_from_name(name.into_name().as_ref(), &zone, Some("@"));
        let rr_type = record_type.as_str();
        let desired = build_datas(record_type, records)?;
        let existing = self.list_at(&zone, &host, record_type).await?;

        let mut existing_pool: Vec<ListedRecord> = existing;
        let mut to_add: Vec<String> = Vec::new();

        for data in desired {
            if let Some(idx) = existing_pool.iter().position(|r| r.data == data) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(data);
            }
        }

        for entry in existing_pool {
            self.delete_record_by_id(entry.recordid).await?;
        }
        for data in to_add {
            self.add_record(&zone, &host, rr_type, &data, ttl).await?;
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
        let zone = origin.into_name().to_string();
        let host = strip_origin_from_name(name.into_name().as_ref(), &zone, Some("@"));
        let rr_type = record_type.as_str();
        let desired = build_datas(record_type, records)?;
        let existing = self.list_at(&zone, &host, record_type).await?;

        for data in desired {
            if existing.iter().any(|r| r.data == data) {
                continue;
            }
            self.add_record(&zone, &host, rr_type, &data, ttl).await?;
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
        let zone = origin.into_name().to_string();
        let host = strip_origin_from_name(name.into_name().as_ref(), &zone, Some("@"));
        let to_remove = build_datas(record_type, records)?;
        let existing = self.list_at(&zone, &host, record_type).await?;

        for data in to_remove {
            if let Some(entry) = existing.iter().find(|r| r.data == data) {
                self.delete_record_by_id(entry.recordid).await?;
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
        let zone = origin.into_name().to_string();
        let host = strip_origin_from_name(name.into_name().as_ref(), &zone, Some("@"));
        let listed = self.list_at(&zone, &host, record_type).await?;
        listed
            .into_iter()
            .map(|r| parse_record(record_type, &r.data))
            .collect()
    }
}

fn render_data(record: &DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content.clone(),
        DnsRecord::NS(content) => content.clone(),
        DnsRecord::TXT(content) => content.clone(),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, mx.exchange),
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority, srv.weight, srv.port, srv.target
        ),
        DnsRecord::TLSA(_) => {
            return Err(Error::Unsupported(
                "TLSA records are not supported by Glesys".to_string(),
            ));
        }
        DnsRecord::CAA(caa) => caa.to_string(),
    })
}

fn build_datas(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<String>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(render_data(&record)?);
    }
    Ok(out)
}

fn parse_record(record_type: DnsRecordType, content: &str) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => content
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A record: {e}"))),
        DnsRecordType::AAAA => content
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA record: {e}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(content.to_string())),
        DnsRecordType::NS => Ok(DnsRecord::NS(content.to_string())),
        DnsRecordType::MX => parse_mx(content),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(content.to_string())),
        DnsRecordType::SRV => parse_srv(content),
        DnsRecordType::TLSA => Err(Error::Unsupported(
            "TLSA records are not supported by Glesys".to_string(),
        )),
        DnsRecordType::CAA => parse_caa(content),
    }
}

fn parse_mx(content: &str) -> crate::Result<DnsRecord> {
    let mut parts = content.splitn(2, char::is_whitespace);
    let prio = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid MX record: {content}")))?;
    let exchange = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid MX record: {content}")))?
        .trim();
    let priority: u16 = prio
        .parse()
        .map_err(|e| Error::Parse(format!("invalid MX priority {prio}: {e}")))?;
    Ok(DnsRecord::MX(MXRecord {
        priority,
        exchange: exchange.to_string(),
    }))
}

fn parse_srv(content: &str) -> crate::Result<DnsRecord> {
    let mut parts = content.split_whitespace();
    let priority: u16 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV priority: {e}")))?;
    let weight: u16 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV weight: {e}")))?;
    let port: u16 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV port: {e}")))?;
    let target = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV record: {content}")))?;
    Ok(DnsRecord::SRV(SRVRecord {
        priority,
        weight,
        port,
        target: target.to_string(),
    }))
}

fn parse_caa(content: &str) -> crate::Result<DnsRecord> {
    let mut parts = content.splitn(3, char::is_whitespace);
    let flags: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags: {e}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {content}")))?
        .trim()
        .to_string();
    let raw_value = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {content}")))?
        .trim();
    let value = raw_value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(raw_value)
        .to_string();

    let issuer_critical = flags & 0x80 != 0;
    match tag.as_str() {
        "issue" => {
            let (name, options) = parse_caa_value(&value);
            Ok(DnsRecord::CAA(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }))
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(&value);
            Ok(DnsRecord::CAA(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            }))
        }
        "iodef" => Ok(DnsRecord::CAA(CAARecord::Iodef {
            issuer_critical,
            url: value,
        })),
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
