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
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone)]
pub struct NameDotComProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecord<'a> {
    host: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    answer: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
}

#[derive(Deserialize, Debug, Clone)]
struct Record {
    id: i64,
    #[serde(default)]
    host: Option<String>,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default)]
    answer: Option<String>,
    #[serde(default)]
    priority: Option<u16>,
}

#[derive(Deserialize, Debug)]
struct ListRecordsResponse {
    #[serde(default)]
    records: Vec<Record>,
    #[serde(default, rename = "nextPage")]
    next_page: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedRecord {
    answer: String,
    priority: Option<u16>,
}

const DEFAULT_API_ENDPOINT: &str = "https://api.name.com";

impl NameDotComProvider {
    pub(crate) fn new(
        username: impl AsRef<str>,
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let username = username.as_ref();
        let token = api_token.as_ref();
        if username.is_empty() || token.is_empty() {
            return Err(Error::Api(
                "Name.com username and API token must not be empty".to_string(),
            ));
        }

        let credentials = BASE64.encode(format!("{username}:{token}"));
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {credentials}"))
            .with_timeout(timeout)
            .build();

        Ok(Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
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
        validate_type(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let host = strip_origin_from_name(&name, &domain, Some(""));
        let desired = build_normalized(record_type, records)?;
        let existing = self.list_at(&domain, &host, record_type).await?;

        let mut existing_pool: Vec<(i64, NormalizedRecord)> = existing.into_iter().collect();
        let mut to_add: Vec<NormalizedRecord> = Vec::new();

        for want in desired {
            if let Some(idx) = existing_pool.iter().position(|(_, have)| have == &want) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(want);
            }
        }

        for (id, _) in existing_pool {
            self.delete_record(&domain, id).await?;
        }
        for want in to_add {
            self.create_record(&domain, &host, record_type, want, ttl)
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
        validate_type(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let host = strip_origin_from_name(&name, &domain, Some(""));
        let desired = build_normalized(record_type, records)?;
        let existing = self.list_at(&domain, &host, record_type).await?;

        for want in desired {
            if existing.iter().any(|(_, have)| have == &want) {
                continue;
            }
            self.create_record(&domain, &host, record_type, want, ttl)
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
        validate_type(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let host = strip_origin_from_name(&name, &domain, Some(""));
        let to_remove = build_normalized(record_type, records)?;
        let existing = self.list_at(&domain, &host, record_type).await?;

        for want in to_remove {
            if let Some((id, _)) = existing.iter().find(|(_, have)| have == &want) {
                self.delete_record(&domain, *id).await?;
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
        validate_type(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let host = strip_origin_from_name(&name, &domain, Some(""));
        let existing = self.list_at(&domain, &host, record_type).await?;
        existing
            .into_iter()
            .map(|(_, normalized)| normalized_to_record(record_type, normalized))
            .collect()
    }

    async fn list_at(
        &self,
        domain: &str,
        host: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<(i64, NormalizedRecord)>> {
        let type_str = record_type.as_str();
        let target_host = normalize_host(host);
        let mut out: Vec<(i64, NormalizedRecord)> = Vec::new();
        let mut page: u32 = 1;
        loop {
            let response = self
                .client
                .get(format!(
                    "{}/v4/domains/{}/records?page={}",
                    self.endpoint, domain, page
                ))
                .send::<ListRecordsResponse>()
                .await?;

            for r in response.records {
                if r.record_type != type_str {
                    continue;
                }
                let r_host = normalize_host(r.host.as_deref().unwrap_or(""));
                if r_host != target_host {
                    continue;
                }
                let answer = r.answer.unwrap_or_default();
                out.push((
                    r.id,
                    NormalizedRecord {
                        answer,
                        priority: r.priority,
                    },
                ));
            }

            if response.next_page == 0 {
                return Ok(out);
            }
            page = response.next_page;
        }
    }

    async fn create_record(
        &self,
        domain: &str,
        host: &str,
        record_type: DnsRecordType,
        record: NormalizedRecord,
        ttl: u32,
    ) -> crate::Result<()> {
        self.client
            .post(format!("{}/v4/domains/{}/records", self.endpoint, domain))
            .with_body(CreateRecord {
                host,
                record_type: record_type.as_str(),
                answer: record.answer,
                ttl,
                priority: record.priority,
            })?
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, domain: &str, record_id: i64) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/v4/domains/{}/records/{}",
                self.endpoint, domain, record_id
            ))
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn normalize_host(host: &str) -> String {
    let trimmed = host.trim_end_matches('.');
    if trimmed == "@" {
        String::new()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

fn validate_type(record_type: DnsRecordType) -> crate::Result<()> {
    if matches!(record_type, DnsRecordType::TLSA) {
        return Err(Error::Api(
            "TLSA records are not supported by Name.com".to_string(),
        ));
    }
    Ok(())
}

fn build_normalized(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<NormalizedRecord>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        let priority = record.priority();
        let answer = render_answer(record)?;
        out.push(NormalizedRecord { answer, priority });
    }
    Ok(out)
}

fn render_answer(record: DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content,
        DnsRecord::NS(content) => content,
        DnsRecord::MX(mx) => mx.exchange,
        DnsRecord::TXT(content) => content,
        DnsRecord::SRV(srv) => format!("{} {} {}", srv.weight, srv.port, srv.target),
        DnsRecord::CAA(caa) => caa.to_string(),
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Name.com".to_string(),
            ));
        }
    })
}

fn normalized_to_record(
    record_type: DnsRecordType,
    record: NormalizedRecord,
) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => record
            .answer
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A answer {}: {e}", record.answer))),
        DnsRecordType::AAAA => record
            .answer
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA answer {}: {e}", record.answer))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(record.answer)),
        DnsRecordType::NS => Ok(DnsRecord::NS(record.answer)),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(record.answer)),
        DnsRecordType::MX => Ok(DnsRecord::MX(MXRecord {
            exchange: record.answer,
            priority: record.priority.unwrap_or(0),
        })),
        DnsRecordType::SRV => parse_srv(record),
        DnsRecordType::CAA => parse_caa(&record.answer).map(DnsRecord::CAA),
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by Name.com".to_string(),
        )),
    }
}

fn parse_srv(record: NormalizedRecord) -> crate::Result<DnsRecord> {
    let mut parts = record.answer.split_whitespace();
    let weight: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("invalid SRV answer: {}", record.answer)))?;
    let port: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("invalid SRV answer: {}", record.answer)))?;
    let target = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV answer: {}", record.answer)))?
        .to_string();
    Ok(DnsRecord::SRV(SRVRecord {
        priority: record.priority.unwrap_or(0),
        weight,
        port,
        target,
    }))
}

fn parse_caa(answer: &str) -> crate::Result<CAARecord> {
    let mut parts = answer.splitn(3, char::is_whitespace);
    let flags: u8 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("invalid CAA answer: {answer}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA answer: {answer}")))?;
    let raw_value = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA answer: {answer}")))?
        .trim();
    let issuer_critical = flags & 0x80 != 0;
    let value = raw_value
        .trim_start_matches('"')
        .trim_end_matches('"')
        .to_string();
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
