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
    DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord,
    http::{HttpClient, HttpClientBuilder},
    utils::strip_origin_from_name,
};
use serde::Deserialize;
use serde_json::Value;
use std::{borrow::Cow, collections::HashMap, time::Duration};

const DEFAULT_API_ENDPOINT: &str = "https://ipv64.net/api";
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

#[derive(Clone)]
pub struct Ipv64Provider {
    client: HttpClient,
    endpoint: Cow<'static, str>,
}

#[derive(Deserialize, Debug, Clone)]
struct ListedRecord {
    record_id: Value,
    praefix: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
}

#[derive(Deserialize, Debug)]
struct DomainEntry {
    #[serde(default)]
    records: Vec<ListedRecord>,
}

#[derive(Deserialize, Debug)]
struct GetDomainsResponse {
    #[serde(default)]
    subdomains: HashMap<String, DomainEntry>,
}

impl Ipv64Provider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        if api_key.is_empty() {
            return Err(Error::Api("IPv64 API key is empty".to_string()));
        }
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {api_key}"))
            .with_timeout(timeout)
            .build();
        Ok(Self {
            client,
            endpoint: Cow::Borrowed(DEFAULT_API_ENDPOINT),
        })
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
        _ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        validate_record_type(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let prefix = strip_origin_from_name(name.as_ref(), domain.as_ref(), Some(""));

        let desired = encode_records(&records)?;
        let listed = self.get_domains().await?;
        let existing: Vec<ListedRecord> =
            filter_listed(&listed, domain.as_ref(), &prefix, record_type)
                .into_iter()
                .cloned()
                .collect();

        let mut existing_pool = existing;
        let mut to_add: Vec<String> = Vec::new();
        for content in desired {
            if let Some(idx) = existing_pool.iter().position(|r| r.content == content) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(content);
            }
        }

        for entry in existing_pool {
            self.del_record_by_id(&entry.record_id).await?;
        }
        for content in to_add {
            self.add_record(domain.as_ref(), &prefix, record_type, &content)
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        check_record_types(record_type, &records)?;
        validate_record_type(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let prefix = strip_origin_from_name(name.as_ref(), domain.as_ref(), Some(""));

        let desired = encode_records(&records)?;
        let listed = self.get_domains().await?;
        let existing = filter_listed(&listed, domain.as_ref(), &prefix, record_type);

        for content in desired {
            if existing.iter().any(|r| r.content == content) {
                continue;
            }
            self.add_record(domain.as_ref(), &prefix, record_type, &content)
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
        check_record_types(record_type, &records)?;
        validate_record_type(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let prefix = strip_origin_from_name(name.as_ref(), domain.as_ref(), Some(""));

        let to_remove = encode_records(&records)?;
        let listed = self.get_domains().await?;
        let existing: Vec<ListedRecord> =
            filter_listed(&listed, domain.as_ref(), &prefix, record_type)
                .into_iter()
                .cloned()
                .collect();

        for content in to_remove {
            if let Some(entry) = existing.iter().find(|r| r.content == content) {
                self.del_record_by_id(&entry.record_id).await?;
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
        validate_record_type(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let prefix = strip_origin_from_name(name.as_ref(), domain.as_ref(), Some(""));

        let listed = self.get_domains().await?;
        filter_listed(&listed, domain.as_ref(), &prefix, record_type)
            .into_iter()
            .map(|r| decode_record(record_type, &r.content))
            .collect()
    }

    async fn get_domains(&self) -> crate::Result<GetDomainsResponse> {
        self.client
            .get(format!("{}?get_domains", self.endpoint))
            .send::<GetDomainsResponse>()
            .await
    }

    async fn add_record(
        &self,
        domain: &str,
        prefix: &str,
        record_type: DnsRecordType,
        content: &str,
    ) -> crate::Result<()> {
        let body = serde_urlencoded::to_string([
            ("add_record", domain),
            ("praefix", prefix),
            ("type", record_type.as_str()),
            ("content", content),
        ])
        .map_err(|err| Error::Serialize(format!("Failed to encode body: {err}")))?;

        self.client
            .post(self.endpoint.to_string())
            .set_header("Content-Type", FORM_CONTENT_TYPE)
            .with_raw_body(body)
            .send_with_retry::<Value>(3)
            .await
            .map(|_| ())
    }

    async fn del_record_by_id(&self, record_id: &Value) -> crate::Result<()> {
        let id_str = record_id_to_string(record_id)?;
        let body = serde_urlencoded::to_string([("del_record", id_str.as_str())])
            .map_err(|err| Error::Serialize(format!("Failed to encode body: {err}")))?;

        self.client
            .delete(self.endpoint.to_string())
            .set_header("Content-Type", FORM_CONTENT_TYPE)
            .with_raw_body(body)
            .send_with_retry::<Value>(3)
            .await
            .map(|_| ())
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

fn validate_record_type(record_type: DnsRecordType) -> crate::Result<()> {
    match record_type {
        DnsRecordType::A
        | DnsRecordType::AAAA
        | DnsRecordType::CNAME
        | DnsRecordType::NS
        | DnsRecordType::MX
        | DnsRecordType::TXT
        | DnsRecordType::SRV => Ok(()),
        DnsRecordType::TLSA | DnsRecordType::CAA => Err(Error::Api(format!(
            "{} records are not supported by IPv64",
            record_type.as_str()
        ))),
    }
}

fn encode_record_content(record: &DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(target) => target.clone(),
        DnsRecord::NS(target) => target.clone(),
        DnsRecord::MX(mx) => mx.to_string(),
        DnsRecord::TXT(text) => text.clone(),
        DnsRecord::SRV(srv) => srv.to_string(),
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by IPv64".to_string(),
            ));
        }
        DnsRecord::CAA(_) => {
            return Err(Error::Api(
                "CAA records are not supported by IPv64".to_string(),
            ));
        }
    })
}

fn encode_records(records: &[DnsRecord]) -> crate::Result<Vec<String>> {
    records.iter().map(encode_record_content).collect()
}

fn decode_record(record_type: DnsRecordType, content: &str) -> crate::Result<DnsRecord> {
    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(
            content
                .parse()
                .map_err(|err| Error::Parse(format!("invalid A content {content}: {err}")))?,
        ),
        DnsRecordType::AAAA => DnsRecord::AAAA(
            content
                .parse()
                .map_err(|err| Error::Parse(format!("invalid AAAA content {content}: {err}")))?,
        ),
        DnsRecordType::CNAME => DnsRecord::CNAME(content.to_string()),
        DnsRecordType::NS => DnsRecord::NS(content.to_string()),
        DnsRecordType::TXT => DnsRecord::TXT(content.to_string()),
        DnsRecordType::MX => {
            let (priority, exchange) = content.split_once(' ').ok_or_else(|| {
                Error::Parse(format!("invalid MX content {content}: missing priority"))
            })?;
            let priority = priority
                .parse::<u16>()
                .map_err(|err| Error::Parse(format!("invalid MX priority {priority}: {err}")))?;
            DnsRecord::MX(MXRecord {
                priority,
                exchange: exchange.to_string(),
            })
        }
        DnsRecordType::SRV => {
            let parts: Vec<&str> = content.splitn(4, ' ').collect();
            if parts.len() != 4 {
                return Err(Error::Parse(format!(
                    "invalid SRV content {content}: expected 4 fields"
                )));
            }
            let priority = parts[0]
                .parse::<u16>()
                .map_err(|err| Error::Parse(format!("invalid SRV priority: {err}")))?;
            let weight = parts[1]
                .parse::<u16>()
                .map_err(|err| Error::Parse(format!("invalid SRV weight: {err}")))?;
            let port = parts[2]
                .parse::<u16>()
                .map_err(|err| Error::Parse(format!("invalid SRV port: {err}")))?;
            DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target: parts[3].to_string(),
            })
        }
        DnsRecordType::TLSA | DnsRecordType::CAA => {
            return Err(Error::Api(format!(
                "{} records are not supported by IPv64",
                record_type.as_str()
            )));
        }
    })
}

fn filter_listed<'a>(
    response: &'a GetDomainsResponse,
    domain: &str,
    prefix: &str,
    record_type: DnsRecordType,
) -> Vec<&'a ListedRecord> {
    let type_str = record_type.as_str();
    let domain = domain.trim_end_matches('.');
    response
        .subdomains
        .iter()
        .filter(|(key, _)| key.trim_end_matches('.').eq_ignore_ascii_case(domain))
        .flat_map(|(_, entry)| entry.records.iter())
        .filter(|r| r.praefix == prefix && r.record_type.eq_ignore_ascii_case(type_str))
        .collect()
}

fn record_id_to_string(value: &Value) -> crate::Result<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        other => Err(Error::Parse(format!(
            "invalid record_id in get_domains response: {other}"
        ))),
    }
}
