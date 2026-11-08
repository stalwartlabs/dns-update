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
    DnsRecord, DnsRecordType, Error, IntoFqdn,
    http::{HttpClient, HttpClientBuilder},
    utils::{
        build_caa, parse_mx, parse_srv, parse_tlsa, strip_origin_from_name, strip_trailing_dot,
        txt_chunks_to_text, unquote_txt,
    },
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{borrow::Cow, fmt::Write, net::AddrParseError, time::Duration};

const DEFAULT_ENDPOINT: &str = "https://api.netcup.com/v1";
const APEX: &str = "@";
const PAGE_SIZE: u32 = 100;
const MAX_PAGES: u32 = 100;
const RETRIES: u32 = 3;

#[derive(Clone)]
pub struct NetcupRestProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Deserialize)]
struct Envelope<T> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<Message>,
    #[serde(default)]
    meta: Option<Meta>,
    #[serde(default)]
    result: Option<T>,
}

#[derive(Deserialize)]
struct Message {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct Meta {
    #[serde(default)]
    pagination: Option<Pagination>,
}

#[derive(Deserialize)]
struct Pagination {
    #[serde(rename = "lastPage", default)]
    last_page: u32,
}

#[derive(Deserialize)]
struct Domain {
    id: u64,
    #[serde(default)]
    fqdn: String,
    #[serde(rename = "isDnsManaged", default)]
    is_dns_managed: Option<bool>,
}

#[derive(Deserialize)]
struct Revision {
    identifier: String,
    #[serde(rename = "createdAt", default)]
    created_at: String,
}

#[derive(Deserialize)]
struct Record {
    #[serde(default)]
    name: String,
    #[serde(rename = "type", default)]
    record_type: String,
    #[serde(default)]
    rdata: String,
    #[serde(default)]
    ttl: Option<u32>,
    #[serde(default)]
    immutable: bool,
}

#[derive(Serialize)]
struct RecordInput<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    rdata: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

#[derive(Serialize)]
struct Changeset<'a> {
    #[serde(rename = "autoCommit")]
    auto_commit: bool,
    strict: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    create: Vec<RecordInput<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    delete: Vec<RecordInput<'a>>,
}

struct RecordSet {
    domain_id: u64,
    hostname: String,
    records: Vec<Record>,
}

impl NetcupRestProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", api_key.as_ref()))
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
        let ttl = ttl.max(1);
        let set = self.record_set(name, record_type, origin).await?;
        let mut missing = Vec::with_capacity(records.len());
        for record in records {
            if !missing.contains(&record) {
                missing.push(record);
            }
        }
        let mut delete = Vec::new();
        for record in set.records.iter().filter(|r| !r.immutable) {
            let found = decode_record(record_type, &record.rdata)
                .ok()
                .filter(|_| record.ttl == Some(ttl))
                .and_then(|current| missing.iter().position(|want| *want == current));
            match found {
                Some(idx) => {
                    missing.swap_remove(idx);
                }
                None => delete.push(record.as_input()),
            }
        }
        let create = missing
            .iter()
            .map(|record| new_input(&set.hostname, record, ttl))
            .collect();
        self.apply(set.domain_id, create, delete).await
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
        let ttl = ttl.max(1);
        let set = self.record_set(name, record_type, origin).await?;
        let mut known = set
            .records
            .iter()
            .filter_map(|r| decode_record(record_type, &r.rdata).ok())
            .collect::<Vec<_>>();
        let mut create = Vec::new();
        for record in records {
            if !known.contains(&record) {
                create.push(new_input(&set.hostname, &record, ttl));
                known.push(record);
            }
        }
        self.apply(set.domain_id, create, Vec::new()).await
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
        let set = self.record_set(name, record_type, origin).await?;
        let delete = set
            .records
            .iter()
            .filter(|r| {
                !r.immutable
                    && decode_record(record_type, &r.rdata)
                        .is_ok_and(|current| records.contains(&current))
            })
            .map(Record::as_input)
            .collect();
        self.apply(set.domain_id, Vec::new(), delete).await
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        self.record_set(name, record_type, origin)
            .await?
            .records
            .iter()
            .map(|r| decode_record(record_type, &r.rdata))
            .collect()
    }

    async fn record_set(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<RecordSet> {
        let name = name.into_name();
        let origin = origin.into_name();
        let hostname = strip_origin_from_name(&name, &origin, Some(APEX));
        let domain_id = self.domain_id(&origin).await?;
        let mut records = match self.current_revision(domain_id).await? {
            Some(revision) => {
                self.get_all::<Record>(&format!(
                    "{}/domain/{domain_id}/dns/revision/{revision}/record",
                    self.endpoint
                ))
                .await?
            }
            None => Vec::new(),
        };
        let type_str = record_type.as_str();
        records.retain(|r| {
            r.record_type.eq_ignore_ascii_case(type_str) && same_name(&r.name, &hostname)
        });
        Ok(RecordSet {
            domain_id,
            hostname,
            records,
        })
    }

    async fn domain_id(&self, origin: &str) -> crate::Result<u64> {
        let domains: Envelope<Vec<Domain>> = self
            .client
            .get(format!("{}/domain?fqdn={origin}", self.endpoint))
            .send_with_retry(RETRIES)
            .await
            .map_err(|err| match err {
                Error::NotFound => Error::Api(format!("Netcup domain {origin} not found")),
                err => err,
            })?;
        let domain = domains
            .into_result()?
            .unwrap_or_default()
            .into_iter()
            .find(|d| strip_trailing_dot(&d.fqdn).eq_ignore_ascii_case(origin))
            .ok_or_else(|| Error::Api(format!("Netcup domain {origin} not found")))?;
        if domain.is_dns_managed == Some(false) {
            return Err(Error::Api(format!(
                "Netcup domain {origin} is not on netcup CloudDNS; use the legacy CCP API"
            )));
        }
        Ok(domain.id)
    }

    async fn current_revision(&self, domain_id: u64) -> crate::Result<Option<String>> {
        Ok(self
            .get_all::<Revision>(&format!(
                "{}/domain/{domain_id}/dns/revision",
                self.endpoint
            ))
            .await?
            .into_iter()
            .max_by_key(|r| r.created_at.parse::<Timestamp>().ok())
            .map(|r| r.identifier))
    }

    async fn get_all<T: DeserializeOwned>(&self, url: &str) -> crate::Result<Vec<T>> {
        let mut items = Vec::new();
        for page in 1..=MAX_PAGES {
            let response: Envelope<Vec<T>> = self
                .client
                .get(format!("{url}?page={page}&perPage={PAGE_SIZE}"))
                .send_with_retry(RETRIES)
                .await?;
            let last_page = response
                .meta
                .as_ref()
                .and_then(|meta| meta.pagination.as_ref())
                .map_or(0, |pagination| pagination.last_page);
            let result = response.into_result()?.unwrap_or_default();
            let done = result.is_empty() || page >= last_page;
            items.extend(result);
            if done {
                break;
            }
        }
        Ok(items)
    }

    async fn apply(
        &self,
        domain_id: u64,
        create: Vec<RecordInput<'_>>,
        delete: Vec<RecordInput<'_>>,
    ) -> crate::Result<()> {
        if create.is_empty() && delete.is_empty() {
            return Ok(());
        }
        let response: Envelope<serde_json::Value> = self
            .client
            .post(format!("{}/domain/{domain_id}/changeset", self.endpoint))
            .with_body(Changeset {
                auto_commit: true,
                strict: true,
                create,
                delete,
            })?
            .send_with_retry(RETRIES)
            .await?;
        response.into_result().map(|_| ())
    }
}

impl<T> Envelope<T> {
    fn into_result(self) -> crate::Result<Option<T>> {
        if self.success {
            return Ok(self.result);
        }
        let mut message = String::from("Netcup API error");
        for error in &self.errors {
            let _ = write!(message, ": {} ({})", error.message, error.code);
        }
        Err(Error::Api(message))
    }
}

impl Record {
    fn as_input(&self) -> RecordInput<'_> {
        RecordInput {
            name: &self.name,
            record_type: &self.record_type,
            rdata: Cow::Borrowed(&self.rdata),
            ttl: self.ttl,
        }
    }
}

fn new_input<'a>(hostname: &'a str, record: &DnsRecord, ttl: u32) -> RecordInput<'a> {
    RecordInput {
        name: hostname,
        record_type: record.as_type().as_str(),
        rdata: Cow::Owned(encode_rdata(record)),
        ttl: Some(ttl),
    }
}

fn same_name(listed: &str, hostname: &str) -> bool {
    listed.eq_ignore_ascii_case(hostname) || (hostname == APEX && listed.is_empty())
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> crate::Result<()> {
    match records.iter().find(|r| r.as_type() != expected) {
        Some(r) => Err(Error::Api(format!(
            "RRSet record type mismatch: expected {}, got {}",
            expected.as_str(),
            r.as_type().as_str(),
        ))),
        None => Ok(()),
    }
}

fn encode_rdata(record: &DnsRecord) -> String {
    match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(target) | DnsRecord::NS(target) => target.into_fqdn().into_owned(),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, (&mx.exchange).into_fqdn()),
        DnsRecord::TXT(text) => {
            let mut out = String::with_capacity(text.len() + 4);
            txt_chunks_to_text(&mut out, text, " ");
            out
        }
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            (&srv.target).into_fqdn(),
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    }
}

fn decode_record(record_type: DnsRecordType, rdata: &str) -> crate::Result<DnsRecord> {
    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(rdata.parse().map_err(|e: AddrParseError| {
            Error::Parse(format!("invalid Netcup A value '{rdata}': {e}"))
        })?),
        DnsRecordType::AAAA => DnsRecord::AAAA(rdata.parse().map_err(|e: AddrParseError| {
            Error::Parse(format!("invalid Netcup AAAA value '{rdata}': {e}"))
        })?),
        DnsRecordType::CNAME => DnsRecord::CNAME(strip_trailing_dot(rdata).to_string()),
        DnsRecordType::NS => DnsRecord::NS(strip_trailing_dot(rdata).to_string()),
        DnsRecordType::MX => parse_mx(rdata)?,
        DnsRecordType::TXT => DnsRecord::TXT(unquote_txt(rdata)),
        DnsRecordType::SRV => parse_srv(rdata)?,
        DnsRecordType::TLSA => parse_tlsa(rdata)?,
        DnsRecordType::CAA => decode_caa(rdata)?,
    })
}

fn decode_caa(rdata: &str) -> crate::Result<DnsRecord> {
    let invalid = || Error::Parse(format!("invalid Netcup CAA value '{rdata}'"));
    let mut parts = rdata.splitn(3, char::is_whitespace);
    let flags = parts
        .next()
        .and_then(|flags| flags.parse::<u8>().ok())
        .ok_or_else(invalid)?;
    let tag = parts.next().ok_or_else(invalid)?.to_ascii_lowercase();
    let value = unquote_txt(parts.next().ok_or_else(invalid)?.trim());
    build_caa(flags, &tag, &value).map(DnsRecord::CAA)
}
