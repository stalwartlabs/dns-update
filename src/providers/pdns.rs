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
        build_caa, parse_mx, parse_srv, parse_tlsa, strip_trailing_dot, txt_chunks_to_text,
        unquote_txt,
    },
};
use serde::{Deserialize, Serialize};
use std::{fmt::Write, time::Duration};

const DEFAULT_ENDPOINT: &str = "http://localhost:8081";
const DEFAULT_SERVER: &str = "localhost";

#[derive(Clone)]
pub struct PdnsProvider {
    client: HttpClient,
    endpoint: String,
    server_name: String,
}

#[derive(Serialize, Debug)]
struct RrsetsRequest {
    rrsets: Vec<RrsetChange>,
}

#[derive(Serialize, Debug)]
struct RrsetChange {
    name: String,
    #[serde(rename = "type")]
    record_type: &'static str,
    changetype: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    records: Option<Vec<PdnsRecord>>,
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
struct PdnsRecord {
    content: String,
    #[serde(default)]
    disabled: bool,
}

#[derive(Deserialize, Debug)]
struct ZoneResponse {
    #[serde(default)]
    rrsets: Vec<RrsetResponse>,
}

#[derive(Deserialize, Debug)]
struct RrsetResponse {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    ttl: u32,
    #[serde(default)]
    records: Vec<PdnsRecord>,
}

#[derive(Deserialize)]
struct EmptyResponse {}

impl PdnsProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        endpoint: Option<impl AsRef<str>>,
        server_name: Option<impl AsRef<str>>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("X-API-Key", api_key.as_ref())
            .with_header("Accept", "application/json")
            .with_timeout(timeout)
            .build();
        let endpoint = endpoint
            .map(|value| normalize_endpoint(value.as_ref()))
            .unwrap_or_else(|| normalize_endpoint(DEFAULT_ENDPOINT));
        let server_name = server_name
            .map(|value| value.as_ref().to_string())
            .unwrap_or_else(|| DEFAULT_SERVER.to_string());

        Self {
            client,
            endpoint,
            server_name,
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
        let records = build_records(record_type, records)?;
        let name = name.into_fqdn().into_owned();
        let origin = origin.into_fqdn();

        if records.is_empty() {
            self.delete_rrset(&name, record_type, origin.as_ref()).await
        } else {
            self.replace_rrset(&name, record_type, ttl, records, origin.as_ref())
                .await
        }
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

        let to_add = build_records(record_type, records)?;
        let name = name.into_fqdn().into_owned();
        let origin = origin.into_fqdn();
        let existing = self
            .get_rrset_for_update(&name, record_type, origin.as_ref())
            .await?;
        let (mut current, ttl) = match existing {
            Some(existing) => {
                let existing_ttl = if existing.records.is_empty() {
                    ttl
                } else {
                    existing.ttl
                };
                (existing.records, existing_ttl)
            }
            None => (Vec::new(), ttl),
        };
        let mut changed = false;

        for record in to_add {
            if current.iter().any(|existing| {
                !existing.disabled
                    && record_contents_equal(record_type, &existing.content, &record.content)
            }) {
                continue;
            }
            if let Some(existing) = current.iter_mut().find(|existing| {
                record_contents_equal(record_type, &existing.content, &record.content)
            }) {
                existing.disabled = false;
            } else {
                current.push(record);
            }
            changed = true;
        }

        if !changed {
            return Ok(());
        }

        self.replace_rrset(&name, record_type, ttl, current, origin.as_ref())
            .await
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

        let to_remove = build_records(record_type, records)?;
        let name = name.into_fqdn().into_owned();
        let origin = origin.into_fqdn();
        let Some(existing) = self
            .get_rrset_for_update(&name, record_type, origin.as_ref())
            .await?
        else {
            return Ok(());
        };
        let original_len = existing.records.len();
        let remaining = existing
            .records
            .into_iter()
            .filter(|record| {
                record.disabled
                    || !to_remove.iter().any(|remove| {
                        record_contents_equal(record_type, &remove.content, &record.content)
                    })
            })
            .collect::<Vec<_>>();

        if remaining.len() == original_len {
            return Ok(());
        }
        if remaining.is_empty() {
            self.delete_rrset(&name, record_type, origin.as_ref()).await
        } else {
            self.replace_rrset(&name, record_type, existing.ttl, remaining, origin.as_ref())
                .await
        }
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let name = name.into_fqdn().into_owned();
        let origin = origin.into_fqdn();
        let Some(rrset) = self
            .get_rrset(&name, record_type, origin.as_ref(), false)
            .await?
        else {
            return Ok(Vec::new());
        };

        rrset
            .records
            .into_iter()
            .filter(|record| !record.disabled)
            .map(|record| parse_record(record_type, &record.content))
            .collect()
    }

    async fn get_rrset_for_update(
        &self,
        name: &str,
        record_type: DnsRecordType,
        origin: &str,
    ) -> crate::Result<Option<RrsetResponse>> {
        let response = self
            .client
            .get(self.zone_url(origin))
            .send_with_retry::<ZoneResponse>(3)
            .await?;

        let full_zone_rrset = find_rrset(response, name, record_type);
        if full_zone_rrset
            .as_ref()
            .is_some_and(|rrset| !rrset.records.is_empty())
        {
            return Ok(full_zone_rrset);
        }

        let filtered_rrset = self.get_rrset(name, record_type, origin, true).await?;
        if filtered_rrset
            .as_ref()
            .is_some_and(|rrset| !rrset.records.is_empty())
        {
            Ok(filtered_rrset)
        } else {
            Ok(full_zone_rrset.or(filtered_rrset))
        }
    }

    async fn get_rrset(
        &self,
        name: &str,
        record_type: DnsRecordType,
        origin: &str,
        include_disabled: bool,
    ) -> crate::Result<Option<RrsetResponse>> {
        let query = serde_urlencoded::to_string([
            ("rrset_name", name),
            ("rrset_type", record_type.as_str()),
            (
                "include_disabled",
                if include_disabled { "true" } else { "false" },
            ),
        ])
        .map_err(|err| Error::Serialize(err.to_string()))?;
        let url = format!("{}?{query}", self.zone_url(origin));
        let response = self
            .client
            .get(url)
            .send_with_retry::<ZoneResponse>(3)
            .await?;

        Ok(find_rrset(response, name, record_type))
    }

    async fn replace_rrset(
        &self,
        name: &str,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<PdnsRecord>,
        origin: &str,
    ) -> crate::Result<()> {
        self.patch_rrset(
            origin,
            RrsetChange {
                name: name.to_string(),
                record_type: record_type.as_str(),
                changetype: "REPLACE",
                ttl: Some(ttl),
                records: Some(records),
            },
        )
        .await
    }

    async fn delete_rrset(
        &self,
        name: &str,
        record_type: DnsRecordType,
        origin: &str,
    ) -> crate::Result<()> {
        self.patch_rrset(
            origin,
            RrsetChange {
                name: name.to_string(),
                record_type: record_type.as_str(),
                changetype: "DELETE",
                ttl: None,
                records: None,
            },
        )
        .await
    }

    async fn patch_rrset(&self, origin: &str, rrset: RrsetChange) -> crate::Result<()> {
        self.client
            .patch(self.zone_url(origin))
            .with_body(RrsetsRequest {
                rrsets: vec![rrset],
            })?
            .send_with_retry::<EmptyResponse>(3)
            .await
            .map(|_| ())
    }

    fn zone_url(&self, origin: &str) -> String {
        format!(
            "{}/servers/{}/zones/{}",
            self.endpoint,
            encode_path_segment(&self.server_name),
            encode_zone_id(origin)
        )
    }
}

fn find_rrset(
    response: ZoneResponse,
    name: &str,
    record_type: DnsRecordType,
) -> Option<RrsetResponse> {
    response.rrsets.into_iter().find(|rrset| {
        rrset.name.eq_ignore_ascii_case(name)
            && rrset.record_type.eq_ignore_ascii_case(record_type.as_str())
    })
}

fn normalize_endpoint(endpoint: &str) -> String {
    let endpoint = endpoint.trim_end_matches('/');
    if endpoint.ends_with("/api/v1") {
        endpoint.to_string()
    } else {
        format!("{endpoint}/api/v1")
    }
}

fn encode_zone_id(origin: &str) -> String {
    if origin == "." {
        return "=2E".to_string();
    }

    let mut encoded = String::with_capacity(origin.len());
    for byte in origin.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-') {
            encoded.push(char::from(byte));
        } else {
            write!(encoded, "={byte:02X}").unwrap();
        }
    }
    if !encoded.ends_with('.') {
        encoded.push('.');
    }
    encoded
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            write!(encoded, "%{byte:02X}").unwrap();
        }
    }
    encoded
}

fn build_records(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<PdnsRecord>> {
    records
        .into_iter()
        .map(|record| {
            if record.as_type() != expected_type {
                return Err(Error::Api(format!(
                    "RRSet record type mismatch: expected {}, got {}",
                    expected_type.as_str(),
                    record.as_type().as_str(),
                )));
            }
            Ok(PdnsRecord {
                content: render_record(record),
                disabled: false,
            })
        })
        .collect()
}

fn render_record(record: DnsRecord) -> String {
    match record {
        DnsRecord::A(address) => address.to_string(),
        DnsRecord::AAAA(address) => address.to_string(),
        DnsRecord::CNAME(target) => target.into_fqdn().into_owned(),
        DnsRecord::NS(target) => target.into_fqdn().into_owned(),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, mx.exchange.into_fqdn()),
        DnsRecord::TXT(text) => {
            let mut content = String::with_capacity(text.len() + 4);
            txt_chunks_to_text(&mut content, &text, " ");
            content
        }
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            srv.target.into_fqdn()
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.decompose();
            format!(
                "{} {} \"{}\"",
                flags,
                tag,
                value.replace('\\', "\\\\").replace('"', "\\\"")
            )
        }
    }
}

fn parse_record(record_type: DnsRecordType, content: &str) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => content
            .parse()
            .map(DnsRecord::A)
            .map_err(|err| Error::Parse(format!("invalid A record: {err}"))),
        DnsRecordType::AAAA => content
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|err| Error::Parse(format!("invalid AAAA record: {err}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(strip_trailing_dot(content).to_string())),
        DnsRecordType::NS => Ok(DnsRecord::NS(strip_trailing_dot(content).to_string())),
        DnsRecordType::MX => parse_mx(content),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(unquote_txt(content))),
        DnsRecordType::SRV => parse_srv(content),
        DnsRecordType::TLSA => parse_tlsa(content),
        DnsRecordType::CAA => parse_caa(content),
    }
}

fn record_contents_equal(record_type: DnsRecordType, left: &str, right: &str) -> bool {
    match (
        parse_record(record_type, left),
        parse_record(record_type, right),
    ) {
        (Ok(left), Ok(right)) => records_equal(&left, &right),
        _ => left == right,
    }
}

fn records_equal(left: &DnsRecord, right: &DnsRecord) -> bool {
    match (left, right) {
        (DnsRecord::CNAME(left), DnsRecord::CNAME(right))
        | (DnsRecord::NS(left), DnsRecord::NS(right)) => left.eq_ignore_ascii_case(right),
        (DnsRecord::MX(left), DnsRecord::MX(right)) => {
            left.priority == right.priority && left.exchange.eq_ignore_ascii_case(&right.exchange)
        }
        (DnsRecord::SRV(left), DnsRecord::SRV(right)) => {
            left.priority == right.priority
                && left.weight == right.weight
                && left.port == right.port
                && left.target.eq_ignore_ascii_case(&right.target)
        }
        _ => left == right,
    }
}

fn parse_caa(content: &str) -> crate::Result<DnsRecord> {
    let (flags, rest) = split_token(content)
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {content}")))?;
    let flags = flags
        .parse::<u8>()
        .map_err(|err| Error::Parse(format!("invalid CAA flags: {err}")))?;
    let (tag, value) =
        split_token(rest).ok_or_else(|| Error::Parse(format!("invalid CAA record: {content}")))?;
    if value.is_empty() {
        return Err(Error::Parse(format!("invalid CAA record: {content}")));
    }
    build_caa(flags, &tag.to_ascii_lowercase(), &unquote_txt(value)).map(DnsRecord::CAA)
}

fn split_token(value: &str) -> Option<(&str, &str)> {
    let value = value.trim_start();
    let end = value.find(char::is_whitespace)?;
    Some((&value[..end], value[end..].trim_start()))
}
