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

use crate::utils::split_caa_value;
use crate::utils::strip_trailing_dot;
use crate::utils::{parse_mx, parse_srv};
use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn,
    http::{HttpClient, HttpClientBuilder},
    utils::{strip_origin_from_name, txt_chunks_to_text},
};
use serde::{Deserialize, Serialize};
use std::{net::AddrParseError, time::Duration};

#[derive(Clone)]
pub struct HetznerProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct RRSetCreate<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    ttl: u32,
    records: Vec<RecordValue>,
}

#[derive(Serialize, Debug)]
struct SetRecordsBody {
    records: Vec<RecordValue>,
}

#[derive(Serialize, Debug)]
struct AddRecordsBody {
    records: Vec<RecordValue>,
    ttl: u32,
}

#[derive(Serialize, Debug)]
struct RemoveRecordsBody {
    records: Vec<RecordValue>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RecordValue {
    value: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ActionResponse {
    #[serde(default)]
    action: Option<serde_json::Value>,
    #[serde(default)]
    rrset: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct ListRRSetsResponse {
    #[serde(default)]
    rrsets: Vec<ListedRRSet>,
}

#[derive(Deserialize, Debug)]
struct ListedRRSet {
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default)]
    records: Vec<RecordValue>,
}

const DEFAULT_API_ENDPOINT: &str = "https://api.hetzner.cloud/v1";
const RETRIES: u32 = 3;

impl HetznerProvider {
    pub(crate) fn new(
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let token = api_token.as_ref();
        if token.is_empty() {
            return Err(Error::Api(
                "Hetzner API token must not be empty".to_string(),
            ));
        }

        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {token}"))
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
        check_record_types(record_type, &records)?;
        reject_tlsa(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));

        if records.is_empty() {
            return self.delete_rrset(&domain, &subdomain, record_type).await;
        }

        let values = build_values(records)?;

        let url = format!(
            "{}/zones/{}/rrsets/{}/{}/actions/set_records",
            self.endpoint,
            domain,
            subdomain,
            record_type.as_str(),
        );

        match self
            .client
            .post(url)
            .with_body(SetRecordsBody {
                records: values.clone(),
            })?
            .send_with_retry::<ActionResponse>(RETRIES)
            .await
        {
            Ok(_) => self.change_ttl(&domain, &subdomain, record_type, ttl).await,
            Err(Error::NotFound) => {
                self.create_rrset(&domain, &subdomain, record_type, ttl, values)
                    .await
            }
            Err(e) => Err(e),
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
        check_record_types(record_type, &records)?;
        reject_tlsa(record_type)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let values = build_values(records)?;

        let url = format!(
            "{}/zones/{}/rrsets/{}/{}/actions/add_records",
            self.endpoint,
            domain,
            subdomain,
            record_type.as_str(),
        );

        match self
            .client
            .post(url)
            .with_body(AddRecordsBody {
                records: values.clone(),
                ttl,
            })?
            .send_with_retry::<ActionResponse>(RETRIES)
            .await
        {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => {
                self.create_rrset(&domain, &subdomain, record_type, ttl, values)
                    .await
            }
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        reject_tlsa(record_type)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let values = build_values(records)?;

        let url = format!(
            "{}/zones/{}/rrsets/{}/{}/actions/remove_records",
            self.endpoint,
            domain,
            subdomain,
            record_type.as_str(),
        );

        match self
            .client
            .post(url)
            .with_body(RemoveRecordsBody { records: values })?
            .send_with_retry::<ActionResponse>(RETRIES)
            .await
        {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));

        let query = serde_urlencoded::to_string([
            ("name", subdomain.as_str()),
            ("type", record_type.as_str()),
            ("per_page", "50"),
        ])
        .map_err(|e| Error::Serialize(e.to_string()))?;

        let url = format!("{}/zones/{}/rrsets?{}", self.endpoint, domain, query);

        let response: ListRRSetsResponse = match self.client.get(url).send_with_retry(RETRIES).await
        {
            Ok(r) => r,
            Err(Error::NotFound) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };

        let expected_type = record_type.as_str();
        let mut out = Vec::new();
        for rrset in response.rrsets {
            if rrset.record_type != expected_type {
                continue;
            }
            for r in rrset.records {
                out.push(parse_value(record_type, &r.value)?);
            }
        }
        Ok(out)
    }

    async fn create_rrset(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
        values: Vec<RecordValue>,
    ) -> crate::Result<()> {
        self.client
            .post(format!("{}/zones/{}/rrsets", self.endpoint, domain))
            .with_body(RRSetCreate {
                name: subdomain,
                record_type: record_type.as_str(),
                ttl,
                records: values,
            })?
            .send_with_retry::<ActionResponse>(RETRIES)
            .await
            .map(|_| ())
    }

    async fn delete_rrset(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        match self
            .client
            .delete(format!(
                "{}/zones/{}/rrsets/{}/{}",
                self.endpoint,
                domain,
                subdomain,
                record_type.as_str(),
            ))
            .send_raw()
            .await
        {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn change_ttl(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
    ) -> crate::Result<()> {
        #[derive(Serialize)]
        struct ChangeTtl {
            ttl: u32,
        }

        let url = format!(
            "{}/zones/{}/rrsets/{}/{}/actions/change_ttl",
            self.endpoint,
            domain,
            subdomain,
            record_type.as_str(),
        );

        self.client
            .post(url)
            .with_body(ChangeTtl { ttl })?
            .send_with_retry::<ActionResponse>(RETRIES)
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

fn reject_tlsa(record_type: DnsRecordType) -> crate::Result<()> {
    if record_type == DnsRecordType::TLSA {
        Err(Error::Unsupported(
            "TLSA records are not supported by Hetzner".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn build_values(records: Vec<DnsRecord>) -> crate::Result<Vec<RecordValue>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        out.push(RecordValue {
            value: render_value(record)?,
        });
    }
    Ok(out)
}

fn render_value(record: DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content.into_fqdn().into_owned(),
        DnsRecord::NS(content) => content.into_fqdn().into_owned(),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, mx.exchange.into_fqdn().into_owned()),
        DnsRecord::TXT(content) => {
            let mut out = String::with_capacity(content.len() + 4);
            txt_chunks_to_text(&mut out, &content, " ");
            out
        }
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            srv.target.into_fqdn().into_owned(),
        ),
        DnsRecord::TLSA(_) => {
            return Err(Error::Unsupported(
                "TLSA records are not supported by Hetzner".to_string(),
            ));
        }
        DnsRecord::CAA(caa) => caa.to_string(),
    })
}

fn parse_value(record_type: DnsRecordType, value: &str) -> crate::Result<DnsRecord> {
    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(value.parse().map_err(|e: AddrParseError| {
            Error::Parse(format!("invalid A value '{value}': {e}"))
        })?),
        DnsRecordType::AAAA => DnsRecord::AAAA(value.parse().map_err(|e: AddrParseError| {
            Error::Parse(format!("invalid AAAA value '{value}': {e}"))
        })?),
        DnsRecordType::CNAME => DnsRecord::CNAME(strip_trailing_dot(value).to_string()),
        DnsRecordType::NS => DnsRecord::NS(strip_trailing_dot(value).to_string()),
        DnsRecordType::MX => parse_mx(value)?,
        DnsRecordType::TXT => DnsRecord::TXT(parse_txt(value)),
        DnsRecordType::SRV => parse_srv(value)?,
        DnsRecordType::TLSA => {
            return Err(Error::Unsupported(
                "TLSA records are not supported by Hetzner".to_string(),
            ));
        }
        DnsRecordType::CAA => parse_caa(value)?,
    })
}

fn parse_txt(value: &str) -> String {
    let trimmed = value.trim();
    let mut out = String::with_capacity(trimmed.len());
    let mut bytes = trimmed.bytes().peekable();
    while let Some(&b) = bytes.peek() {
        if b != b'"' {
            bytes.next();
            continue;
        }
        bytes.next();
        loop {
            match bytes.next() {
                Some(b'"') => break,
                Some(b'\\') => {
                    if let Some(next) = bytes.next() {
                        out.push(next as char);
                    }
                }
                Some(other) => out.push(other as char),
                None => break,
            }
        }
    }
    if out.is_empty() && !trimmed.is_empty() && !trimmed.starts_with('"') {
        return trimmed.to_string();
    }
    out
}

fn parse_caa(value: &str) -> crate::Result<DnsRecord> {
    let mut parts = value.splitn(3, char::is_whitespace);
    let flags: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags in '{value}': {e}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value '{value}'")))?
        .to_ascii_lowercase();
    let raw_value = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value '{value}'")))?
        .trim();
    let unquoted = raw_value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .map(|s| s.replace("\\\"", "\""))
        .unwrap_or_else(|| raw_value.to_string());

    let issuer_critical = flags & 0x80 != 0;
    match tag.as_str() {
        "issue" => {
            let (name, options) = split_caa_value(&unquoted);
            Ok(DnsRecord::CAA(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }))
        }
        "issuewild" => {
            let (name, options) = split_caa_value(&unquoted);
            Ok(DnsRecord::CAA(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            }))
        }
        "iodef" => Ok(DnsRecord::CAA(CAARecord::Iodef {
            issuer_critical,
            url: unquoted,
        })),
        other => Err(Error::Parse(format!("unknown CAA tag: {other}"))),
    }
}
