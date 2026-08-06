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

use crate::utils::{build_caa, parse_tlsa, strip_origin_from_name, strip_trailing_dot};
use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord,
    http::{HttpClient, HttpClientBuilder},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.simply.com/2";

#[derive(Clone)]
pub struct SimplyProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ProductList {
    #[serde(default)]
    pub products: Vec<Product>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Product {
    pub object: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub domain: Option<ProductDomain>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ProductDomain {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub name_idn: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RecordList {
    #[serde(default)]
    pub records: Vec<ExistingDnsRecord>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ExistingDnsRecord {
    pub record_id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub priority: Option<u16>,
}

#[derive(Serialize, Debug, Clone)]
pub struct CreateDnsRecord<'a> {
    #[serde(rename = "type")]
    pub record_type: &'static str,
    pub name: &'a str,
    pub data: &'a str,
    pub ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimplyRecordContent {
    pub record_type: &'static str,
    pub data: String,
    pub priority: Option<u16>,
}

impl SimplyProvider {
    pub(crate) fn new(
        account_name: impl AsRef<str>,
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let credentials = format!("{}:{}", account_name.as_ref(), api_key.as_ref());
        let encoded = BASE64.encode(credentials.as_bytes());
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {encoded}"))
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
}

fn build_contents(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<SimplyRecordContent>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(SimplyRecordContent::try_from(record)?);
    }
    Ok(out)
}

fn record_matches(existing: &ExistingDnsRecord, desired: &SimplyRecordContent) -> bool {
    existing.record_type == desired.record_type
        && existing.data == desired.data
        && (desired.priority.is_none() || existing.priority == desired.priority)
}

fn parse_simply_srv(data: &str, priority: u16) -> crate::Result<DnsRecord> {
    let mut parts = data.split_whitespace();
    let weight = parts.next().and_then(|v| v.parse().ok());
    let port = parts.next().and_then(|v| v.parse().ok());
    let target = parts.next();
    match (weight, port, target) {
        (Some(weight), Some(port), Some(target)) if parts.next().is_none() => {
            Ok(DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target: strip_trailing_dot(target).to_string(),
            }))
        }
        _ => Err(Error::Parse(format!("invalid SRV data: {data}"))),
    }
}

fn parse_simply_caa(data: &str) -> crate::Result<DnsRecord> {
    let mut parts = data.splitn(3, ' ');
    let flags = parts
        .next()
        .and_then(|v| v.parse::<u8>().ok())
        .ok_or_else(|| Error::Parse(format!("invalid CAA data: {data}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA data: {data}")))?;
    let value = parts
        .next()
        .map(|v| v.trim().trim_matches('"'))
        .ok_or_else(|| Error::Parse(format!("invalid CAA data: {data}")))?;
    build_caa(flags, tag, value).map(DnsRecord::CAA)
}

impl TryFrom<DnsRecord> for SimplyRecordContent {
    type Error = Error;

    fn try_from(record: DnsRecord) -> Result<Self, Self::Error> {
        Ok(match record {
            DnsRecord::A(addr) => SimplyRecordContent {
                record_type: "A",
                data: addr.to_string(),
                priority: None,
            },
            DnsRecord::AAAA(addr) => SimplyRecordContent {
                record_type: "AAAA",
                data: addr.to_string(),
                priority: None,
            },
            DnsRecord::CNAME(target) => SimplyRecordContent {
                record_type: "CNAME",
                data: strip_trailing_dot(&target).to_string(),
                priority: None,
            },
            DnsRecord::NS(target) => SimplyRecordContent {
                record_type: "NS",
                data: strip_trailing_dot(&target).to_string(),
                priority: None,
            },
            DnsRecord::MX(mx) => SimplyRecordContent {
                record_type: "MX",
                data: strip_trailing_dot(&mx.exchange).to_string(),
                priority: Some(mx.priority),
            },
            DnsRecord::TXT(text) => SimplyRecordContent {
                record_type: "TXT",
                data: text,
                priority: None,
            },
            DnsRecord::SRV(srv) => SimplyRecordContent {
                record_type: "SRV",
                data: format!(
                    "{} {} {}",
                    srv.weight,
                    srv.port,
                    strip_trailing_dot(&srv.target)
                ),
                priority: Some(srv.priority),
            },
            DnsRecord::TLSA(tlsa) => SimplyRecordContent {
                record_type: "TLSA",
                data: tlsa.to_string(),
                priority: None,
            },
            DnsRecord::CAA(caa) => SimplyRecordContent {
                record_type: "CAA",
                data: caa.to_string(),
                priority: None,
            },
        })
    }
}

impl TryFrom<ExistingDnsRecord> for DnsRecord {
    type Error = Error;

    fn try_from(record: ExistingDnsRecord) -> Result<Self, Self::Error> {
        match record.record_type.as_str() {
            "A" => record
                .data
                .parse()
                .map(DnsRecord::A)
                .map_err(|e| Error::Parse(format!("invalid A data: {e}"))),
            "AAAA" => record
                .data
                .parse()
                .map(DnsRecord::AAAA)
                .map_err(|e| Error::Parse(format!("invalid AAAA data: {e}"))),
            "CNAME" => Ok(DnsRecord::CNAME(record.data)),
            "NS" => Ok(DnsRecord::NS(record.data)),
            "MX" => Ok(DnsRecord::MX(MXRecord {
                exchange: record.data,
                priority: record.priority.unwrap_or_default(),
            })),
            "TXT" => Ok(DnsRecord::TXT(record.data)),
            "SRV" => parse_simply_srv(&record.data, record.priority.unwrap_or_default()),
            "TLSA" => parse_tlsa(&record.data),
            "CAA" => parse_simply_caa(&record.data),
            other => Err(Error::Parse(format!(
                "Unsupported Simply.com record type: {other}"
            ))),
        }
    }
}
