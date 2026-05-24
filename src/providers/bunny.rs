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
    TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector,
    http::{HttpClient, HttpClientBuilder},
    utils::strip_origin_from_name,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, time::Duration};

const DEFAULT_API_ENDPOINT: &str = "https://api.bunny.net";

const BUNNY_TYPE_A: u8 = 0;
const BUNNY_TYPE_AAAA: u8 = 1;
const BUNNY_TYPE_CNAME: u8 = 2;
const BUNNY_TYPE_TXT: u8 = 3;
const BUNNY_TYPE_MX: u8 = 4;
const BUNNY_TYPE_SRV: u8 = 8;
const BUNNY_TYPE_CAA: u8 = 9;
const BUNNY_TYPE_NS: u8 = 12;
const BUNNY_TYPE_TLSA: u8 = 15;

#[derive(Clone)]
pub struct BunnyProvider {
    client: HttpClient,
    endpoint: Cow<'static, str>,
}

impl BunnyProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        Ok(Self {
            client: HttpClientBuilder::default()
                .with_header("AccessKey", api_key.as_ref())
                .with_timeout(timeout)
                .build(),
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
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let zone_data = self.get_zone_data(origin).await?;
        let name = strip_origin_from_name(name.into_name().as_ref(), &zone_data.domain, Some(""));
        let desired = build_contents(record_type, records)?;
        let mut existing_pool: Vec<BunnyDnsRecord> = zone_data
            .records
            .into_iter()
            .filter(|r| r.name == name && r.content.matches_type(record_type))
            .collect();

        let mut to_add = Vec::new();
        for content in desired {
            if let Some(idx) = existing_pool.iter().position(|r| r.content == content) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(content);
            }
        }

        for stale in existing_pool {
            self.delete_record(zone_data.id, stale.id).await?;
        }
        for content in to_add {
            self.add_record(zone_data.id, &name, ttl, &content).await?;
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
        let zone_data = self.get_zone_data(origin).await?;
        let name = strip_origin_from_name(name.into_name().as_ref(), &zone_data.domain, Some(""));
        let desired = build_contents(record_type, records)?;
        let existing: Vec<BunnyDnsRecord> = zone_data
            .records
            .into_iter()
            .filter(|r| r.name == name && r.content.matches_type(record_type))
            .collect();

        for content in desired {
            if existing.iter().any(|r| r.content == content) {
                continue;
            }
            self.add_record(zone_data.id, &name, ttl, &content).await?;
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
        let zone_data = self.get_zone_data(origin).await?;
        let name = strip_origin_from_name(name.into_name().as_ref(), &zone_data.domain, Some(""));
        let to_remove = build_contents(record_type, records)?;
        let existing: Vec<BunnyDnsRecord> = zone_data
            .records
            .into_iter()
            .filter(|r| r.name == name && r.content.matches_type(record_type))
            .collect();

        for content in to_remove {
            if let Some(entry) = existing.iter().find(|r| r.content == content) {
                self.delete_record(zone_data.id, entry.id).await?;
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
        let zone_data = self.get_zone_data(origin).await?;
        let name = strip_origin_from_name(name.into_name().as_ref(), &zone_data.domain, Some(""));
        zone_data
            .records
            .into_iter()
            .filter(|r| r.name == name && r.content.matches_type(record_type))
            .map(|r| DnsRecord::try_from(r.content))
            .collect()
    }

    async fn add_record(
        &self,
        zone_id: u32,
        name: &str,
        ttl: u32,
        content: &BunnyRecordContent,
    ) -> crate::Result<()> {
        let body = AddDnsRecordBody { name, ttl, content };
        self.client
            .put(format!("{}/dnszone/{zone_id}/records", self.endpoint))
            .with_body(&body)?
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, zone_id: u32, record_id: u32) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/dnszone/{zone_id}/records/{record_id}",
                self.endpoint
            ))
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }

    async fn get_zone_data(&self, origin: impl IntoFqdn<'_>) -> crate::Result<PartialDnsZone> {
        let origin = origin.into_name();
        let query_string = serde_urlencoded::to_string([("search", origin.as_ref())])
            .expect("Unable to convert DNS origin into HTTP query string");
        self.client
            .get(format!("{}/dnszone?{query_string}", self.endpoint))
            .send_with_retry::<ApiItems<PartialDnsZone>>(3)
            .await
            .and_then(|r| {
                r.items
                    .into_iter()
                    .find(|z| z.domain == origin.as_ref())
                    .ok_or_else(|| Error::Api(format!("DNS Record {origin} not found")))
            })
    }
}

fn build_contents(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<BunnyRecordContent>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(BunnyRecordContent::try_from(&record)?);
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct BunnyRecordContent {
    #[serde(rename = "Type")]
    pub record_type: u8,
    #[serde(default)]
    pub value: String,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub priority: u16,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub weight: u16,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub flags: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

impl BunnyRecordContent {
    fn matches_type(&self, record_type: DnsRecordType) -> bool {
        bunny_type_for(record_type)
            .map(|t| t == self.record_type)
            .unwrap_or(false)
    }
}

fn bunny_type_for(record_type: DnsRecordType) -> Option<u8> {
    Some(match record_type {
        DnsRecordType::A => BUNNY_TYPE_A,
        DnsRecordType::AAAA => BUNNY_TYPE_AAAA,
        DnsRecordType::CNAME => BUNNY_TYPE_CNAME,
        DnsRecordType::TXT => BUNNY_TYPE_TXT,
        DnsRecordType::MX => BUNNY_TYPE_MX,
        DnsRecordType::SRV => BUNNY_TYPE_SRV,
        DnsRecordType::CAA => BUNNY_TYPE_CAA,
        DnsRecordType::NS => BUNNY_TYPE_NS,
        DnsRecordType::TLSA => BUNNY_TYPE_TLSA,
    })
}

impl TryFrom<&DnsRecord> for BunnyRecordContent {
    type Error = Error;

    fn try_from(record: &DnsRecord) -> crate::Result<Self> {
        Ok(match record {
            DnsRecord::A(addr) => BunnyRecordContent {
                record_type: BUNNY_TYPE_A,
                value: addr.to_string(),
                ..Default::default()
            },
            DnsRecord::AAAA(addr) => BunnyRecordContent {
                record_type: BUNNY_TYPE_AAAA,
                value: addr.to_string(),
                ..Default::default()
            },
            DnsRecord::CNAME(target) => BunnyRecordContent {
                record_type: BUNNY_TYPE_CNAME,
                value: target.clone(),
                ..Default::default()
            },
            DnsRecord::NS(target) => BunnyRecordContent {
                record_type: BUNNY_TYPE_NS,
                value: target.clone(),
                ..Default::default()
            },
            DnsRecord::TXT(text) => BunnyRecordContent {
                record_type: BUNNY_TYPE_TXT,
                value: text.clone(),
                ..Default::default()
            },
            DnsRecord::MX(mx) => BunnyRecordContent {
                record_type: BUNNY_TYPE_MX,
                value: mx.exchange.clone(),
                priority: mx.priority,
                ..Default::default()
            },
            DnsRecord::SRV(srv) => BunnyRecordContent {
                record_type: BUNNY_TYPE_SRV,
                value: srv.target.clone(),
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
                ..Default::default()
            },
            DnsRecord::TLSA(tlsa) => BunnyRecordContent {
                record_type: BUNNY_TYPE_TLSA,
                value: tlsa.to_string(),
                ..Default::default()
            },
            DnsRecord::CAA(caa) => {
                let (flags, tag, value) = caa.clone().decompose();
                BunnyRecordContent {
                    record_type: BUNNY_TYPE_CAA,
                    value,
                    flags,
                    tag: Some(tag),
                    ..Default::default()
                }
            }
        })
    }
}

impl TryFrom<BunnyRecordContent> for DnsRecord {
    type Error = Error;

    fn try_from(content: BunnyRecordContent) -> crate::Result<Self> {
        Ok(match content.record_type {
            BUNNY_TYPE_A => DnsRecord::A(content.value.parse().map_err(|e| {
                Error::Parse(format!("invalid IPv4 address {:?}: {e}", content.value))
            })?),
            BUNNY_TYPE_AAAA => DnsRecord::AAAA(content.value.parse().map_err(|e| {
                Error::Parse(format!("invalid IPv6 address {:?}: {e}", content.value))
            })?),
            BUNNY_TYPE_CNAME => DnsRecord::CNAME(content.value),
            BUNNY_TYPE_NS => DnsRecord::NS(content.value),
            BUNNY_TYPE_TXT => DnsRecord::TXT(content.value),
            BUNNY_TYPE_MX => DnsRecord::MX(MXRecord {
                exchange: content.value,
                priority: content.priority,
            }),
            BUNNY_TYPE_SRV => DnsRecord::SRV(SRVRecord {
                target: content.value,
                priority: content.priority,
                weight: content.weight,
                port: content.port,
            }),
            BUNNY_TYPE_CAA => {
                let tag = content
                    .tag
                    .ok_or_else(|| Error::Parse("CAA record missing Tag field".to_string()))?;
                DnsRecord::CAA(build_caa(content.flags, &tag, content.value)?)
            }
            BUNNY_TYPE_TLSA => DnsRecord::TLSA(parse_tlsa(&content.value)?),
            other => {
                return Err(Error::Parse(format!(
                    "unsupported Bunny record type: {other}"
                )));
            }
        })
    }
}

fn build_caa(flags: u8, tag: &str, value: String) -> crate::Result<CAARecord> {
    let issuer_critical = flags & 0x80 != 0;
    match tag {
        "issue" => {
            let (name, options) = parse_caa_value(&value);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(&value);
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

fn parse_tlsa(value: &str) -> crate::Result<TLSARecord> {
    let mut parts = value.split_whitespace();
    let usage = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("TLSA missing usage field: {value:?}")))?;
    let selector = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("TLSA missing selector field: {value:?}")))?;
    let matching = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("TLSA missing matching field: {value:?}")))?;
    let cert_hex = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("TLSA missing certificate data: {value:?}")))?;
    if parts.next().is_some() {
        return Err(Error::Parse(format!(
            "TLSA unexpected extra fields: {value:?}"
        )));
    }
    let usage = usage
        .parse::<u8>()
        .map_err(|e| Error::Parse(format!("TLSA invalid usage {usage:?}: {e}")))?;
    let selector = selector
        .parse::<u8>()
        .map_err(|e| Error::Parse(format!("TLSA invalid selector {selector:?}: {e}")))?;
    let matching = matching
        .parse::<u8>()
        .map_err(|e| Error::Parse(format!("TLSA invalid matching {matching:?}: {e}")))?;
    Ok(TLSARecord {
        cert_usage: tlsa_cert_usage_from_u8(usage)?,
        selector: tlsa_selector_from_u8(selector)?,
        matching: tlsa_matching_from_u8(matching)?,
        cert_data: decode_hex(cert_hex)?,
    })
}

fn tlsa_cert_usage_from_u8(value: u8) -> crate::Result<TlsaCertUsage> {
    Ok(match value {
        0 => TlsaCertUsage::PkixTa,
        1 => TlsaCertUsage::PkixEe,
        2 => TlsaCertUsage::DaneTa,
        3 => TlsaCertUsage::DaneEe,
        255 => TlsaCertUsage::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA cert usage: {value}"))),
    })
}

fn tlsa_selector_from_u8(value: u8) -> crate::Result<TlsaSelector> {
    Ok(match value {
        0 => TlsaSelector::Full,
        1 => TlsaSelector::Spki,
        255 => TlsaSelector::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA selector: {value}"))),
    })
}

fn tlsa_matching_from_u8(value: u8) -> crate::Result<TlsaMatching> {
    Ok(match value {
        0 => TlsaMatching::Raw,
        1 => TlsaMatching::Sha256,
        2 => TlsaMatching::Sha512,
        255 => TlsaMatching::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA matching: {value}"))),
    })
}

fn decode_hex(hex: &str) -> crate::Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::Parse(format!("invalid hex string: {hex}")));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| Error::Parse(format!("invalid hex byte: {e}")))
        })
        .collect()
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct AddDnsRecordBody<'a> {
    name: &'a str,
    ttl: u32,
    #[serde(flatten)]
    content: &'a BunnyRecordContent,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ApiItems<T> {
    pub items: Vec<T>,
    pub current_page: u32,
    pub total_items: u32,
    pub has_more_items: bool,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PartialDnsZone {
    pub id: u32,
    pub domain: String,
    pub records: Vec<BunnyDnsRecord>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct BunnyDnsRecord {
    pub id: u32,
    pub name: String,
    #[serde(flatten)]
    pub content: BunnyRecordContent,
}
