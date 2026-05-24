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
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api.autodns.com/v1";
pub const DEFAULT_CONTEXT: u32 = 4;

#[derive(Clone)]
pub struct AutodnsProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Serialize, Debug)]
pub struct ZoneStream {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub adds: Vec<ResourceRecord>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rems: Vec<ResourceRecord>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,
    pub ttl: u32,
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pref: u32,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

#[derive(Deserialize, Debug)]
pub struct Zone {
    #[serde(rename = "origin", default)]
    pub origin: String,
    #[serde(rename = "resourceRecords", default)]
    pub resource_records: Vec<ResourceRecord>,
}

#[derive(Deserialize, Debug)]
pub struct DataZoneResponse {
    #[serde(default)]
    pub data: Vec<Zone>,
}

impl AutodnsProvider {
    pub(crate) fn new(
        username: impl AsRef<str>,
        password: impl AsRef<str>,
        context: Option<u32>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let user = username.as_ref();
        let pass = password.as_ref();
        if user.is_empty() {
            return Err(Error::Api("AutoDNS username is empty".to_string()));
        }
        if pass.is_empty() {
            return Err(Error::Api("AutoDNS password is empty".to_string()));
        }
        let encoded = STANDARD.encode(format!("{user}:{pass}"));
        let ctx = context.unwrap_or(DEFAULT_CONTEXT);
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {encoded}"))
            .with_header("X-Domainrobot-Context", ctx.to_string())
            .with_header("Accept", "application/json")
            .with_timeout(timeout)
            .build();
        Ok(Self {
            client,
            endpoint: DEFAULT_ENDPOINT.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    fn stream_url(&self, domain: &str) -> String {
        format!("{}/zone/{}/_stream", self.endpoint, domain)
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
        let domain = origin.into_name();
        let fqdn = name.into_fqdn();

        let existing = self.find_existing(&domain, &fqdn, record_type).await?;
        let desired: Vec<ResourceRecord> = records
            .iter()
            .map(|r| build_resource_record(&fqdn, r, ttl))
            .collect();

        let mut rems: Vec<ResourceRecord> = Vec::new();
        for current in &existing {
            if !desired.iter().any(|d| records_equal(d, current)) {
                rems.push(current.clone());
            }
        }
        let mut adds: Vec<ResourceRecord> = Vec::new();
        for want in &desired {
            if !existing.iter().any(|e| records_equal(want, e)) {
                adds.push(want.clone());
            }
        }

        if adds.is_empty() && rems.is_empty() {
            return Ok(());
        }

        let body = ZoneStream { adds, rems };
        self.client
            .post(self.stream_url(&domain))
            .with_body(body)?
            .send_raw()
            .await
            .map(|_| ())
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
        let domain = origin.into_name();
        let fqdn = name.into_fqdn();

        let existing = self.find_existing(&domain, &fqdn, record_type).await?;
        let mut adds: Vec<ResourceRecord> = Vec::new();
        for record in &records {
            let candidate = build_resource_record(&fqdn, record, ttl);
            if existing.iter().any(|e| records_equal(&candidate, e)) {
                continue;
            }
            adds.push(candidate);
        }

        if adds.is_empty() {
            return Ok(());
        }

        let body = ZoneStream { adds, rems: vec![] };
        self.client
            .post(self.stream_url(&domain))
            .with_body(body)?
            .send_raw()
            .await
            .map(|_| ())
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
        let domain = origin.into_name();
        let fqdn = name.into_fqdn();

        let existing = self.find_existing(&domain, &fqdn, record_type).await?;
        let mut rems: Vec<ResourceRecord> = Vec::new();
        for record in &records {
            let candidate = build_resource_record(&fqdn, record, 0);
            if let Some(found) = existing.iter().find(|e| records_equal(&candidate, e))
                && !rems.iter().any(|r| r == found)
            {
                rems.push(found.clone());
            }
        }

        if rems.is_empty() {
            return Ok(());
        }

        let body = ZoneStream { adds: vec![], rems };
        self.client
            .post(self.stream_url(&domain))
            .with_body(body)?
            .send_raw()
            .await
            .map(|_| ())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let domain = origin.into_name();
        let fqdn = name.into_fqdn();
        let existing = self.find_existing(&domain, &fqdn, record_type).await?;
        existing
            .into_iter()
            .map(|r| resource_record_to_dns_record(&r, record_type))
            .collect()
    }

    async fn find_existing(
        &self,
        domain: &str,
        fqdn: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ResourceRecord>> {
        let url = format!("{}/zone/{}/_search", self.endpoint, domain);
        let response = self
            .client
            .post(url)
            .with_raw_body("{}".to_string())
            .send_raw()
            .await
            .ok();
        let Some(body) = response else {
            return Ok(Vec::new());
        };
        if body.is_empty() {
            return Ok(Vec::new());
        }
        let parsed: DataZoneResponse = match serde_json::from_str(&body) {
            Ok(p) => p,
            Err(_) => return Ok(Vec::new()),
        };
        let target_name = strip_origin_from_name(fqdn, domain, Some("@"));
        let type_str = record_type.as_str();
        let mut matches = Vec::new();
        for zone in parsed.data {
            for r in zone.resource_records {
                let candidate_name = strip_origin_from_name(&r.name, domain, Some("@"));
                if candidate_name == target_name && r.record_type == type_str {
                    matches.push(r);
                }
            }
        }
        Ok(matches)
    }
}

fn records_equal(a: &ResourceRecord, b: &ResourceRecord) -> bool {
    a.record_type == b.record_type && a.value == b.value && a.pref == b.pref
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

fn resource_record_to_dns_record(
    rr: &ResourceRecord,
    expected_type: DnsRecordType,
) -> crate::Result<DnsRecord> {
    Ok(match expected_type {
        DnsRecordType::A => DnsRecord::A(
            rr.value
                .parse()
                .map_err(|e| Error::Parse(format!("invalid A: {e}")))?,
        ),
        DnsRecordType::AAAA => DnsRecord::AAAA(
            rr.value
                .parse()
                .map_err(|e| Error::Parse(format!("invalid AAAA: {e}")))?,
        ),
        DnsRecordType::CNAME => DnsRecord::CNAME(autodns_strip_dot(&rr.value)),
        DnsRecordType::NS => DnsRecord::NS(autodns_strip_dot(&rr.value)),
        DnsRecordType::MX => DnsRecord::MX(MXRecord {
            exchange: autodns_strip_dot(&rr.value),
            priority: u16::try_from(rr.pref).unwrap_or(0),
        }),
        DnsRecordType::TXT => DnsRecord::TXT(rr.value.clone()),
        DnsRecordType::SRV => {
            let mut parts = rr.value.split_whitespace();
            let weight: u16 = parts
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::Parse(format!("invalid SRV: {}", rr.value)))?;
            let port: u16 = parts
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::Parse(format!("invalid SRV: {}", rr.value)))?;
            let target = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid SRV: {}", rr.value)))?
                .to_string();
            DnsRecord::SRV(SRVRecord {
                priority: u16::try_from(rr.pref).unwrap_or(0),
                weight,
                port,
                target: autodns_strip_dot(&target),
            })
        }
        DnsRecordType::TLSA => {
            let mut parts = rr.value.split_whitespace();
            let usage: u8 = parts
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::Parse(format!("invalid TLSA: {}", rr.value)))?;
            let selector: u8 = parts
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::Parse(format!("invalid TLSA: {}", rr.value)))?;
            let matching: u8 = parts
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| Error::Parse(format!("invalid TLSA: {}", rr.value)))?;
            let hex = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid TLSA: {}", rr.value)))?;
            let cert_data = autodns_decode_hex(hex)?;
            DnsRecord::TLSA(TLSARecord {
                cert_usage: autodns_tlsa_cert_usage(usage)?,
                selector: autodns_tlsa_selector(selector)?,
                matching: autodns_tlsa_matching(matching)?,
                cert_data,
            })
        }
        DnsRecordType::CAA => DnsRecord::CAA(autodns_parse_caa(&rr.value)?),
    })
}

fn autodns_strip_dot(s: &str) -> String {
    s.strip_suffix('.').unwrap_or(s).to_string()
}

fn autodns_decode_hex(hex: &str) -> crate::Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::Parse(format!("invalid hex: {hex}")));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| Error::Parse(e.to_string())))
        .collect()
}

fn autodns_tlsa_cert_usage(value: u8) -> crate::Result<TlsaCertUsage> {
    Ok(match value {
        0 => TlsaCertUsage::PkixTa,
        1 => TlsaCertUsage::PkixEe,
        2 => TlsaCertUsage::DaneTa,
        3 => TlsaCertUsage::DaneEe,
        255 => TlsaCertUsage::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA cert usage: {value}"))),
    })
}

fn autodns_tlsa_selector(value: u8) -> crate::Result<TlsaSelector> {
    Ok(match value {
        0 => TlsaSelector::Full,
        1 => TlsaSelector::Spki,
        255 => TlsaSelector::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA selector: {value}"))),
    })
}

fn autodns_tlsa_matching(value: u8) -> crate::Result<TlsaMatching> {
    Ok(match value {
        0 => TlsaMatching::Raw,
        1 => TlsaMatching::Sha256,
        2 => TlsaMatching::Sha512,
        255 => TlsaMatching::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA matching: {value}"))),
    })
}

fn autodns_parse_caa(value: &str) -> crate::Result<CAARecord> {
    let mut parts = value.splitn(3, ' ');
    let flags: u8 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("invalid CAA: {value}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA: {value}")))?
        .to_string();
    let rest = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA: {value}")))?
        .trim();
    let inner = rest
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(rest);
    let issuer_critical = flags & 0x80 != 0;
    match tag.as_str() {
        "issue" => {
            let (name, options) = autodns_split_caa_value(inner);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = autodns_split_caa_value(inner);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: inner.to_string(),
        }),
        other => Err(Error::Parse(format!("unknown CAA tag: {other}"))),
    }
}

fn autodns_split_caa_value(value: &str) -> (Option<String>, Vec<KeyValue>) {
    let mut iter = value.split(';').map(str::trim);
    let name_part = iter.next().unwrap_or("").trim().to_string();
    let name = if name_part.is_empty() {
        None
    } else {
        Some(name_part)
    };
    let options = iter
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

fn build_resource_record(name: &str, record: &DnsRecord, ttl: u32) -> ResourceRecord {
    let (value, pref) = match record {
        DnsRecord::A(ip) => (ip.to_string(), 0),
        DnsRecord::AAAA(ip) => (ip.to_string(), 0),
        DnsRecord::CNAME(value) => (value.clone(), 0),
        DnsRecord::NS(value) => (value.clone(), 0),
        DnsRecord::MX(mx) => (mx.exchange.clone(), u32::from(mx.priority)),
        DnsRecord::TXT(value) => (value.clone(), 0),
        DnsRecord::SRV(srv) => (
            format!("{} {} {}", srv.weight, srv.port, srv.target),
            u32::from(srv.priority),
        ),
        DnsRecord::TLSA(tlsa) => (tlsa.to_string(), 0),
        DnsRecord::CAA(caa) => (caa.to_string(), 0),
    };
    ResourceRecord {
        name: name.to_string(),
        ttl,
        record_type: record.as_type().as_str().to_string(),
        value,
        pref,
    }
}
