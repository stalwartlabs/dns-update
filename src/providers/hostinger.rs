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
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://developers.hostinger.com";

#[derive(Clone)]
pub struct HostingerProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Serialize, Debug)]
pub struct ZoneRequest {
    pub overwrite: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub zone: Vec<RecordSet>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecordSet {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub ttl: u32,
    pub records: Vec<RecordValue>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecordValue {
    pub content: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_disabled: bool,
}

#[derive(Serialize, Debug)]
pub struct Filters {
    pub filters: Vec<Filter>,
}

#[derive(Serialize, Debug)]
pub struct Filter {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl HostingerProvider {
    pub(crate) fn new(
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let token = api_token.as_ref();
        if token.is_empty() {
            return Err(Error::Api("Hostinger API token is empty".to_string()));
        }
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {token}"))
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

    fn zone_url(&self, domain: &str) -> String {
        format!("{}/api/dns/v1/zones/{}", self.endpoint, domain)
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));

        if records.is_empty() {
            let request = Filters {
                filters: vec![Filter {
                    name: subdomain,
                    record_type: record_type.as_str().to_string(),
                }],
            };
            return self
                .client
                .delete(self.zone_url(&domain))
                .with_body(request)?
                .send_raw()
                .await
                .map(|_| ())
                .or_else(|err| match err {
                    Error::NotFound => Ok(()),
                    err => Err(err),
                });
        }

        let contents = build_contents(record_type, records);
        let new_rrset = RecordSet {
            name: subdomain.clone(),
            record_type: record_type.as_str().to_string(),
            ttl,
            records: contents
                .into_iter()
                .map(|content| RecordValue {
                    content,
                    is_disabled: false,
                })
                .collect(),
        };

        let zone = self.fetch_zone(&domain).await?;
        let mut next: Vec<RecordSet> = zone
            .into_iter()
            .filter(|r| !(r.name == subdomain && r.record_type == record_type.as_str()))
            .collect();
        next.push(new_rrset);

        let request = ZoneRequest {
            overwrite: true,
            zone: next,
        };

        self.client
            .put(self.zone_url(&domain))
            .with_body(request)?
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let to_add = build_contents(record_type, records);

        let zone = self.fetch_zone(&domain).await?;
        let mut next: Vec<RecordSet> = Vec::with_capacity(zone.len() + 1);
        let mut merged = false;
        let mut changed = false;

        for mut rrset in zone {
            if rrset.name == subdomain && rrset.record_type == record_type.as_str() {
                merged = true;
                let before = rrset.records.len();
                for content in &to_add {
                    if !rrset.records.iter().any(|r| &r.content == content) {
                        rrset.records.push(RecordValue {
                            content: content.clone(),
                            is_disabled: false,
                        });
                    }
                }
                if rrset.records.len() != before {
                    changed = true;
                }
                rrset.ttl = ttl;
            }
            next.push(rrset);
        }

        if !merged {
            next.push(RecordSet {
                name: subdomain,
                record_type: record_type.as_str().to_string(),
                ttl,
                records: to_add
                    .into_iter()
                    .map(|content| RecordValue {
                        content,
                        is_disabled: false,
                    })
                    .collect(),
            });
            changed = true;
        }

        if !changed {
            return Ok(());
        }

        let request = ZoneRequest {
            overwrite: true,
            zone: next,
        };

        self.client
            .put(self.zone_url(&domain))
            .with_body(request)?
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let to_remove = build_contents(record_type, records);

        let zone = self.fetch_zone(&domain).await?;
        let mut next: Vec<RecordSet> = Vec::with_capacity(zone.len());
        let mut changed = false;
        let mut became_empty = false;

        for rrset in zone {
            if rrset.name == subdomain && rrset.record_type == record_type.as_str() {
                let before = rrset.records.len();
                let filtered: Vec<RecordValue> = rrset
                    .records
                    .into_iter()
                    .filter(|r| !to_remove.iter().any(|c| c == &r.content))
                    .collect();
                if filtered.len() != before {
                    changed = true;
                }
                if filtered.is_empty() {
                    became_empty = true;
                    continue;
                }
                next.push(RecordSet {
                    name: rrset.name,
                    record_type: rrset.record_type,
                    ttl: rrset.ttl,
                    records: filtered,
                });
            } else {
                next.push(rrset);
            }
        }

        if !changed {
            return Ok(());
        }

        if became_empty {
            let request = Filters {
                filters: vec![Filter {
                    name: subdomain,
                    record_type: record_type.as_str().to_string(),
                }],
            };
            return self
                .client
                .delete(self.zone_url(&domain))
                .with_body(request)?
                .send_raw()
                .await
                .map(|_| ())
                .or_else(|err| match err {
                    Error::NotFound => Ok(()),
                    err => Err(err),
                });
        }

        let request = ZoneRequest {
            overwrite: true,
            zone: next,
        };

        self.client
            .put(self.zone_url(&domain))
            .with_body(request)?
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));

        let rrset = self
            .fetch_record_set(&domain, &subdomain, record_type)
            .await?;
        match rrset {
            None => Ok(Vec::new()),
            Some(rrset) => rrset
                .records
                .into_iter()
                .map(|r| parse_record(record_type, &r.content))
                .collect(),
        }
    }

    async fn fetch_zone(&self, domain: &str) -> crate::Result<Vec<RecordSet>> {
        let response = self.client.get(self.zone_url(domain)).send_raw().await?;
        if response.is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_str(&response)
            .map_err(|err| Error::Serialize(format!("Failed to deserialize Hostinger zone: {err}")))
    }

    async fn fetch_record_set(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Option<RecordSet>> {
        let zone = self.fetch_zone(domain).await?;
        Ok(zone
            .into_iter()
            .find(|r| r.name == subdomain && r.record_type == record_type.as_str()))
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

fn build_contents(_expected_type: DnsRecordType, records: Vec<DnsRecord>) -> Vec<String> {
    records.iter().map(encode_record).collect()
}

fn ensure_fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

fn encode_record(record: &DnsRecord) -> String {
    match record {
        DnsRecord::A(ip) => ip.to_string(),
        DnsRecord::AAAA(ip) => ip.to_string(),
        DnsRecord::CNAME(value) => ensure_fqdn(value),
        DnsRecord::NS(value) => ensure_fqdn(value),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, ensure_fqdn(&mx.exchange)),
        DnsRecord::TXT(value) => value.clone(),
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            ensure_fqdn(&srv.target)
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    }
}

fn strip_trailing_dot(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
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
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(strip_trailing_dot(content).to_string())),
        DnsRecordType::NS => Ok(DnsRecord::NS(strip_trailing_dot(content).to_string())),
        DnsRecordType::MX => parse_mx(content),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(unquote_txt(content))),
        DnsRecordType::SRV => parse_srv(content),
        DnsRecordType::TLSA => parse_tlsa(content),
        DnsRecordType::CAA => parse_caa(content),
    }
}

fn unquote_txt(content: &str) -> String {
    let trimmed = content
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(content);
    trimmed.replace("\\\"", "\"")
}

fn parse_mx(content: &str) -> crate::Result<DnsRecord> {
    let (prio, exchange) = content
        .split_once(' ')
        .ok_or_else(|| Error::Parse(format!("invalid MX record: {content}")))?;
    let priority: u16 = prio
        .parse()
        .map_err(|e| Error::Parse(format!("invalid MX priority {prio}: {e}")))?;
    Ok(DnsRecord::MX(MXRecord {
        priority,
        exchange: strip_trailing_dot(exchange.trim()).to_string(),
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
        target: strip_trailing_dot(target).to_string(),
    }))
}

fn parse_tlsa(content: &str) -> crate::Result<DnsRecord> {
    let mut parts = content.split_whitespace();
    let usage: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA usage: {e}")))?;
    let selector: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA selector: {e}")))?;
    let matching: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA matching: {e}")))?;
    let hex: String = parts.collect::<Vec<_>>().join("");
    Ok(DnsRecord::TLSA(TLSARecord {
        cert_usage: tlsa_cert_usage_from_u8(usage)?,
        selector: tlsa_selector_from_u8(selector)?,
        matching: tlsa_matching_from_u8(matching)?,
        cert_data: decode_hex(&hex)?,
    }))
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

fn parse_caa(content: &str) -> crate::Result<DnsRecord> {
    let mut parts = content.splitn(3, ' ');
    let flags: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags: {e}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {content}")))?
        .to_string();
    let raw_value = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {content}")))?;
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
