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

const DEFAULT_API_ENDPOINT: &str = "https://api.scaleway.com/domain/v2beta1";

#[derive(Clone)]
pub struct ScalewayProvider {
    client: HttpClient,
    endpoint: Cow<'static, str>,
}

#[derive(Serialize, Debug)]
struct ZoneRecordsRequest {
    return_all_records: bool,
    disallow_new_zone_creation: bool,
    changes: Vec<RecordChange>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
enum RecordChange {
    Add {
        records: Vec<RecordEntry>,
    },
    Set {
        id_fields: RecordIdentifier,
        records: Vec<RecordEntry>,
    },
    Delete {
        id_fields: RecordIdentifier,
    },
}

#[derive(Serialize, Debug)]
struct RecordEntry {
    name: String,
    #[serde(rename = "type")]
    record_type: &'static str,
    data: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
}

#[derive(Serialize, Debug)]
struct RecordIdentifier {
    name: String,
    #[serde(rename = "type")]
    record_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ListRecordsResponse {
    #[serde(default)]
    records: Vec<ListedRecord>,
}

#[derive(Deserialize, Debug)]
struct ListedRecord {
    #[serde(rename = "type")]
    record_type: String,
    data: String,
    #[serde(default)]
    priority: u16,
}

impl ScalewayProvider {
    pub(crate) fn new(api_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("X-Auth-Token", api_token.as_ref())
            .with_timeout(timeout)
            .build();
        Self {
            client,
            endpoint: Cow::Borrowed(DEFAULT_API_ENDPOINT),
        }
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
        check_record_types(record_type, &records)?;
        let zone = origin.into_name().into_owned();
        let fqdn = name.into_name().into_owned();
        let short = strip_origin_from_name(&fqdn, &zone, Some("@"));
        let rtype = record_type.as_str();

        let change = if records.is_empty() {
            RecordChange::Delete {
                id_fields: RecordIdentifier {
                    name: short,
                    record_type: rtype,
                    data: None,
                },
            }
        } else {
            let entries = records
                .into_iter()
                .map(|r| build_entry(short.clone(), r, ttl))
                .collect::<crate::Result<Vec<_>>>()?;
            RecordChange::Set {
                id_fields: RecordIdentifier {
                    name: short,
                    record_type: rtype,
                    data: None,
                },
                records: entries,
            }
        };

        self.patch_zone(
            &zone,
            ZoneRecordsRequest {
                return_all_records: false,
                disallow_new_zone_creation: true,
                changes: vec![change],
            },
        )
        .await
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
        let zone = origin.into_name().into_owned();
        let fqdn = name.into_name().into_owned();
        let short = strip_origin_from_name(&fqdn, &zone, Some("@"));

        let entries = records
            .into_iter()
            .map(|r| build_entry(short.clone(), r, ttl))
            .collect::<crate::Result<Vec<_>>>()?;

        self.patch_zone(
            &zone,
            ZoneRecordsRequest {
                return_all_records: false,
                disallow_new_zone_creation: true,
                changes: vec![RecordChange::Add { records: entries }],
            },
        )
        .await
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
        let zone = origin.into_name().into_owned();
        let fqdn = name.into_name().into_owned();
        let short = strip_origin_from_name(&fqdn, &zone, Some("@"));
        let rtype = record_type.as_str();

        let changes = records
            .into_iter()
            .map(|r| {
                let entry = build_entry(short.clone(), r, 0)?;
                Ok(RecordChange::Delete {
                    id_fields: RecordIdentifier {
                        name: short.clone(),
                        record_type: rtype,
                        data: Some(entry.data),
                    },
                })
            })
            .collect::<crate::Result<Vec<_>>>()?;

        self.patch_zone(
            &zone,
            ZoneRecordsRequest {
                return_all_records: false,
                disallow_new_zone_creation: true,
                changes,
            },
        )
        .await
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let zone = origin.into_name().into_owned();
        let fqdn = name.into_name().into_owned();
        let short = strip_origin_from_name(&fqdn, &zone, Some("@"));
        let rtype = record_type.as_str();

        let query = serde_urlencoded::to_string([("name", short.as_str()), ("type", rtype)])
            .map_err(|err| Error::Serialize(format!("Failed to encode query: {err}")))?;
        let url = format!("{}/dns-zones/{}/records?{}", self.endpoint, zone, query);

        let response: ListRecordsResponse = self.client.get(url).send().await?;
        let mut out = Vec::new();
        for record in response.records {
            if record.record_type != rtype {
                continue;
            }
            out.push(parse_listed_record(record_type, &record)?);
        }
        Ok(out)
    }

    async fn patch_zone(&self, zone: &str, body: ZoneRecordsRequest) -> crate::Result<()> {
        self.client
            .patch(format!("{}/dns-zones/{}/records", self.endpoint, zone))
            .with_body(body)?
            .send_raw()
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

fn build_entry(name: String, record: DnsRecord, ttl: u32) -> crate::Result<RecordEntry> {
    let record_type = record.as_type().as_str();
    let priority = match &record {
        DnsRecord::MX(mx) => Some(mx.priority),
        DnsRecord::SRV(srv) => Some(srv.priority),
        _ => None,
    };
    let data = match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content,
        DnsRecord::NS(content) => content,
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, mx.exchange),
        DnsRecord::TXT(content) => format!("\"{}\"", content.replace('"', "\\\"")),
        DnsRecord::SRV(srv) => format!("{} {} {}", srv.weight, srv.port, srv.target),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    };
    Ok(RecordEntry {
        name,
        record_type,
        data,
        ttl,
        priority,
    })
}

fn parse_listed_record(expected: DnsRecordType, record: &ListedRecord) -> crate::Result<DnsRecord> {
    Ok(match expected {
        DnsRecordType::A => DnsRecord::A(
            record
                .data
                .parse()
                .map_err(|e| Error::Parse(format!("invalid A data: {e}")))?,
        ),
        DnsRecordType::AAAA => DnsRecord::AAAA(
            record
                .data
                .parse()
                .map_err(|e| Error::Parse(format!("invalid AAAA data: {e}")))?,
        ),
        DnsRecordType::CNAME => DnsRecord::CNAME(strip_trailing_dot(&record.data)),
        DnsRecordType::NS => DnsRecord::NS(strip_trailing_dot(&record.data)),
        DnsRecordType::MX => DnsRecord::MX(parse_mx(&record.data, record.priority)?),
        DnsRecordType::TXT => DnsRecord::TXT(unquote_txt(&record.data)),
        DnsRecordType::SRV => DnsRecord::SRV(parse_srv(&record.data, record.priority)?),
        DnsRecordType::TLSA => DnsRecord::TLSA(parse_tlsa(&record.data)?),
        DnsRecordType::CAA => DnsRecord::CAA(parse_caa(&record.data)?),
    })
}

fn strip_trailing_dot(s: &str) -> String {
    s.strip_suffix('.').unwrap_or(s).to_string()
}

fn unquote_txt(content: &str) -> String {
    let trimmed = content
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(content);
    trimmed.replace("\\\"", "\"")
}

fn parse_mx(data: &str, fallback_priority: u16) -> crate::Result<MXRecord> {
    let parts: Vec<&str> = data.split_whitespace().collect();
    match parts.as_slice() {
        [prio, exchange] => Ok(MXRecord {
            priority: prio
                .parse()
                .map_err(|e| Error::Parse(format!("invalid MX priority: {e}")))?,
            exchange: strip_trailing_dot(exchange),
        }),
        [exchange] => Ok(MXRecord {
            priority: fallback_priority,
            exchange: strip_trailing_dot(exchange),
        }),
        _ => Err(Error::Parse(format!("invalid MX data: {data}"))),
    }
}

fn parse_srv(data: &str, priority: u16) -> crate::Result<SRVRecord> {
    let parts: Vec<&str> = data.split_whitespace().collect();
    match parts.as_slice() {
        [weight, port, target] => Ok(SRVRecord {
            priority,
            weight: weight
                .parse()
                .map_err(|e| Error::Parse(format!("invalid SRV weight: {e}")))?,
            port: port
                .parse()
                .map_err(|e| Error::Parse(format!("invalid SRV port: {e}")))?,
            target: strip_trailing_dot(target),
        }),
        [p, weight, port, target] => Ok(SRVRecord {
            priority: p
                .parse()
                .map_err(|e| Error::Parse(format!("invalid SRV priority: {e}")))?,
            weight: weight
                .parse()
                .map_err(|e| Error::Parse(format!("invalid SRV weight: {e}")))?,
            port: port
                .parse()
                .map_err(|e| Error::Parse(format!("invalid SRV port: {e}")))?,
            target: strip_trailing_dot(target),
        }),
        _ => Err(Error::Parse(format!("invalid SRV data: {data}"))),
    }
}

fn parse_tlsa(data: &str) -> crate::Result<TLSARecord> {
    let parts: Vec<&str> = data.split_whitespace().collect();
    if parts.len() != 4 {
        return Err(Error::Parse(format!("invalid TLSA data: {data}")));
    }
    let usage = parts[0]
        .parse::<u8>()
        .map_err(|e| Error::Parse(format!("invalid TLSA usage: {e}")))?;
    let selector = parts[1]
        .parse::<u8>()
        .map_err(|e| Error::Parse(format!("invalid TLSA selector: {e}")))?;
    let matching = parts[2]
        .parse::<u8>()
        .map_err(|e| Error::Parse(format!("invalid TLSA matching: {e}")))?;
    let cert_data = decode_hex(parts[3])?;
    Ok(TLSARecord {
        cert_usage: tlsa_cert_usage_from_u8(usage)?,
        selector: tlsa_selector_from_u8(selector)?,
        matching: tlsa_matching_from_u8(matching)?,
        cert_data,
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

fn parse_caa(data: &str) -> crate::Result<CAARecord> {
    let mut iter = data.splitn(3, char::is_whitespace);
    let flags_str = iter
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA data: {data}")))?;
    let tag = iter
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA data: {data}")))?;
    let value_raw = iter
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA data: {data}")))?
        .trim();
    let flags: u8 = flags_str
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags: {e}")))?;
    let issuer_critical = flags & 0x80 != 0;
    let value = value_raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(value_raw);

    match tag {
        "issue" => {
            let (name, options) = parse_caa_value(value);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(value);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: value.to_string(),
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
