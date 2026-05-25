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
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://rest.easydns.net";

#[derive(Clone)]
pub struct EasyDnsProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct ZoneRecordPayload<'a> {
    domain: &'a str,
    host: &'a str,
    ttl: String,
    prio: String,
    #[serde(rename = "type")]
    record_type: &'a str,
    rdata: String,
}

#[derive(Deserialize, Debug, Default, Clone)]
#[allow(dead_code)]
struct ZoneRecord {
    #[serde(default)]
    id: String,
    #[serde(default)]
    host: String,
    #[serde(default, rename = "type")]
    record_type: String,
    #[serde(default)]
    rdata: String,
    #[serde(default)]
    ttl: String,
    #[serde(default)]
    prio: String,
}

#[derive(Deserialize, Debug)]
struct ApiEnvelope<T> {
    #[serde(default)]
    data: Option<T>,
    #[serde(default)]
    error: Option<ApiError>,
}

#[derive(Deserialize, Debug)]
struct ApiError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordWire {
    rdata: String,
    prio: u16,
}

impl EasyDnsProvider {
    pub(crate) fn new(
        token: impl AsRef<str>,
        key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let token = token.as_ref();
        let key = key.as_ref();
        if token.is_empty() || key.is_empty() {
            return Err(Error::Api(
                "EasyDNS API token and key must not be empty".to_string(),
            ));
        }

        let credentials = STANDARD.encode(format!("{token}:{key}"));
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {credentials}"))
            .with_header("Accept", "application/json")
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
        reject_unsupported(record_type)?;
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let desired = build_wire(record_type, records)?;
        let existing = self.list_at(&domain, &subdomain, record_type).await?;

        let mut to_add: Vec<RecordWire> = Vec::new();
        let mut existing_pool = existing;

        for wire in desired {
            if let Some(idx) = existing_pool.iter().position(|r| record_wire_of(r) == wire) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(wire);
            }
        }

        for entry in existing_pool {
            self.delete_record(&domain, &entry.id).await?;
        }
        for wire in to_add {
            self.put_record(&domain, &subdomain, record_type, ttl, wire)
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
        reject_unsupported(record_type)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let desired = build_wire(record_type, records)?;
        let existing = self.list_at(&domain, &subdomain, record_type).await?;

        for wire in desired {
            if existing.iter().any(|r| record_wire_of(r) == wire) {
                continue;
            }
            self.put_record(&domain, &subdomain, record_type, ttl, wire)
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
        reject_unsupported(record_type)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let to_remove = build_wire(record_type, records)?;
        let existing = self.list_at(&domain, &subdomain, record_type).await?;

        for wire in to_remove {
            if let Some(entry) = existing.iter().find(|r| record_wire_of(r) == wire) {
                self.delete_record(&domain, &entry.id).await?;
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
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let listed = self.list_at(&domain, &subdomain, record_type).await?;
        listed
            .into_iter()
            .map(|r| parse_record(record_type, &r.rdata, &r.prio))
            .collect()
    }

    async fn list_at(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ZoneRecord>> {
        let all = self.list_all(domain).await?;
        Ok(all
            .into_iter()
            .filter(|r| r.record_type == record_type.as_str() && r.host == subdomain)
            .collect())
    }

    async fn list_all(&self, domain: &str) -> crate::Result<Vec<ZoneRecord>> {
        let body = self
            .client
            .get(format!(
                "{}/zones/records/all/{}?format=json",
                self.endpoint, domain,
            ))
            .send_raw()
            .await?;
        let envelope: ApiEnvelope<Vec<ZoneRecord>> = serde_json::from_str(&body)
            .map_err(|e| Error::Parse(format!("Invalid EasyDNS response: {e}")))?;
        check_error(envelope.error)?;
        Ok(envelope.data.unwrap_or_default())
    }

    async fn put_record(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
        wire: RecordWire,
    ) -> crate::Result<()> {
        let payload = ZoneRecordPayload {
            domain,
            host: subdomain,
            ttl: ttl.to_string(),
            prio: wire.prio.to_string(),
            record_type: record_type.as_str(),
            rdata: wire.rdata,
        };

        let body = self
            .client
            .put(format!(
                "{}/zones/records/add/{}/{}?format=json",
                self.endpoint,
                domain,
                record_type.as_str(),
            ))
            .with_body(payload)?
            .send_raw()
            .await?;

        let envelope: ApiEnvelope<ZoneRecord> = serde_json::from_str(&body)
            .map_err(|e| Error::Parse(format!("Invalid EasyDNS response: {e}")))?;
        check_error(envelope.error)
    }

    async fn delete_record(&self, domain: &str, record_id: &str) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/zones/records/{}/{}?format=json",
                self.endpoint, domain, record_id,
            ))
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }
}

fn check_error(error: Option<ApiError>) -> crate::Result<()> {
    if let Some(err) = error {
        Err(Error::Api(format!(
            "EasyDNS error {}: {}",
            err.code, err.message
        )))
    } else {
        Ok(())
    }
}

fn record_wire_of(record: &ZoneRecord) -> RecordWire {
    let prio = record.prio.parse::<u16>().unwrap_or(0);
    let rdata = if matches!(record.record_type.as_str(), "CNAME" | "NS" | "MX" | "SRV") {
        record.rdata.trim_end_matches('.').to_string()
    } else {
        record.rdata.clone()
    };
    RecordWire { rdata, prio }
}

fn reject_unsupported(record_type: DnsRecordType) -> crate::Result<()> {
    if record_type == DnsRecordType::TLSA {
        return Err(Error::Api(
            "TLSA records are not supported by EasyDNS".to_string(),
        ));
    }
    Ok(())
}

fn build_wire(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<RecordWire>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(render_wire(record)?);
    }
    Ok(out)
}

fn render_wire(record: DnsRecord) -> crate::Result<RecordWire> {
    let prio = record.priority().unwrap_or(0);
    let rdata = match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content.trim_end_matches('.').to_string(),
        DnsRecord::NS(content) => content.trim_end_matches('.').to_string(),
        DnsRecord::MX(mx) => mx.exchange.trim_end_matches('.').to_string(),
        DnsRecord::TXT(content) => content,
        DnsRecord::SRV(srv) => format!(
            "{} {} {}",
            srv.weight,
            srv.port,
            srv.target.trim_end_matches('.'),
        ),
        DnsRecord::CAA(caa) => caa.to_string(),
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by EasyDNS".to_string(),
            ));
        }
    };
    Ok(RecordWire { rdata, prio })
}

fn parse_record(
    record_type: DnsRecordType,
    rdata: &str,
    prio_str: &str,
) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => rdata
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A rdata {rdata:?}: {e}"))),
        DnsRecordType::AAAA => rdata
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA rdata {rdata:?}: {e}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(rdata.to_string())),
        DnsRecordType::NS => Ok(DnsRecord::NS(rdata.to_string())),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(rdata.to_string())),
        DnsRecordType::MX => {
            let priority = prio_str.parse::<u16>().unwrap_or(0);
            Ok(DnsRecord::MX(MXRecord {
                exchange: rdata.to_string(),
                priority,
            }))
        }
        DnsRecordType::SRV => {
            let mut parts = rdata.split_whitespace();
            let weight = parts
                .next()
                .and_then(|v| v.parse::<u16>().ok())
                .ok_or_else(|| Error::Parse(format!("invalid SRV rdata {rdata:?}: weight")))?;
            let port = parts
                .next()
                .and_then(|v| v.parse::<u16>().ok())
                .ok_or_else(|| Error::Parse(format!("invalid SRV rdata {rdata:?}: port")))?;
            let target = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid SRV rdata {rdata:?}: target")))?
                .to_string();
            let priority = prio_str.parse::<u16>().unwrap_or(0);
            Ok(DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target,
            }))
        }
        DnsRecordType::CAA => parse_caa(rdata).map(DnsRecord::CAA),
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by EasyDNS".to_string(),
        )),
    }
}

fn parse_caa(rdata: &str) -> crate::Result<CAARecord> {
    let trimmed = rdata.trim();
    let mut chars = trimmed.splitn(3, ' ');
    let flags_str = chars
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA rdata {rdata:?}: flags")))?;
    let tag = chars
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA rdata {rdata:?}: tag")))?;
    let value_raw = chars
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA rdata {rdata:?}: value")))?;
    let flags = flags_str
        .parse::<u8>()
        .map_err(|e| Error::Parse(format!("invalid CAA flags {flags_str:?}: {e}")))?;
    let issuer_critical = flags & 0x80 != 0;
    let value = value_raw
        .trim()
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(value_raw.trim())
        .to_string();

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
