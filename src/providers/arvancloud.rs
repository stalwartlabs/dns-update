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
    utils::strip_origin_from_name,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://napi.arvancloud.ir";
const PAGE_SIZE: u32 = 300;

#[derive(Clone)]
pub struct ArvanCloudProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct ArvanRecordPayload {
    #[serde(rename = "type")]
    pub record_type: &'static str,
    pub name: String,
    pub value: Value,
    pub ttl: u32,
    pub upstream_https: &'static str,
    pub ip_filter_mode: ArvanIpFilterMode,
}

#[derive(Serialize, Debug, Clone)]
pub struct ArvanIpFilterMode {
    pub count: &'static str,
    pub order: &'static str,
    pub geo_filter: &'static str,
}

impl Default for ArvanIpFilterMode {
    fn default() -> Self {
        Self {
            count: "single",
            order: "none",
            geo_filter: "none",
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct ArvanApiResponse<T> {
    pub data: T,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ArvanListedRecord {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: Value,
    #[serde(default = "default_true")]
    pub can_delete: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize, Debug)]
struct ArvanPagedResponse {
    data: Vec<ArvanListedRecord>,
    #[serde(default)]
    meta: Option<ArvanMeta>,
}

#[derive(Deserialize, Debug)]
struct ArvanMeta {
    #[serde(default)]
    last_page: u32,
}

pub struct ArvanRecordContent {
    pub record_type: &'static str,
    pub value: Value,
}

#[derive(Debug, Clone)]
struct DesiredRecord {
    record_type: &'static str,
    wire_value: Value,
    normalized: Value,
}

impl PartialEq<Value> for DesiredRecord {
    fn eq(&self, other: &Value) -> bool {
        self.normalized == *other
    }
}

impl ArvanCloudProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", api_key.as_ref())
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

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        let fqdn = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&fqdn, &domain, Some("@"));
        let wire_type = record_type_to_wire(record_type);

        let desired = build_desired(record_type, records)?;
        let existing = self.list_at(&domain, &subdomain, wire_type).await?;

        let mut existing_pool: Vec<ArvanListedRecord> =
            existing.into_iter().filter(|r| r.can_delete).collect();

        let mut to_create: Vec<DesiredRecord> = Vec::new();
        for desired_record in desired {
            if let Some(idx) = existing_pool
                .iter()
                .position(|r| desired_record == normalize_listed(r))
            {
                existing_pool.swap_remove(idx);
            } else {
                to_create.push(desired_record);
            }
        }

        for stale in existing_pool {
            self.delete_record(&domain, &stale.id).await?;
        }
        for desired_record in to_create {
            self.create_record(&domain, &subdomain, ttl, desired_record)
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
        if records.is_empty() {
            return Ok(());
        }
        check_record_types(record_type, &records)?;
        let fqdn = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&fqdn, &domain, Some("@"));
        let wire_type = record_type_to_wire(record_type);

        let desired = build_desired(record_type, records)?;
        let existing = self.list_at(&domain, &subdomain, wire_type).await?;

        for desired_record in desired {
            if existing
                .iter()
                .any(|r| desired_record == normalize_listed(r))
            {
                continue;
            }
            self.create_record(&domain, &subdomain, ttl, desired_record)
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
        let fqdn = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&fqdn, &domain, Some("@"));
        let wire_type = record_type_to_wire(record_type);

        let to_remove = build_desired(record_type, records)?;
        let existing = self.list_at(&domain, &subdomain, wire_type).await?;

        for desired_record in to_remove {
            if let Some(entry) = existing
                .iter()
                .find(|r| r.can_delete && desired_record == normalize_listed(r))
            {
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
        let fqdn = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&fqdn, &domain, Some("@"));
        let wire_type = record_type_to_wire(record_type);

        let existing = self.list_at(&domain, &subdomain, wire_type).await?;

        let mut out = Vec::with_capacity(existing.len());
        for listed in existing {
            if let Some(record) = listed_to_dns_record(record_type, &listed.value) {
                out.push(record);
            }
        }
        Ok(out)
    }

    async fn list_at(
        &self,
        domain: &str,
        subdomain: &str,
        wire_type: &str,
    ) -> crate::Result<Vec<ArvanListedRecord>> {
        let mut out = Vec::new();
        let mut page: u32 = 1;
        loop {
            let url = format!(
                "{endpoint}/cdn/4.0/domains/{domain}/dns-records?page={page}&per_page={per_page}",
                endpoint = self.endpoint,
                per_page = PAGE_SIZE,
            );
            let response: ArvanPagedResponse = self.client.get(url).send().await?;
            for record in response.data {
                if record.name == subdomain && record.record_type == wire_type {
                    out.push(record);
                }
            }
            match response.meta {
                Some(meta) if meta.last_page > 0 && page < meta.last_page => {
                    page += 1;
                }
                _ => return Ok(out),
            }
        }
    }

    async fn create_record(
        &self,
        domain: &str,
        subdomain: &str,
        ttl: u32,
        desired: DesiredRecord,
    ) -> crate::Result<()> {
        let body = ArvanRecordPayload {
            record_type: desired.record_type,
            name: subdomain.to_string(),
            value: desired.wire_value,
            ttl,
            upstream_https: "default",
            ip_filter_mode: ArvanIpFilterMode::default(),
        };
        self.client
            .post(format!(
                "{endpoint}/cdn/4.0/domains/{domain}/dns-records",
                endpoint = self.endpoint
            ))
            .with_body(&body)?
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, domain: &str, record_id: &str) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{endpoint}/cdn/4.0/domains/{domain}/dns-records/{record_id}",
                endpoint = self.endpoint
            ))
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn record_type_to_wire(record_type: DnsRecordType) -> &'static str {
    match record_type {
        DnsRecordType::A => "a",
        DnsRecordType::AAAA => "aaaa",
        DnsRecordType::CNAME => "cname",
        DnsRecordType::NS => "ns",
        DnsRecordType::MX => "mx",
        DnsRecordType::TXT => "txt",
        DnsRecordType::SRV => "srv",
        DnsRecordType::TLSA => "tlsa",
        DnsRecordType::CAA => "caa",
    }
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> crate::Result<()> {
    for record in records {
        if record.as_type() != expected {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected.as_str(),
                record.as_type().as_str(),
            )));
        }
    }
    Ok(())
}

fn build_desired(
    expected: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<DesiredRecord>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected.as_str(),
                record.as_type().as_str(),
            )));
        }
        let content = ArvanRecordContent::try_from(record)?;
        let normalized = normalize_value(content.record_type, content.value.clone());
        out.push(DesiredRecord {
            record_type: content.record_type,
            wire_value: content.value,
            normalized,
        });
    }
    Ok(out)
}

fn normalize_listed(record: &ArvanListedRecord) -> Value {
    normalize_value(static_wire(&record.record_type), record.value.clone())
}

fn static_wire(s: &str) -> &'static str {
    match s {
        "a" => "a",
        "aaaa" => "aaaa",
        "cname" => "cname",
        "ns" => "ns",
        "mx" => "mx",
        "txt" => "txt",
        "srv" => "srv",
        "tlsa" => "tlsa",
        "caa" => "caa",
        _ => "",
    }
}

fn normalize_value(wire_type: &str, mut value: Value) -> Value {
    match wire_type {
        "a" | "aaaa" => {
            if let Value::Array(items) = &mut value {
                let mut normalized: Vec<Value> = items
                    .iter_mut()
                    .map(|item| {
                        let ip = item
                            .get("ip")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        serde_json::json!({ "ip": ip })
                    })
                    .collect();
                normalized.sort_by(|a, b| {
                    a.get("ip")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .cmp(b.get("ip").and_then(|v| v.as_str()).unwrap_or(""))
                });
                return Value::Array(normalized);
            }
            value
        }
        "cname" | "ns" => {
            let host = value
                .get("host")
                .and_then(|v| v.as_str())
                .map(strip_trailing_dot)
                .unwrap_or_default();
            serde_json::json!({ "host": host })
        }
        "mx" => {
            let host = value
                .get("host")
                .and_then(|v| v.as_str())
                .map(strip_trailing_dot)
                .unwrap_or_default();
            let priority = value.get("priority").and_then(|v| v.as_u64()).unwrap_or(0);
            serde_json::json!({ "host": host, "priority": priority })
        }
        "txt" => {
            let text = value
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            serde_json::json!({ "text": text })
        }
        "srv" => {
            let target = value
                .get("target")
                .and_then(|v| v.as_str())
                .map(strip_trailing_dot)
                .unwrap_or_default();
            let priority = value.get("priority").and_then(|v| v.as_u64()).unwrap_or(0);
            let weight = value.get("weight").and_then(|v| v.as_u64()).unwrap_or(0);
            let port = value.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
            serde_json::json!({
                "target": target,
                "priority": priority,
                "weight": weight,
                "port": port,
            })
        }
        "tlsa" => {
            let usage = value.get("usage").and_then(|v| v.as_u64()).unwrap_or(0);
            let selector = value.get("selector").and_then(|v| v.as_u64()).unwrap_or(0);
            let matching_type = value
                .get("matching_type")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let certificate = value
                .get("certificate")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            serde_json::json!({
                "usage": usage,
                "selector": selector,
                "matching_type": matching_type,
                "certificate": certificate,
            })
        }
        "caa" => {
            let flag = value.get("flag").and_then(|v| v.as_u64()).unwrap_or(0);
            let tag = value
                .get("tag")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let v = value
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            serde_json::json!({ "flag": flag, "tag": tag, "value": v })
        }
        _ => value,
    }
}

fn strip_trailing_dot(s: &str) -> String {
    s.strip_suffix('.').unwrap_or(s).to_string()
}

fn listed_to_dns_record(record_type: DnsRecordType, value: &Value) -> Option<DnsRecord> {
    use crate::{CAARecord, KeyValue, MXRecord, SRVRecord, TLSARecord};

    match record_type {
        DnsRecordType::A => {
            let items = value.as_array()?;
            let ip = items.first()?.get("ip")?.as_str()?;
            ip.parse().ok().map(DnsRecord::A)
        }
        DnsRecordType::AAAA => {
            let items = value.as_array()?;
            let ip = items.first()?.get("ip")?.as_str()?;
            ip.parse().ok().map(DnsRecord::AAAA)
        }
        DnsRecordType::CNAME => {
            let host = value.get("host")?.as_str()?;
            Some(DnsRecord::CNAME(strip_trailing_dot(host)))
        }
        DnsRecordType::NS => {
            let host = value.get("host")?.as_str()?;
            Some(DnsRecord::NS(strip_trailing_dot(host)))
        }
        DnsRecordType::MX => {
            let host = value.get("host")?.as_str()?;
            let priority = value.get("priority")?.as_u64()? as u16;
            Some(DnsRecord::MX(MXRecord {
                exchange: strip_trailing_dot(host),
                priority,
            }))
        }
        DnsRecordType::TXT => {
            let text = value.get("text")?.as_str()?;
            Some(DnsRecord::TXT(text.to_string()))
        }
        DnsRecordType::SRV => {
            let target = value.get("target")?.as_str()?;
            let priority = value.get("priority")?.as_u64()? as u16;
            let weight = value.get("weight")?.as_u64()? as u16;
            let port = value.get("port")?.as_u64()? as u16;
            Some(DnsRecord::SRV(SRVRecord {
                target: strip_trailing_dot(target),
                priority,
                weight,
                port,
            }))
        }
        DnsRecordType::TLSA => {
            let usage = value.get("usage")?.as_u64()? as u8;
            let selector = value.get("selector")?.as_u64()? as u8;
            let matching = value.get("matching_type")?.as_u64()? as u8;
            let hex = value.get("certificate")?.as_str()?;
            let cert_data = decode_hex(hex)?;
            let cert_usage = match usage {
                0 => crate::TlsaCertUsage::PkixTa,
                1 => crate::TlsaCertUsage::PkixEe,
                2 => crate::TlsaCertUsage::DaneTa,
                3 => crate::TlsaCertUsage::DaneEe,
                _ => crate::TlsaCertUsage::Private,
            };
            let selector = match selector {
                0 => crate::TlsaSelector::Full,
                1 => crate::TlsaSelector::Spki,
                _ => crate::TlsaSelector::Private,
            };
            let matching = match matching {
                0 => crate::TlsaMatching::Raw,
                1 => crate::TlsaMatching::Sha256,
                2 => crate::TlsaMatching::Sha512,
                _ => crate::TlsaMatching::Private,
            };
            Some(DnsRecord::TLSA(TLSARecord {
                cert_usage,
                selector,
                matching,
                cert_data,
            }))
        }
        DnsRecordType::CAA => {
            let flag = value.get("flag")?.as_u64()? as u8;
            let tag = value.get("tag")?.as_str()?.to_string();
            let v = value.get("value")?.as_str()?.to_string();
            let issuer_critical = flag & 0x80 != 0;
            let parse_options = |target: &str| -> (Option<String>, Vec<KeyValue>) {
                let mut parts = target.split(';');
                let name = parts
                    .next()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                let options = parts
                    .filter_map(|p| {
                        let p = p.trim();
                        if p.is_empty() {
                            return None;
                        }
                        let (k, val) = p.split_once('=').unwrap_or((p, ""));
                        Some(KeyValue {
                            key: k.trim().to_string(),
                            value: val.trim().to_string(),
                        })
                    })
                    .collect();
                (name, options)
            };
            match tag.as_str() {
                "issue" => {
                    let (name, options) = parse_options(&v);
                    Some(DnsRecord::CAA(CAARecord::Issue {
                        issuer_critical,
                        name,
                        options,
                    }))
                }
                "issuewild" => {
                    let (name, options) = parse_options(&v);
                    Some(DnsRecord::CAA(CAARecord::IssueWild {
                        issuer_critical,
                        name,
                        options,
                    }))
                }
                "iodef" => Some(DnsRecord::CAA(CAARecord::Iodef {
                    issuer_critical,
                    url: v,
                })),
                _ => None,
            }
        }
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let h = char::from(chunk[0]).to_digit(16)?;
        let l = char::from(chunk[1]).to_digit(16)?;
        out.push(((h << 4) | l) as u8);
    }
    Some(out)
}

impl TryFrom<DnsRecord> for ArvanRecordContent {
    type Error = Error;

    fn try_from(record: DnsRecord) -> Result<Self, Self::Error> {
        match record {
            DnsRecord::A(addr) => Ok(ArvanRecordContent {
                record_type: "a",
                value: serde_json::json!([{
                    "ip": addr.to_string(),
                    "port": serde_json::Value::Null,
                    "weight": 100,
                    "country": "",
                }]),
            }),
            DnsRecord::AAAA(addr) => Ok(ArvanRecordContent {
                record_type: "aaaa",
                value: serde_json::json!([{
                    "ip": addr.to_string(),
                    "port": serde_json::Value::Null,
                    "weight": 100,
                    "country": "",
                }]),
            }),
            DnsRecord::CNAME(target) => Ok(ArvanRecordContent {
                record_type: "cname",
                value: serde_json::json!({ "host": target }),
            }),
            DnsRecord::NS(target) => Ok(ArvanRecordContent {
                record_type: "ns",
                value: serde_json::json!({ "host": target }),
            }),
            DnsRecord::MX(mx) => Ok(ArvanRecordContent {
                record_type: "mx",
                value: serde_json::json!({ "host": mx.exchange, "priority": mx.priority }),
            }),
            DnsRecord::TXT(text) => Ok(ArvanRecordContent {
                record_type: "txt",
                value: serde_json::json!({ "text": text }),
            }),
            DnsRecord::SRV(srv) => Ok(ArvanRecordContent {
                record_type: "srv",
                value: serde_json::json!({
                    "target": srv.target,
                    "priority": srv.priority,
                    "weight": srv.weight,
                    "port": srv.port,
                }),
            }),
            DnsRecord::TLSA(tlsa) => {
                let certificate: String =
                    tlsa.cert_data.iter().map(|b| format!("{b:02x}")).collect();
                Ok(ArvanRecordContent {
                    record_type: "tlsa",
                    value: serde_json::json!({
                        "usage": u8::from(tlsa.cert_usage),
                        "selector": u8::from(tlsa.selector),
                        "matching_type": u8::from(tlsa.matching),
                        "certificate": certificate,
                    }),
                })
            }
            DnsRecord::CAA(caa) => {
                let (flags, tag, value) = caa.decompose();
                Ok(ArvanRecordContent {
                    record_type: "caa",
                    value: serde_json::json!({
                        "flag": flags,
                        "tag": tag,
                        "value": value,
                    }),
                })
            }
        }
    }
}
