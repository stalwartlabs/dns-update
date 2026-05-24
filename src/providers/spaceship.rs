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
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://spaceship.dev/api/v1";

#[derive(Clone)]
pub struct SpaceshipProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct PutRecordsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    force: Option<bool>,
    items: Vec<SpaceshipDnsRecord>,
}

#[derive(Deserialize, Debug)]
struct GetRecordsResponse {
    items: Vec<SpaceshipDnsRecord>,
    total: usize,
}

#[derive(Serialize, Debug)]
struct SpaceshipDeleteRecord {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nameserver: Option<String>,
    #[serde(rename = "aliasName", skip_serializing_if = "Option::is_none")]
    alias_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pointer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exchange: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preference: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selector: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matching: Option<u8>,
    #[serde(rename = "associationData", skip_serializing_if = "Option::is_none")]
    association_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flag: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct SpaceshipDnsRecord {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nameserver: Option<String>,
    #[serde(rename = "aliasName", skip_serializing_if = "Option::is_none")]
    alias_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pointer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exchange: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preference: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selector: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matching: Option<u8>,
    #[serde(rename = "associationData", skip_serializing_if = "Option::is_none")]
    association_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flag: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    extra: BTreeMap<String, Value>,
}

impl SpaceshipProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        api_secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("X-Api-Key", api_key.as_ref())
            .with_header("X-Api-Secret", api_secret.as_ref())
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
        let name = name.into_name();
        let domain = origin.into_name();
        let raw_subdomain = strip_origin_from_name(&name, &domain, None);
        let identity = self.rrset_identity(&raw_subdomain, record_type)?;
        let type_str = record_type.as_str();

        let existing: Vec<SpaceshipDnsRecord> = self
            .fetch_records(&domain)
            .await?
            .into_iter()
            .filter(|r| identity.matches(r, type_str))
            .collect();

        let desired: Vec<SpaceshipDnsRecord> = records
            .into_iter()
            .map(|record| SpaceshipDnsRecord::from_dns_record(record, &raw_subdomain, Some(ttl)))
            .collect::<crate::Result<Vec<_>>>()?;

        let mut to_add: Vec<SpaceshipDnsRecord> = Vec::new();
        let mut existing_pool = existing;

        for want in desired {
            if let Some(idx) = existing_pool
                .iter()
                .position(|have| record_value_matches(have, &want))
            {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(want);
            }
        }

        if !existing_pool.is_empty() {
            let to_delete: Vec<SpaceshipDeleteRecord> = existing_pool
                .into_iter()
                .map(SpaceshipDnsRecord::into_delete_record)
                .collect::<crate::Result<Vec<_>>>()?;
            self.client
                .delete(format!("{}/dns/records/{}", self.endpoint, domain))
                .with_body(to_delete)?
                .send_with_retry::<serde_json::Value>(3)
                .await?;
        }

        if !to_add.is_empty() {
            self.client
                .put(format!("{}/dns/records/{}", self.endpoint, domain))
                .with_body(PutRecordsRequest {
                    force: None,
                    items: to_add,
                })?
                .send_with_retry::<serde_json::Value>(3)
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
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name();
        let domain = origin.into_name();
        let raw_subdomain = strip_origin_from_name(&name, &domain, None);
        let identity = self.rrset_identity(&raw_subdomain, record_type)?;
        let type_str = record_type.as_str();

        let existing: Vec<SpaceshipDnsRecord> = self
            .fetch_records(&domain)
            .await?
            .into_iter()
            .filter(|r| identity.matches(r, type_str))
            .collect();

        let desired: Vec<SpaceshipDnsRecord> = records
            .into_iter()
            .map(|record| SpaceshipDnsRecord::from_dns_record(record, &raw_subdomain, Some(ttl)))
            .collect::<crate::Result<Vec<_>>>()?;

        let to_add: Vec<SpaceshipDnsRecord> = desired
            .into_iter()
            .filter(|want| !existing.iter().any(|have| record_value_matches(have, want)))
            .collect();

        if to_add.is_empty() {
            return Ok(());
        }

        self.client
            .put(format!("{}/dns/records/{}", self.endpoint, domain))
            .with_body(PutRecordsRequest {
                force: None,
                items: to_add,
            })?
            .send_with_retry::<serde_json::Value>(3)
            .await?;
        Ok(())
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
        let raw_subdomain = strip_origin_from_name(&name, &domain, None);
        let identity = self.rrset_identity(&raw_subdomain, record_type)?;
        let type_str = record_type.as_str();

        let existing: Vec<SpaceshipDnsRecord> = self
            .fetch_records(&domain)
            .await?
            .into_iter()
            .filter(|r| identity.matches(r, type_str))
            .collect();

        let targets: Vec<SpaceshipDnsRecord> = records
            .into_iter()
            .map(|record| SpaceshipDnsRecord::from_dns_record(record, &raw_subdomain, None))
            .collect::<crate::Result<Vec<_>>>()?;

        let mut to_delete: Vec<SpaceshipDeleteRecord> = Vec::new();
        for want in targets {
            if let Some(have) = existing
                .iter()
                .find(|have| record_value_matches(have, &want))
            {
                to_delete.push(have.clone().into_delete_record()?);
            }
        }

        if to_delete.is_empty() {
            return Ok(());
        }

        self.client
            .delete(format!("{}/dns/records/{}", self.endpoint, domain))
            .with_body(to_delete)?
            .send_with_retry::<serde_json::Value>(3)
            .await?;
        Ok(())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let name = name.into_name();
        let domain = origin.into_name();
        let raw_subdomain = strip_origin_from_name(&name, &domain, None);
        let identity = self.rrset_identity(&raw_subdomain, record_type)?;
        let type_str = record_type.as_str();

        self.fetch_records(&domain)
            .await?
            .into_iter()
            .filter(|r| identity.matches(r, type_str))
            .map(SpaceshipDnsRecord::into_dns_record)
            .collect()
    }

    async fn fetch_records(&self, domain: &str) -> crate::Result<Vec<SpaceshipDnsRecord>> {
        const PAGE_SIZE: usize = 100;
        let mut skip = 0usize;
        let mut all_items = Vec::new();

        loop {
            let response = self
                .client
                .get(format!(
                    "{}/dns/records/{}?take={}&skip={}",
                    self.endpoint, domain, PAGE_SIZE, skip
                ))
                .send_with_retry::<GetRecordsResponse>(3)
                .await?;

            let received = response.items.len();
            all_items.extend(response.items);

            if all_items.len() >= response.total || received < PAGE_SIZE {
                break;
            }

            skip += PAGE_SIZE;
        }

        Ok(all_items)
    }

    fn rrset_identity(
        &self,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<RrsetIdentity> {
        match record_type {
            DnsRecordType::SRV => {
                let (service, protocol, name) = split_service_protocol_labels(subdomain)?;
                Ok(RrsetIdentity::Srv {
                    name,
                    service,
                    protocol,
                })
            }
            DnsRecordType::TLSA => {
                let (port_label, protocol, name) = split_service_protocol_labels(subdomain)?;
                let port = parse_tlsa_port_label(&port_label)?;
                Ok(RrsetIdentity::Tlsa {
                    name,
                    port,
                    protocol,
                })
            }
            _ => Ok(RrsetIdentity::Simple {
                name: subdomain.to_string(),
            }),
        }
    }
}

enum RrsetIdentity {
    Simple { name: String },
    Srv { name: String, service: String, protocol: String },
    Tlsa { name: String, port: u16, protocol: String },
}

impl RrsetIdentity {
    fn matches(&self, r: &SpaceshipDnsRecord, type_str: &str) -> bool {
        if r.record_type != type_str {
            return false;
        }
        match self {
            Self::Simple { name } => r.name == *name,
            Self::Srv {
                name,
                service,
                protocol,
            } => {
                r.name == *name
                    && r.service.as_deref() == Some(service.as_str())
                    && r.protocol.as_deref() == Some(protocol.as_str())
            }
            Self::Tlsa {
                name,
                port,
                protocol,
            } => {
                r.name == *name
                    && r.port.as_ref().and_then(|v| v.as_u64()) == Some(u64::from(*port))
                    && r.protocol.as_deref() == Some(protocol.as_str())
            }
        }
    }
}

impl SpaceshipDnsRecord {
    fn from_dns_record(record: DnsRecord, name: &str, ttl: Option<u32>) -> crate::Result<Self> {
        let mut item = Self {
            record_type: match &record {
                DnsRecord::A(_) => "A",
                DnsRecord::AAAA(_) => "AAAA",
                DnsRecord::CNAME(_) => "CNAME",
                DnsRecord::NS(_) => "NS",
                DnsRecord::MX(_) => "MX",
                DnsRecord::TXT(_) => "TXT",
                DnsRecord::SRV(_) => "SRV",
                DnsRecord::TLSA(_) => "TLSA",
                DnsRecord::CAA(_) => "CAA",
            }
            .to_string(),
            name: name.to_string(),
            value: None,
            address: None,
            nameserver: None,
            alias_name: None,
            pointer: None,
            cname: None,
            exchange: None,
            preference: None,
            priority: None,
            weight: None,
            port: None,
            service: None,
            protocol: None,
            target: None,
            usage: None,
            selector: None,
            matching: None,
            association_data: None,
            flag: None,
            tag: None,
            ttl,
            extra: BTreeMap::new(),
        };

        match record {
            DnsRecord::A(content) => {
                item.address = Some(content.to_string());
            }
            DnsRecord::AAAA(content) => {
                item.address = Some(content.to_string());
            }
            DnsRecord::CNAME(content) => {
                item.cname = Some(content);
            }
            DnsRecord::NS(content) => {
                item.nameserver = Some(content);
            }
            DnsRecord::MX(mx) => {
                item.exchange = Some(mx.exchange);
                item.preference = Some(mx.priority);
            }
            DnsRecord::TXT(content) => item.value = Some(content),
            DnsRecord::SRV(srv) => {
                let (service, protocol, normalized_name) = split_service_protocol_labels(name)?;
                item.name = normalized_name;
                item.service = Some(service);
                item.protocol = Some(protocol);
                item.priority = Some(srv.priority);
                item.target = Some(srv.target);
                item.weight = Some(srv.weight);
                item.port = Some(Value::from(srv.port));
            }
            DnsRecord::TLSA(tlsa) => {
                let (port_label, protocol, normalized_name) = split_service_protocol_labels(name)?;
                let port = parse_tlsa_port_label(&port_label)?;
                item.name = normalized_name;
                item.port = Some(Value::from(port));
                item.protocol = Some(protocol);
                item.usage = Some(u8::from(tlsa.cert_usage));
                item.selector = Some(u8::from(tlsa.selector));
                item.matching = Some(u8::from(tlsa.matching));
                item.association_data = Some(
                    tlsa.cert_data
                        .into_iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                );
            }
            DnsRecord::CAA(caa) => {
                let (flag, tag, value) = caa.decompose();
                item.flag = Some(flag);
                item.tag = Some(tag);
                item.value = Some(value);
            }
        }

        Ok(item)
    }

    fn into_dns_record(self) -> crate::Result<DnsRecord> {
        let record_type = self.record_type.clone();
        let name = self.name.clone();
        let missing = |field: &str| {
            Error::Parse(format!(
                "Missing field '{field}' in {} record '{}'",
                record_type, name
            ))
        };

        Ok(match self.record_type.as_str() {
            "A" => {
                let addr = self.address.ok_or_else(|| missing("address"))?;
                DnsRecord::A(
                    addr.parse()
                        .map_err(|e| Error::Parse(format!("Invalid IPv4 address '{addr}': {e}")))?,
                )
            }
            "AAAA" => {
                let addr = self.address.ok_or_else(|| missing("address"))?;
                DnsRecord::AAAA(
                    addr.parse()
                        .map_err(|e| Error::Parse(format!("Invalid IPv6 address '{addr}': {e}")))?,
                )
            }
            "CNAME" => DnsRecord::CNAME(self.cname.ok_or_else(|| missing("cname"))?),
            "NS" => DnsRecord::NS(self.nameserver.ok_or_else(|| missing("nameserver"))?),
            "MX" => DnsRecord::MX(MXRecord {
                exchange: self.exchange.ok_or_else(|| missing("exchange"))?,
                priority: self
                    .preference
                    .or(self.priority)
                    .ok_or_else(|| missing("preference"))?,
            }),
            "TXT" => DnsRecord::TXT(self.value.ok_or_else(|| missing("value"))?),
            "SRV" => DnsRecord::SRV(SRVRecord {
                priority: self.priority.ok_or_else(|| missing("priority"))?,
                weight: self.weight.ok_or_else(|| missing("weight"))?,
                port: port_as_u64(&self.port)
                    .and_then(|p| u16::try_from(p).ok())
                    .ok_or_else(|| missing("port"))?,
                target: self.target.ok_or_else(|| missing("target"))?,
            }),
            "TLSA" => DnsRecord::TLSA(TLSARecord {
                cert_usage: tlsa_cert_usage_from_u8(self.usage.ok_or_else(|| missing("usage"))?)?,
                selector: tlsa_selector_from_u8(self.selector.ok_or_else(|| missing("selector"))?)?,
                matching: tlsa_matching_from_u8(self.matching.ok_or_else(|| missing("matching"))?)?,
                cert_data: decode_hex(
                    &self
                        .association_data
                        .ok_or_else(|| missing("associationData"))?,
                )?,
            }),
            "CAA" => DnsRecord::CAA(build_caa(
                self.flag.ok_or_else(|| missing("flag"))?,
                self.tag.ok_or_else(|| missing("tag"))?,
                self.value.ok_or_else(|| missing("value"))?,
            )?),
            other => {
                return Err(Error::Parse(format!(
                    "Unsupported Spaceship record type for list: {other}"
                )));
            }
        })
    }

    fn into_delete_record(self) -> crate::Result<SpaceshipDeleteRecord> {
        let record_type = self.record_type.clone();
        let name = self.name.clone();
        let make_err = |field: &str| {
            Error::Parse(format!(
                "Missing required delete field '{field}' for {} record '{}'",
                record_type, name
            ))
        };

        let mut out = SpaceshipDeleteRecord {
            record_type: self.record_type.clone(),
            name: self.name,
            value: None,
            address: None,
            nameserver: None,
            alias_name: None,
            pointer: None,
            cname: None,
            exchange: None,
            preference: None,
            priority: None,
            weight: None,
            port: None,
            service: None,
            protocol: None,
            target: None,
            usage: None,
            selector: None,
            matching: None,
            association_data: None,
            flag: None,
            tag: None,
        };

        match self.record_type.as_str() {
            "A" | "AAAA" => {
                out.address = Some(self.address.ok_or_else(|| make_err("address"))?);
            }
            "CNAME" => out.cname = Some(self.cname.ok_or_else(|| make_err("cname"))?),
            "NS" => out.nameserver = Some(self.nameserver.ok_or_else(|| make_err("nameserver"))?),
            "MX" => {
                out.exchange = Some(self.exchange.ok_or_else(|| make_err("exchange"))?);
                out.preference = Some(
                    self.preference
                        .or(self.priority)
                        .ok_or_else(|| make_err("preference"))?,
                );
            }
            "TXT" => out.value = Some(self.value.ok_or_else(|| make_err("value"))?),
            "SRV" => {
                out.service = Some(self.service.ok_or_else(|| make_err("service"))?);
                out.protocol = Some(self.protocol.ok_or_else(|| make_err("protocol"))?);
                out.priority = Some(self.priority.ok_or_else(|| make_err("priority"))?);
                out.weight = Some(self.weight.ok_or_else(|| make_err("weight"))?);
                out.port = Some(self.port.ok_or_else(|| make_err("port"))?);
                out.target = Some(self.target.ok_or_else(|| make_err("target"))?);
            }
            "TLSA" => {
                out.port = Some(self.port.ok_or_else(|| make_err("port"))?);
                out.protocol = Some(self.protocol.ok_or_else(|| make_err("protocol"))?);
                out.usage = Some(self.usage.ok_or_else(|| make_err("usage"))?);
                out.selector = Some(self.selector.ok_or_else(|| make_err("selector"))?);
                out.matching = Some(self.matching.ok_or_else(|| make_err("matching"))?);
                out.association_data = Some(
                    self.association_data
                        .ok_or_else(|| make_err("associationData"))?,
                );
            }
            "CAA" => {
                out.flag = Some(self.flag.ok_or_else(|| make_err("flag"))?);
                out.tag = Some(self.tag.ok_or_else(|| make_err("tag"))?);
                out.value = Some(self.value.ok_or_else(|| make_err("value"))?);
            }
            other => {
                return Err(Error::Parse(format!(
                    "Unsupported Spaceship record type for delete: {other}"
                )));
            }
        }

        Ok(out)
    }
}

fn split_service_protocol_labels(name: &str) -> crate::Result<(String, String, String)> {
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return Err(Error::Parse(format!(
            "Invalid DNS record name for service/protocol record: {name}"
        )));
    }
    let first = labels[0];
    let second = labels[1];
    if !first.starts_with('_') || !second.starts_with('_') {
        return Err(Error::Parse(format!(
            "Expected service/protocol labels to start with '_' in record name: {name}"
        )));
    }
    let normalized_name = if labels.len() > 2 {
        labels[2..].join(".")
    } else {
        "@".to_string()
    };
    Ok((first.to_string(), second.to_string(), normalized_name))
}

fn parse_tlsa_port_label(label: &str) -> crate::Result<u16> {
    let digits = label.strip_prefix('_').unwrap_or(label);
    digits.parse::<u16>().map_err(|_| {
        Error::Parse(format!(
            "Invalid TLSA port label '{label}': expected '_<u16>'"
        ))
    })
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

fn record_value_matches(a: &SpaceshipDnsRecord, b: &SpaceshipDnsRecord) -> bool {
    if a.record_type != b.record_type || a.name != b.name {
        return false;
    }
    match a.record_type.as_str() {
        "A" | "AAAA" => a.address == b.address,
        "CNAME" => a.cname == b.cname,
        "NS" => a.nameserver == b.nameserver,
        "MX" => {
            a.exchange == b.exchange && a.preference.or(a.priority) == b.preference.or(b.priority)
        }
        "TXT" => a.value == b.value,
        "SRV" => {
            a.service == b.service
                && a.protocol == b.protocol
                && a.priority == b.priority
                && a.weight == b.weight
                && port_value_matches(&a.port, &b.port)
                && a.target == b.target
        }
        "TLSA" => {
            a.protocol == b.protocol
                && port_value_matches(&a.port, &b.port)
                && a.usage == b.usage
                && a.selector == b.selector
                && a.matching == b.matching
                && a.association_data.as_deref().map(str::to_ascii_lowercase)
                    == b.association_data.as_deref().map(str::to_ascii_lowercase)
        }
        "CAA" => a.flag == b.flag && a.tag == b.tag && a.value == b.value,
        _ => false,
    }
}

fn port_value_matches(a: &Option<Value>, b: &Option<Value>) -> bool {
    match (port_as_u64(a), port_as_u64(b)) {
        (Some(av), Some(bv)) => av == bv,
        _ => a == b,
    }
}

fn port_as_u64(v: &Option<Value>) -> Option<u64> {
    match v.as_ref()? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim_start_matches('_').parse::<u64>().ok(),
        _ => None,
    }
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

fn build_caa(flag: u8, tag: String, value: String) -> crate::Result<CAARecord> {
    let issuer_critical = flag & 0x80 != 0;
    match tag.as_str() {
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
