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
    DnsRecord, DnsRecordType, Error, IntoFqdn, http::HttpClientBuilder, utils::strip_origin_from_name,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://spaceship.dev/api/v1";

#[derive(Clone)]
pub struct SpaceshipProvider {
    client: HttpClientBuilder,
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
            .with_timeout(timeout);
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

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);

        self.client
            .put(format!("{}/dns/records/{}", self.endpoint, domain))
            .with_body(PutRecordsRequest {
                force: None,
                items: vec![SpaceshipDnsRecord::from_dns_record(record, &subdomain, Some(ttl))?],
            })?
            .send_raw()
            .await
            .map(|_| ())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);

        self.client
            .put(format!("{}/dns/records/{}", self.endpoint, domain))
            .with_body(PutRecordsRequest {
                force: None,
                items: vec![SpaceshipDnsRecord::from_dns_record(record, &subdomain, Some(ttl))?],
            })?
            .send_raw()
            .await
            .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = self.normalize_subdomain_for_delete(
            strip_origin_from_name(&name, &domain, None),
            record_type,
        )?;
        let record_type = record_type.to_string();
        let records = self.fetch_records(&domain).await?;
        let to_delete: Vec<SpaceshipDeleteRecord> = records
            .into_iter()
            .filter(|record| record.name == subdomain && record.record_type == record_type)
            .map(SpaceshipDnsRecord::into_delete_record)
            .collect::<crate::Result<Vec<_>>>()?;

        if to_delete.is_empty() {
            return Err(Error::NotFound);
        }

        for item in to_delete {
            self.client
                .delete(format!("{}/dns/records/{}", self.endpoint, domain))
                .with_body(vec![item])?
                .send_raw()
                .await?;
        }
        Ok(())
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

    fn normalize_subdomain_for_delete(
        &self,
        subdomain: String,
        record_type: DnsRecordType,
    ) -> crate::Result<String> {
        match record_type {
            DnsRecordType::SRV | DnsRecordType::TLSA => {
                let (_left, _right, normalized_name) = split_service_protocol_labels(&subdomain)?;
                Ok(normalized_name)
            }
            _ => Ok(subdomain),
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
                let (port, protocol, normalized_name) = split_service_protocol_labels(name)?;
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
