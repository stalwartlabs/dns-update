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

use crate::utils::build_caa;
use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord,
    http::{HttpClient, HttpClientBuilder},
    utils::strip_origin_from_name,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.domeneshop.no/v0";

#[derive(Clone)]
pub struct DomeneshopProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Domain {
    pub id: i64,
    pub domain: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DnsRecordPayload {
    pub host: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub data: String,
    pub ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ExistingDnsRecord {
    pub id: i64,
    pub host: String,
    #[serde(rename = "type")]
    pub record_type: String,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub priority: Option<u16>,
    #[serde(default)]
    pub weight: Option<u16>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub flags: Option<u8>,
    #[serde(default)]
    pub tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomeneshopRecordContent {
    pub record_type: &'static str,
    pub data: String,
    pub priority: Option<u16>,
    pub weight: Option<u16>,
    pub port: Option<u16>,
    pub flags: Option<u8>,
    pub tag: Option<String>,
}

impl DomeneshopProvider {
    pub(crate) fn new(
        api_token: impl AsRef<str>,
        api_secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let credentials = format!("{}:{}", api_token.as_ref(), api_secret.as_ref());
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

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let host = strip_origin_from_name(&name, &domain, Some("@"));
        let desired = build_contents(record_type, records)?;
        let domain_id = self.find_domain_id(&domain).await?;
        let existing = self.list_at(domain_id, &host, record_type).await?;

        let mut existing_pool = existing;
        let mut to_add: Vec<DomeneshopRecordContent> = Vec::new();

        for content in desired {
            if let Some(idx) = existing_pool
                .iter()
                .position(|r| record_matches(r, &content))
            {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(content);
            }
        }

        for entry in existing_pool {
            self.delete_record(domain_id, entry.id).await?;
        }
        for content in to_add {
            self.create_record(domain_id, &host, ttl, &content).await?;
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
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let host = strip_origin_from_name(&name, &domain, Some("@"));
        let desired = build_contents(record_type, records)?;
        let domain_id = self.find_domain_id(&domain).await?;
        let existing = self.list_at(domain_id, &host, record_type).await?;

        for content in desired {
            if existing.iter().any(|r| record_matches(r, &content)) {
                continue;
            }
            self.create_record(domain_id, &host, ttl, &content).await?;
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
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let host = strip_origin_from_name(&name, &domain, Some("@"));
        let to_remove = build_contents(record_type, records)?;
        let domain_id = self.find_domain_id(&domain).await?;
        let existing = self.list_at(domain_id, &host, record_type).await?;

        for content in to_remove {
            if let Some(entry) = existing.iter().find(|r| record_matches(r, &content)) {
                self.delete_record(domain_id, entry.id).await?;
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
        let host = strip_origin_from_name(&name, &domain, Some("@"));
        let domain_id = self.find_domain_id(&domain).await?;
        let existing = self.list_at(domain_id, &host, record_type).await?;
        existing.into_iter().map(DnsRecord::try_from).collect()
    }

    async fn find_domain_id(&self, domain: &str) -> crate::Result<i64> {
        let domains: Vec<Domain> = self
            .client
            .get(format!("{endpoint}/domains", endpoint = self.endpoint))
            .send()
            .await?;
        domains
            .into_iter()
            .find(|d| d.domain == domain)
            .map(|d| d.id)
            .ok_or_else(|| Error::Api(format!("Domain {domain} not found")))
    }

    async fn list_at(
        &self,
        domain_id: i64,
        host: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ExistingDnsRecord>> {
        let query = serde_urlencoded::to_string([("host", host), ("type", record_type.as_str())])
            .unwrap_or_default();
        let records: Vec<ExistingDnsRecord> = self
            .client
            .get(format!(
                "{endpoint}/domains/{domain_id}/dns?{query}",
                endpoint = self.endpoint
            ))
            .send()
            .await?;
        let type_str = record_type.as_str();
        Ok(records
            .into_iter()
            .filter(|r| r.host == host && r.record_type == type_str)
            .collect())
    }

    async fn create_record(
        &self,
        domain_id: i64,
        host: &str,
        ttl: u32,
        content: &DomeneshopRecordContent,
    ) -> crate::Result<()> {
        let body = build_payload(host, ttl, content);
        self.client
            .post(format!(
                "{endpoint}/domains/{domain_id}/dns",
                endpoint = self.endpoint
            ))
            .with_body(&body)?
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, domain_id: i64, record_id: i64) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{endpoint}/domains/{domain_id}/dns/{record_id}",
                endpoint = self.endpoint
            ))
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }
}

fn build_payload(host: &str, ttl: u32, content: &DomeneshopRecordContent) -> DnsRecordPayload {
    DnsRecordPayload {
        host: host.to_string(),
        record_type: content.record_type.to_string(),
        data: content.data.clone(),
        ttl,
        priority: content.priority,
        weight: content.weight,
        port: content.port,
        flags: content.flags,
        tag: content.tag.clone(),
    }
}

fn build_contents(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<DomeneshopRecordContent>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(DomeneshopRecordContent::try_from(record)?);
    }
    Ok(out)
}

fn record_matches(existing: &ExistingDnsRecord, desired: &DomeneshopRecordContent) -> bool {
    existing.record_type == desired.record_type
        && existing.data == desired.data
        && existing.priority == desired.priority
        && existing.weight == desired.weight
        && existing.port == desired.port
        && existing.flags == desired.flags
        && existing.tag == desired.tag
}

impl TryFrom<DnsRecord> for DomeneshopRecordContent {
    type Error = Error;

    fn try_from(record: DnsRecord) -> Result<Self, Self::Error> {
        match record {
            DnsRecord::A(addr) => Ok(DomeneshopRecordContent {
                record_type: "A",
                data: addr.to_string(),
                priority: None,
                weight: None,
                port: None,
                flags: None,
                tag: None,
            }),
            DnsRecord::AAAA(addr) => Ok(DomeneshopRecordContent {
                record_type: "AAAA",
                data: addr.to_string(),
                priority: None,
                weight: None,
                port: None,
                flags: None,
                tag: None,
            }),
            DnsRecord::CNAME(target) => Ok(DomeneshopRecordContent {
                record_type: "CNAME",
                data: target,
                priority: None,
                weight: None,
                port: None,
                flags: None,
                tag: None,
            }),
            DnsRecord::NS(target) => Ok(DomeneshopRecordContent {
                record_type: "NS",
                data: target,
                priority: None,
                weight: None,
                port: None,
                flags: None,
                tag: None,
            }),
            DnsRecord::MX(mx) => Ok(DomeneshopRecordContent {
                record_type: "MX",
                data: mx.exchange,
                priority: Some(mx.priority),
                weight: None,
                port: None,
                flags: None,
                tag: None,
            }),
            DnsRecord::TXT(text) => Ok(DomeneshopRecordContent {
                record_type: "TXT",
                data: text,
                priority: None,
                weight: None,
                port: None,
                flags: None,
                tag: None,
            }),
            DnsRecord::SRV(srv) => Ok(DomeneshopRecordContent {
                record_type: "SRV",
                data: srv.target,
                priority: Some(srv.priority),
                weight: Some(srv.weight),
                port: Some(srv.port),
                flags: None,
                tag: None,
            }),
            DnsRecord::TLSA(_) => Err(Error::Unsupported(
                "TLSA records are not supported by Domeneshop".to_string(),
            )),
            DnsRecord::CAA(caa) => {
                let (flags, tag, value) = caa.decompose();
                Ok(DomeneshopRecordContent {
                    record_type: "CAA",
                    data: value,
                    priority: None,
                    weight: None,
                    port: None,
                    flags: Some(flags),
                    tag: Some(tag),
                })
            }
        }
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
            "SRV" => Ok(DnsRecord::SRV(SRVRecord {
                priority: record.priority.unwrap_or_default(),
                weight: record.weight.unwrap_or_default(),
                port: record.port.unwrap_or_default(),
                target: record.data,
            })),
            "CAA" => {
                let flags = record.flags.unwrap_or_default();
                let tag = record.tag.unwrap_or_default();
                Ok(DnsRecord::CAA(build_caa(flags, &tag, &record.data)?))
            }
            other => Err(Error::Parse(format!(
                "Unsupported Domeneshop record type: {other}"
            ))),
        }
    }
}
