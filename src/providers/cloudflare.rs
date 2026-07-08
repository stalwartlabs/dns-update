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
use crate::utils::unquote_txt;
use crate::utils::{
    decode_hex, tlsa_cert_usage_from_u8, tlsa_matching_from_u8, tlsa_selector_from_u8,
};
use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord, TLSARecord,
    http::{HttpClient, HttpClientBuilder},
    utils::txt_chunks_to_text,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

#[derive(Clone)]
pub struct CloudflareProvider {
    client: HttpClient,
    endpoint: Cow<'static, str>,
}

#[derive(Deserialize, Debug)]
pub struct IdMap {
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Debug)]
pub struct Query {
    name: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    record_type: Option<&'static str>,
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    match_mode: Option<&'static str>,
}

#[derive(Serialize, Clone, Debug)]
pub struct CreateDnsRecordParams<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,
    pub name: &'a str,
    #[serde(flatten)]
    pub content: DnsContent,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type")]
#[allow(clippy::upper_case_acronyms)]
pub enum DnsContent {
    A { content: Ipv4Addr },
    AAAA { content: Ipv6Addr },
    CNAME { content: String },
    NS { content: String },
    MX { content: String, priority: u16 },
    TXT { content: String },
    SRV { data: SrvData },
    TLSA { data: TlsaData },
    CAA { data: CaaData },
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct SrvData {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct TlsaData {
    pub usage: u8,
    pub selector: u8,
    pub matching_type: u8,
    pub certificate: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct CaaData {
    pub flags: u8,
    pub tag: String,
    pub value: String,
}

#[derive(Deserialize, Debug, Clone)]
struct ListedRecord {
    id: String,
    #[serde(flatten)]
    content: DnsContent,
}

#[derive(Deserialize, Serialize, Debug)]
struct ApiResult<T> {
    errors: Vec<ApiError>,
    success: bool,
    result: T,
}

const DEFAULT_API_ENDPOINT: &str = "https://api.cloudflare.com/client/v4";

#[derive(Deserialize, Serialize, Debug)]
pub struct ApiError {
    pub code: u16,
    pub message: String,
}

impl CloudflareProvider {
    pub(crate) fn new(secret: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", secret.as_ref()))
            .with_timeout(timeout)
            .build();

        Ok(Self {
            client,
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

    async fn obtain_zone_id(&self, origin: impl IntoFqdn<'_>) -> crate::Result<String> {
        let origin = origin.into_name();
        let mut candidate: &str = origin.as_ref();
        loop {
            let zones = self
                .client
                .get(format!(
                    "{}/zones?{}",
                    self.endpoint,
                    Query::name(candidate).serialize()
                ))
                .send_with_retry::<ApiResult<Vec<IdMap>>>(3)
                .await
                .and_then(|r| r.unwrap_response("list zones"))?;
            if let Some(zone) = zones.into_iter().find(|zone| zone.name == candidate) {
                return Ok(zone.id);
            }
            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => {
                    return Err(Error::Api(format!(
                        "No Cloudflare zone found for {}",
                        origin.as_ref()
                    )));
                }
            }
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
        let zone_id = self.obtain_zone_id(origin).await?;
        let name = name.into_name().into_owned();
        let desired = build_contents(record_type, records)?;
        let existing = self.list_at(&zone_id, &name, record_type).await?;

        let mut to_add = Vec::new();
        let mut existing_unmatched: Vec<ListedRecord> = Vec::new();
        let mut existing_iter = existing.into_iter();
        let mut existing_pool: Vec<ListedRecord> = existing_iter.by_ref().collect();

        for content in desired {
            if let Some(idx) = existing_pool.iter().position(|r| r.content == content) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(content);
            }
        }
        existing_unmatched.append(&mut existing_pool);

        for entry in existing_unmatched {
            self.delete_record(&zone_id, &entry.id).await?;
        }
        for content in to_add {
            self.create_record(&zone_id, &name, ttl, content).await?;
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
        let zone_id = self.obtain_zone_id(origin).await?;
        let name = name.into_name().into_owned();
        let desired = build_contents(record_type, records)?;
        let existing = self.list_at(&zone_id, &name, record_type).await?;

        for content in desired {
            if existing.iter().any(|r| r.content == content) {
                continue;
            }
            self.create_record(&zone_id, &name, ttl, content).await?;
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
        let zone_id = self.obtain_zone_id(origin).await?;
        let name = name.into_name().into_owned();
        let to_remove = build_contents(record_type, records)?;
        let existing = self.list_at(&zone_id, &name, record_type).await?;

        for content in to_remove {
            if let Some(entry) = existing.iter().find(|r| r.content == content) {
                self.delete_record(&zone_id, &entry.id).await?;
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
        let zone_id = self.obtain_zone_id(origin).await?;
        let name = name.into_name().into_owned();
        let listed = self.list_at(&zone_id, &name, record_type).await?;
        listed.into_iter().map(|r| r.content.try_into()).collect()
    }

    #[cfg(test)]
    pub(crate) async fn list_contents_for_tests(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsContent>> {
        let zone_id = self.obtain_zone_id(origin).await?;
        let name = name.into_name().into_owned();
        let listed = self.list_at(&zone_id, &name, record_type).await?;
        Ok(listed.into_iter().map(|r| r.content).collect())
    }

    async fn list_at(
        &self,
        zone_id: &str,
        name: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ListedRecord>> {
        let url = format!(
            "{}/zones/{zone_id}/dns_records?{}&per_page=100",
            self.endpoint,
            Query::name_and_type(name, record_type).serialize()
        );
        let response: ApiResult<Vec<ListedRecord>> =
            self.client.get(url).send_with_retry(3).await?;
        response.unwrap_response("list DNS records")
    }

    async fn create_record(
        &self,
        zone_id: &str,
        name: &str,
        ttl: u32,
        content: DnsContent,
    ) -> crate::Result<()> {
        let priority = match &content {
            DnsContent::MX { priority, .. } => Some(*priority),
            _ => None,
        };
        self.client
            .post(format!("{}/zones/{zone_id}/dns_records", self.endpoint))
            .with_body(CreateDnsRecordParams {
                ttl: Some(ttl),
                priority,
                proxied: Some(false),
                name,
                content,
            })?
            .send_with_retry::<ApiResult<Value>>(3)
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, zone_id: &str, record_id: &str) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/zones/{zone_id}/dns_records/{record_id}",
                self.endpoint
            ))
            .send_with_retry::<ApiResult<Value>>(3)
            .await
            .map(|_| ())
    }
}

fn build_contents(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<DnsContent>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(record.into());
    }
    Ok(out)
}

impl<T> ApiResult<T> {
    fn unwrap_response(self, action_name: &str) -> crate::Result<T> {
        if self.success {
            Ok(self.result)
        } else {
            Err(Error::Api(format!(
                "Failed to {action_name}: {:?}",
                self.errors
            )))
        }
    }
}

impl Query {
    pub fn name(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            record_type: None,
            match_mode: None,
        }
    }

    pub fn name_and_type(name: impl Into<String>, record_type: DnsRecordType) -> Self {
        Self {
            name: name.into(),
            record_type: Some(record_type.as_str()),
            match_mode: Some("all"),
        }
    }

    pub fn serialize(&self) -> String {
        serde_urlencoded::to_string(self).unwrap()
    }
}

impl From<DnsRecord> for DnsContent {
    fn from(record: DnsRecord) -> Self {
        match record {
            DnsRecord::A(content) => DnsContent::A { content },
            DnsRecord::AAAA(content) => DnsContent::AAAA { content },
            DnsRecord::CNAME(content) => DnsContent::CNAME { content },
            DnsRecord::NS(content) => DnsContent::NS { content },
            DnsRecord::MX(mx) => DnsContent::MX {
                content: mx.exchange,
                priority: mx.priority,
            },
            DnsRecord::TXT(content) => {
                let mut out = String::with_capacity(content.len() + 4);
                txt_chunks_to_text(&mut out, &content, " ");
                DnsContent::TXT { content: out }
            }
            DnsRecord::SRV(srv) => DnsContent::SRV {
                data: SrvData {
                    priority: srv.priority,
                    weight: srv.weight,
                    port: srv.port,
                    target: srv.target,
                },
            },
            DnsRecord::TLSA(tlsa) => DnsContent::TLSA {
                data: TlsaData {
                    usage: u8::from(tlsa.cert_usage),
                    selector: u8::from(tlsa.selector),
                    matching_type: u8::from(tlsa.matching),
                    certificate: tlsa.cert_data.iter().map(|b| format!("{b:02x}")).collect(),
                },
            },
            DnsRecord::CAA(caa) => {
                let (flags, tag, value) = caa.decompose();
                DnsContent::CAA {
                    data: CaaData { flags, tag, value },
                }
            }
        }
    }
}

impl TryFrom<DnsContent> for DnsRecord {
    type Error = Error;

    fn try_from(content: DnsContent) -> crate::Result<Self> {
        Ok(match content {
            DnsContent::A { content } => DnsRecord::A(content),
            DnsContent::AAAA { content } => DnsRecord::AAAA(content),
            DnsContent::CNAME { content } => DnsRecord::CNAME(content),
            DnsContent::NS { content } => DnsRecord::NS(content),
            DnsContent::MX { content, priority } => DnsRecord::MX(MXRecord {
                exchange: content,
                priority,
            }),
            DnsContent::TXT { content } => DnsRecord::TXT(unquote_txt(&content)),
            DnsContent::SRV { data } => DnsRecord::SRV(SRVRecord {
                priority: data.priority,
                weight: data.weight,
                port: data.port,
                target: data.target,
            }),
            DnsContent::TLSA { data } => DnsRecord::TLSA(TLSARecord {
                cert_usage: tlsa_cert_usage_from_u8(data.usage)?,
                selector: tlsa_selector_from_u8(data.selector)?,
                matching: tlsa_matching_from_u8(data.matching_type)?,
                cert_data: decode_hex(&data.certificate)?,
            }),
            DnsContent::CAA { data } => {
                DnsRecord::CAA(build_caa(data.flags, &data.tag, &data.value)?)
            }
        })
    }
}
