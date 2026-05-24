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
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

const DEFAULT_API_ENDPOINT: &str = "https://api.digitalocean.com";
const LIST_PAGE_SIZE: u32 = 200;

#[derive(Clone)]
pub struct DigitalOceanProvider {
    client: HttpClient,
    endpoint: Cow<'static, str>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ListDomainRecord {
    domain_records: Vec<DomainRecord>,
    #[serde(default)]
    links: ListLinks,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct ListLinks {
    #[serde(default)]
    pages: ListPages,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct ListPages {
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct UpdateDomainRecord<'a> {
    ttl: u32,
    name: &'a str,
    #[serde(flatten)]
    data: RecordData,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DomainRecord {
    id: i64,
    ttl: u32,
    name: String,
    #[serde(flatten)]
    data: RecordData,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type")]
#[allow(clippy::upper_case_acronyms)]
pub enum RecordData {
    A {
        data: Ipv4Addr,
    },
    AAAA {
        data: Ipv6Addr,
    },
    CNAME {
        data: String,
    },
    NS {
        data: String,
    },
    MX {
        data: String,
        priority: u16,
    },
    TXT {
        data: String,
    },
    SRV {
        data: String,
        priority: u16,
        port: u16,
        weight: u16,
    },
    CAA {
        data: String,
        flags: u8,
        tag: String,
    },
}

#[derive(Serialize, Debug)]
pub struct Query<'a> {
    name: &'a str,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    record_type: Option<&'static str>,
}

impl DigitalOceanProvider {
    pub(crate) fn new(auth_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", auth_token.as_ref()))
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
        reject_unsupported(record_type)?;
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let desired = build_record_data(record_type, records)?;
        let existing = self
            .list_at(&domain, &name, &subdomain, record_type)
            .await?;

        let mut existing_pool: Vec<DomainRecord> = existing;
        let mut to_add: Vec<RecordData> = Vec::new();

        for data in desired {
            if let Some(idx) = existing_pool.iter().position(|r| r.data == data) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(data);
            }
        }

        for entry in existing_pool {
            self.delete_record(&domain, entry.id).await?;
        }
        for data in to_add {
            self.create_record(&domain, &subdomain, ttl, data).await?;
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
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let desired = build_record_data(record_type, records)?;
        let existing = self
            .list_at(&domain, &name, &subdomain, record_type)
            .await?;

        for data in desired {
            if existing.iter().any(|r| r.data == data) {
                continue;
            }
            self.create_record(&domain, &subdomain, ttl, data).await?;
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
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let to_remove = build_record_data(record_type, records)?;
        let existing = self
            .list_at(&domain, &name, &subdomain, record_type)
            .await?;

        for data in to_remove {
            if let Some(entry) = existing.iter().find(|r| r.data == data) {
                self.delete_record(&domain, entry.id).await?;
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
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let listed = self
            .list_at(&domain, &name, &subdomain, record_type)
            .await?;
        listed.into_iter().map(|r| r.data.try_into()).collect()
    }

    async fn list_at(
        &self,
        domain: &str,
        name: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<DomainRecord>> {
        let mut out: Vec<DomainRecord> = Vec::new();
        let mut page: u32 = 1;
        loop {
            let url = format!(
                "{}/v2/domains/{domain}/records?{}&per_page={LIST_PAGE_SIZE}&page={page}",
                self.endpoint,
                Query::name_and_type(name, record_type).serialize()
            );
            let response: ListDomainRecord = self.client.get(url).send_with_retry(3).await?;
            let returned = response.domain_records.len() as u32;
            for record in response.domain_records {
                if record.name == subdomain && record.data.is_type(record_type) {
                    out.push(record);
                }
            }
            if response.links.pages.next.is_none() || returned < LIST_PAGE_SIZE {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    async fn create_record(
        &self,
        domain: &str,
        subdomain: &str,
        ttl: u32,
        data: RecordData,
    ) -> crate::Result<()> {
        self.client
            .post(format!("{}/v2/domains/{domain}/records", self.endpoint))
            .with_body(UpdateDomainRecord {
                ttl,
                name: subdomain,
                data,
            })?
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, domain: &str, record_id: i64) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/v2/domains/{domain}/records/{record_id}",
                self.endpoint
            ))
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn reject_unsupported(record_type: DnsRecordType) -> crate::Result<()> {
    if record_type == DnsRecordType::TLSA {
        return Err(Error::Api(
            "TLSA records are not supported by DigitalOcean".to_string(),
        ));
    }
    Ok(())
}

fn build_record_data(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<RecordData>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(RecordData::try_from(record).map_err(|err| Error::Api(err.to_string()))?);
    }
    Ok(out)
}

fn ensure_absolute(host: String) -> String {
    if host.is_empty() || host.ends_with('.') {
        host
    } else {
        format!("{host}.")
    }
}

impl RecordData {
    fn is_type(&self, record_type: DnsRecordType) -> bool {
        matches!(
            (self, record_type),
            (RecordData::A { .. }, DnsRecordType::A)
                | (RecordData::AAAA { .. }, DnsRecordType::AAAA)
                | (RecordData::CNAME { .. }, DnsRecordType::CNAME)
                | (RecordData::NS { .. }, DnsRecordType::NS)
                | (RecordData::MX { .. }, DnsRecordType::MX)
                | (RecordData::TXT { .. }, DnsRecordType::TXT)
                | (RecordData::SRV { .. }, DnsRecordType::SRV)
                | (RecordData::CAA { .. }, DnsRecordType::CAA)
        )
    }
}

impl<'a> Query<'a> {
    pub fn name(name: impl Into<&'a str>) -> Self {
        Self {
            name: name.into(),
            record_type: None,
        }
    }

    pub fn name_and_type(name: impl Into<&'a str>, record_type: DnsRecordType) -> Self {
        Self {
            name: name.into(),
            record_type: Some(record_type.as_str()),
        }
    }

    pub fn serialize(&self) -> String {
        serde_urlencoded::to_string(self).unwrap()
    }
}

impl TryFrom<DnsRecord> for RecordData {
    type Error = &'static str;

    fn try_from(record: DnsRecord) -> Result<Self, Self::Error> {
        match record {
            DnsRecord::A(content) => Ok(RecordData::A { data: content }),
            DnsRecord::AAAA(content) => Ok(RecordData::AAAA { data: content }),
            DnsRecord::CNAME(content) => Ok(RecordData::CNAME {
                data: ensure_absolute(content),
            }),
            DnsRecord::NS(content) => Ok(RecordData::NS {
                data: ensure_absolute(content),
            }),
            DnsRecord::MX(mx) => Ok(RecordData::MX {
                data: ensure_absolute(mx.exchange),
                priority: mx.priority,
            }),
            DnsRecord::TXT(content) => Ok(RecordData::TXT { data: content }),
            DnsRecord::SRV(srv) => Ok(RecordData::SRV {
                data: ensure_absolute(srv.target),
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
            }),
            DnsRecord::TLSA(_) => Err("TLSA records are not supported by DigitalOcean"),
            DnsRecord::CAA(caa) => {
                let (flags, tag, value) = caa.decompose();
                Ok(RecordData::CAA {
                    data: value,
                    flags,
                    tag,
                })
            }
        }
    }
}

impl TryFrom<RecordData> for DnsRecord {
    type Error = Error;

    fn try_from(data: RecordData) -> crate::Result<Self> {
        Ok(match data {
            RecordData::A { data } => DnsRecord::A(data),
            RecordData::AAAA { data } => DnsRecord::AAAA(data),
            RecordData::CNAME { data } => DnsRecord::CNAME(data),
            RecordData::NS { data } => DnsRecord::NS(data),
            RecordData::MX { data, priority } => DnsRecord::MX(MXRecord {
                exchange: data,
                priority,
            }),
            RecordData::TXT { data } => DnsRecord::TXT(data),
            RecordData::SRV {
                data,
                priority,
                port,
                weight,
            } => DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target: data,
            }),
            RecordData::CAA { data, flags, tag } => DnsRecord::CAA(build_caa(flags, tag, data)?),
        })
    }
}

fn build_caa(flags: u8, tag: String, value: String) -> crate::Result<CAARecord> {
    let issuer_critical = flags & 0x80 != 0;
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
