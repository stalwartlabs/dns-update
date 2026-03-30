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

use crate::{DnsRecord, Error, IntoFqdn, http::HttpClientBuilder, utils::strip_origin_from_name};
use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

#[derive(Clone)]
pub struct DigitalOceanProvider {
    client: HttpClientBuilder,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ListDomainRecord {
    domain_records: Vec<DomainRecord>,
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

#[derive(Deserialize, Serialize, Clone, Debug)]
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
}

impl DigitalOceanProvider {
    pub(crate) fn new(auth_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", auth_token.as_ref()))
            .with_timeout(timeout);
        Self { client }
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
            .post(format!(
                "https://api.digitalocean.com/v2/domains/{domain}/records",
            ))
            .with_body(UpdateDomainRecord {
                ttl,
                name: &subdomain,
                data: RecordData::try_from(record).map_err(|err| Error::Api(err.to_string()))?,
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
        let record_id = self.obtain_record_id(&name, &domain).await?;

        self.client
            .put(format!(
                "https://api.digitalocean.com/v2/domains/{domain}/records/{record_id}",
            ))
            .with_body(UpdateDomainRecord {
                ttl,
                name: &subdomain,
                data: RecordData::try_from(record).map_err(|err| Error::Api(err.to_string()))?,
            })?
            .send_raw()
            .await
            .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let record_id = self.obtain_record_id(&name, &domain).await?;

        self.client
            .delete(format!(
                "https://api.digitalocean.com/v2/domains/{domain}/records/{record_id}",
            ))
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn obtain_record_id(&self, name: &str, domain: &str) -> crate::Result<i64> {
        let subdomain = strip_origin_from_name(name, domain, None);
        self.client
            .get(format!(
                "https://api.digitalocean.com/v2/domains/{domain}/records?{}",
                Query::name(name).serialize()
            ))
            .send_with_retry::<ListDomainRecord>(3)
            .await
            .and_then(|result| {
                result
                    .domain_records
                    .into_iter()
                    .find(|record| record.name == subdomain)
                    .map(|record| record.id)
                    .ok_or_else(|| Error::Api(format!("DNS Record {} not found", subdomain)))
            })
    }
}

impl<'a> Query<'a> {
    pub fn name(name: impl Into<&'a str>) -> Self {
        Self { name: name.into() }
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
            DnsRecord::CNAME(content) => Ok(RecordData::CNAME { data: content }),
            DnsRecord::NS(content) => Ok(RecordData::NS { data: content }),
            DnsRecord::MX(mx) => Ok(RecordData::MX {
                data: mx.exchange,
                priority: mx.priority,
            }),
            DnsRecord::TXT(content) => Ok(RecordData::TXT { data: content }),
            DnsRecord::SRV(srv) => Ok(RecordData::SRV {
                data: srv.target,
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
