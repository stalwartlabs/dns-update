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
    DnsRecord, DnsRecordType, Error, IntoFqdn, http::HttpClientBuilder,
    utils::strip_origin_from_name,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.domeneshop.no/v0";

#[derive(Clone)]
pub struct DomeneshopProvider {
    client: HttpClientBuilder,
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
}

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
            .with_timeout(timeout);
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

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let host = strip_origin_from_name(&name, &domain, Some("@"));
        let domain_id = self.find_domain_id(&domain).await?;
        let content = DomeneshopRecordContent::try_from(record)?;
        let body = DnsRecordPayload {
            host,
            record_type: content.record_type.to_string(),
            data: content.data,
            ttl,
            priority: content.priority,
            weight: content.weight,
            port: content.port,
            flags: content.flags,
            tag: content.tag,
        };

        self.client
            .post(format!(
                "{endpoint}/domains/{domain_id}/dns",
                endpoint = self.endpoint
            ))
            .with_body(&body)?
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
        let host = strip_origin_from_name(&name, &domain, Some("@"));
        let record_type = record.as_type();
        let domain_id = self.find_domain_id(&domain).await?;
        let record_id = self
            .find_record_id(domain_id, &host, record_type)
            .await?;
        let content = DomeneshopRecordContent::try_from(record)?;
        let body = DnsRecordPayload {
            host,
            record_type: content.record_type.to_string(),
            data: content.data,
            ttl,
            priority: content.priority,
            weight: content.weight,
            port: content.port,
            flags: content.flags,
            tag: content.tag,
        };

        self.client
            .put(format!(
                "{endpoint}/domains/{domain_id}/dns/{record_id}",
                endpoint = self.endpoint
            ))
            .with_body(&body)?
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
        let host = strip_origin_from_name(&name, &domain, Some("@"));
        let domain_id = self.find_domain_id(&domain).await?;
        let record_id = self.find_record_id(domain_id, &host, record_type).await?;

        self.client
            .delete(format!(
                "{endpoint}/domains/{domain_id}/dns/{record_id}",
                endpoint = self.endpoint
            ))
            .send_raw()
            .await
            .map(|_| ())
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

    async fn find_record_id(
        &self,
        domain_id: i64,
        host: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<i64> {
        let records: Vec<ExistingDnsRecord> = self
            .client
            .get(format!(
                "{endpoint}/domains/{domain_id}/dns",
                endpoint = self.endpoint
            ))
            .send()
            .await?;
        let type_str = record_type.as_str();
        records
            .into_iter()
            .find(|r| r.host == host && r.record_type == type_str)
            .map(|r| r.id)
            .ok_or_else(|| {
                Error::Api(format!(
                    "DNS Record {host} of type {type_str} not found"
                ))
            })
    }
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
            DnsRecord::TLSA(_) => Err(Error::Api(
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
