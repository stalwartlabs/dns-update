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

use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, http::HttpClientBuilder};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.ukfast.io/safedns/v1";

#[derive(Clone)]
pub struct SafeDnsProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct SafeDnsRecordPayload<'a> {
    pub name: &'a str,
    #[serde(rename = "type")]
    pub record_type: &'a str,
    pub content: String,
    pub ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SafeDnsRecord {
    pub id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
}

#[derive(Deserialize, Debug)]
pub struct ListRecordsResponse {
    pub data: Vec<SafeDnsRecord>,
}

#[derive(Deserialize, Debug)]
pub struct AddRecordResponse {
    #[allow(dead_code)]
    pub data: SafeDnsRecord,
}

pub struct SafeDnsRecordContent {
    pub record_type: &'static str,
    pub content: String,
    pub priority: Option<u16>,
}

impl SafeDnsProvider {
    pub(crate) fn new(auth_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", auth_token.as_ref())
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
        let fqdn = name.into_name().to_string();
        let zone = origin.into_name().to_string();
        let content = SafeDnsRecordContent::try_from(record)?;
        let body = SafeDnsRecordPayload {
            name: &fqdn,
            record_type: content.record_type,
            content: content.content,
            ttl,
            priority: content.priority,
        };

        self.client
            .post(format!(
                "{endpoint}/zones/{zone}/records",
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
        let fqdn = name.into_name().to_string();
        let zone = origin.into_name().to_string();
        let record_type = record.as_type();
        let record_id = self.find_record_id(&zone, &fqdn, record_type).await?;
        let content = SafeDnsRecordContent::try_from(record)?;
        let body = SafeDnsRecordPayload {
            name: &fqdn,
            record_type: content.record_type,
            content: content.content,
            ttl,
            priority: content.priority,
        };

        self.client
            .patch(format!(
                "{endpoint}/zones/{zone}/records/{record_id}",
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
        let fqdn = name.into_name().to_string();
        let zone = origin.into_name().to_string();
        let record_id = self.find_record_id(&zone, &fqdn, record_type).await?;

        self.client
            .delete(format!(
                "{endpoint}/zones/{zone}/records/{record_id}",
                endpoint = self.endpoint
            ))
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn find_record_id(
        &self,
        zone: &str,
        name: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<i64> {
        let response: ListRecordsResponse = self
            .client
            .get(format!(
                "{endpoint}/zones/{zone}/records",
                endpoint = self.endpoint
            ))
            .send()
            .await?;
        let type_str = record_type.as_str();
        response
            .data
            .into_iter()
            .find(|r| r.name == name && r.record_type == type_str)
            .map(|r| r.id)
            .ok_or_else(|| {
                Error::Api(format!(
                    "DNS Record {name} of type {type_str} not found"
                ))
            })
    }
}

impl TryFrom<DnsRecord> for SafeDnsRecordContent {
    type Error = Error;

    fn try_from(record: DnsRecord) -> Result<Self, Self::Error> {
        match record {
            DnsRecord::A(addr) => Ok(SafeDnsRecordContent {
                record_type: "A",
                content: addr.to_string(),
                priority: None,
            }),
            DnsRecord::AAAA(addr) => Ok(SafeDnsRecordContent {
                record_type: "AAAA",
                content: addr.to_string(),
                priority: None,
            }),
            DnsRecord::CNAME(target) => Ok(SafeDnsRecordContent {
                record_type: "CNAME",
                content: target,
                priority: None,
            }),
            DnsRecord::NS(target) => Ok(SafeDnsRecordContent {
                record_type: "NS",
                content: target,
                priority: None,
            }),
            DnsRecord::MX(mx) => Ok(SafeDnsRecordContent {
                record_type: "MX",
                content: mx.exchange,
                priority: Some(mx.priority),
            }),
            DnsRecord::TXT(text) => Ok(SafeDnsRecordContent {
                record_type: "TXT",
                content: format!("\"{text}\""),
                priority: None,
            }),
            DnsRecord::SRV(srv) => Ok(SafeDnsRecordContent {
                record_type: "SRV",
                content: format!("{} {} {} {}", srv.priority, srv.weight, srv.port, srv.target),
                priority: Some(srv.priority),
            }),
            DnsRecord::TLSA(tlsa) => Ok(SafeDnsRecordContent {
                record_type: "TLSA",
                content: tlsa.to_string(),
                priority: None,
            }),
            DnsRecord::CAA(caa) => Ok(SafeDnsRecordContent {
                record_type: "CAA",
                content: caa.to_string(),
                priority: None,
            }),
        }
    }
}
