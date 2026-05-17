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
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, time::Duration};

const DEFAULT_API_ENDPOINT: &str = "https://api.vultr.com/v2";

#[derive(Clone)]
pub struct VultrProvider {
    client: HttpClientBuilder,
    endpoint: Cow<'static, str>,
}

#[derive(Deserialize, Debug)]
struct DomainRecordsResponse {
    records: Vec<VultrRecord>,
}

#[derive(Deserialize, Debug)]
struct VultrRecord {
    id: String,
    #[serde(rename = "type")]
    record_type: String,
    name: String,
}

#[derive(Serialize, Debug)]
struct CreateRecordRequest<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'static str,
    data: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
}

#[derive(Serialize, Debug)]
struct UpdateRecordRequest<'a> {
    name: &'a str,
    data: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
}

impl VultrProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", api_key.as_ref()))
            .with_timeout(timeout);
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

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let domain = origin.into_name();
        let name = name.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let body = build_create(&subdomain, record, ttl)?;

        self.client
            .post(format!("{}/domains/{}/records", self.endpoint, domain))
            .with_body(body)?
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
        let domain = origin.into_name();
        let name = name.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let record_id = self
            .obtain_record_id(&domain, &subdomain, record.as_type())
            .await?;
        let body = build_update(&subdomain, record, ttl)?;

        self.client
            .patch(format!(
                "{}/domains/{}/records/{}",
                self.endpoint, domain, record_id
            ))
            .with_body(body)?
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
        let domain = origin.into_name();
        let name = name.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let record_id = self
            .obtain_record_id(&domain, &subdomain, record_type)
            .await?;

        self.client
            .delete(format!(
                "{}/domains/{}/records/{}",
                self.endpoint, domain, record_id
            ))
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn obtain_record_id(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<String> {
        let wanted_type = record_type.as_str();
        self.client
            .get(format!("{}/domains/{}/records", self.endpoint, domain))
            .send_with_retry::<DomainRecordsResponse>(3)
            .await
            .and_then(|response| {
                response
                    .records
                    .into_iter()
                    .find(|r| r.name == subdomain && r.record_type == wanted_type)
                    .map(|r| r.id)
                    .ok_or_else(|| {
                        Error::Api(format!(
                            "DNS Record {subdomain} of type {wanted_type} not found"
                        ))
                    })
            })
    }
}

fn record_target(record: &DnsRecord) -> Result<String, Error> {
    match record {
        DnsRecord::A(addr) => Ok(addr.to_string()),
        DnsRecord::AAAA(addr) => Ok(addr.to_string()),
        DnsRecord::CNAME(content) => Ok(content.clone()),
        DnsRecord::NS(content) => Ok(content.clone()),
        DnsRecord::MX(mx) => Ok(mx.exchange.clone()),
        DnsRecord::TXT(content) => Ok(format!("\"{}\"", content.replace('"', "\\\""))),
        DnsRecord::SRV(srv) => Ok(format!("{} {} {}", srv.weight, srv.port, srv.target)),
        DnsRecord::TLSA(_) => Err(Error::Api(
            "TLSA records are not supported by Vultr".to_string(),
        )),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            Ok(format!("{flags} {tag} \"{value}\""))
        }
    }
}

fn build_create<'a>(
    subdomain: &'a str,
    record: DnsRecord,
    ttl: u32,
) -> crate::Result<CreateRecordRequest<'a>> {
    let record_type = record.as_type().as_str();
    let priority = match &record {
        DnsRecord::MX(mx) => Some(mx.priority),
        DnsRecord::SRV(srv) => Some(srv.priority),
        _ => None,
    };
    let data = record_target(&record)?;
    Ok(CreateRecordRequest {
        name: subdomain,
        record_type,
        data,
        ttl,
        priority,
    })
}

fn build_update<'a>(
    subdomain: &'a str,
    record: DnsRecord,
    ttl: u32,
) -> crate::Result<UpdateRecordRequest<'a>> {
    let priority = match &record {
        DnsRecord::MX(mx) => Some(mx.priority),
        DnsRecord::SRV(srv) => Some(srv.priority),
        _ => None,
    };
    let data = record_target(&record)?;
    Ok(UpdateRecordRequest {
        name: subdomain,
        data,
        ttl,
        priority,
    })
}
