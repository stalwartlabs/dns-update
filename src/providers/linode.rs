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

const DEFAULT_API_ENDPOINT: &str = "https://api.linode.com/v4";

#[derive(Clone)]
pub struct LinodeProvider {
    client: HttpClientBuilder,
    endpoint: Cow<'static, str>,
}

#[derive(Deserialize, Debug)]
struct PagedDomains {
    data: Vec<Domain>,
}

#[derive(Deserialize, Debug)]
struct Domain {
    id: i64,
    domain: String,
}

#[derive(Deserialize, Debug)]
struct PagedDomainRecords {
    data: Vec<DomainRecord>,
}

#[derive(Deserialize, Debug)]
struct DomainRecord {
    id: i64,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
}

#[derive(Serialize, Debug)]
struct DomainRecordRequest<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'static str,
    target: String,
    ttl_sec: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
}

impl LinodeProvider {
    pub(crate) fn new(auth_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", auth_token.as_ref()))
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
        let domain_id = self.obtain_domain_id(&domain).await?;
        let body = build_request(&subdomain, record, ttl)?;

        self.client
            .post(format!("{}/domains/{}/records", self.endpoint, domain_id))
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
        let domain_id = self.obtain_domain_id(&domain).await?;
        let record_id = self
            .obtain_record_id(domain_id, &subdomain, record.as_type())
            .await?;
        let body = build_request(&subdomain, record, ttl)?;

        self.client
            .put(format!(
                "{}/domains/{}/records/{}",
                self.endpoint, domain_id, record_id
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
        let domain_id = self.obtain_domain_id(&domain).await?;
        let record_id = self
            .obtain_record_id(domain_id, &subdomain, record_type)
            .await?;

        self.client
            .delete(format!(
                "{}/domains/{}/records/{}",
                self.endpoint, domain_id, record_id
            ))
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn obtain_domain_id(&self, domain: &str) -> crate::Result<i64> {
        self.client
            .get(format!("{}/domains", self.endpoint))
            .with_header("X-Filter", format!(r#"{{"domain":"{}"}}"#, domain))
            .send_with_retry::<PagedDomains>(3)
            .await
            .and_then(|response| {
                response
                    .data
                    .into_iter()
                    .find(|d| d.domain == domain)
                    .map(|d| d.id)
                    .ok_or_else(|| Error::Api(format!("Linode domain {domain} not found")))
            })
    }

    async fn obtain_record_id(
        &self,
        domain_id: i64,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<i64> {
        let wanted_type = record_type.as_str();
        self.client
            .get(format!(
                "{}/domains/{}/records",
                self.endpoint, domain_id
            ))
            .send_with_retry::<PagedDomainRecords>(3)
            .await
            .and_then(|response| {
                response
                    .data
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

fn build_request<'a>(
    subdomain: &'a str,
    record: DnsRecord,
    ttl: u32,
) -> crate::Result<DomainRecordRequest<'a>> {
    let record_type = record.as_type().as_str();
    match record {
        DnsRecord::A(addr) => Ok(DomainRecordRequest {
            name: subdomain,
            record_type,
            target: addr.to_string(),
            ttl_sec: ttl,
            priority: None,
            weight: None,
            port: None,
            tag: None,
        }),
        DnsRecord::AAAA(addr) => Ok(DomainRecordRequest {
            name: subdomain,
            record_type,
            target: addr.to_string(),
            ttl_sec: ttl,
            priority: None,
            weight: None,
            port: None,
            tag: None,
        }),
        DnsRecord::CNAME(content) => Ok(DomainRecordRequest {
            name: subdomain,
            record_type,
            target: content,
            ttl_sec: ttl,
            priority: None,
            weight: None,
            port: None,
            tag: None,
        }),
        DnsRecord::NS(content) => Ok(DomainRecordRequest {
            name: subdomain,
            record_type,
            target: content,
            ttl_sec: ttl,
            priority: None,
            weight: None,
            port: None,
            tag: None,
        }),
        DnsRecord::MX(mx) => Ok(DomainRecordRequest {
            name: subdomain,
            record_type,
            target: mx.exchange,
            ttl_sec: ttl,
            priority: Some(mx.priority),
            weight: None,
            port: None,
            tag: None,
        }),
        DnsRecord::TXT(content) => Ok(DomainRecordRequest {
            name: subdomain,
            record_type,
            target: content,
            ttl_sec: ttl,
            priority: None,
            weight: None,
            port: None,
            tag: None,
        }),
        DnsRecord::SRV(srv) => Ok(DomainRecordRequest {
            name: subdomain,
            record_type,
            target: srv.target,
            ttl_sec: ttl,
            priority: Some(srv.priority),
            weight: Some(srv.weight),
            port: Some(srv.port),
            tag: None,
        }),
        DnsRecord::TLSA(_) => Err(Error::Api(
            "TLSA records are not supported by Linode".to_string(),
        )),
        DnsRecord::CAA(caa) => {
            let (_flags, tag, value) = caa.decompose();
            Ok(DomainRecordRequest {
                name: subdomain,
                record_type,
                target: value,
                ttl_sec: ttl,
                priority: None,
                weight: None,
                port: None,
                tag: Some(tag),
            })
        }
    }
}
