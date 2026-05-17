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
use std::{borrow::Cow, time::Duration};

const DEFAULT_API_ENDPOINT: &str = "https://api.gcore.com/dns";

#[derive(Clone)]
pub struct GcoreProvider {
    client: HttpClientBuilder,
    endpoint: Cow<'static, str>,
}

#[derive(Deserialize, Debug)]
struct Zone {
    name: String,
}

#[derive(Serialize, Debug)]
struct RrSet {
    ttl: u32,
    resource_records: Vec<ResourceRecord>,
}

#[derive(Serialize, Debug)]
struct ResourceRecord {
    content: Vec<serde_json::Value>,
}

impl GcoreProvider {
    pub(crate) fn new(api_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("APIKey {}", api_token.as_ref()))
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
        let zone = self.obtain_zone(&origin.into_name()).await?;
        let fqdn = name.into_name();
        let record_type = record.as_type().as_str();
        let body = build_rrset(record, ttl)?;
        self.client
            .post(format!(
                "{}/v2/zones/{}/{}/{}",
                self.endpoint, zone, fqdn, record_type
            ))
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
        let zone = self.obtain_zone(&origin.into_name()).await?;
        let fqdn = name.into_name();
        let record_type = record.as_type().as_str();
        let body = build_rrset(record, ttl)?;
        self.client
            .put(format!(
                "{}/v2/zones/{}/{}/{}",
                self.endpoint, zone, fqdn, record_type
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
        let zone = self.obtain_zone(&origin.into_name()).await?;
        let fqdn = name.into_name();
        self.client
            .delete(format!(
                "{}/v2/zones/{}/{}/{}",
                self.endpoint,
                zone,
                fqdn,
                record_type.as_str()
            ))
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn obtain_zone(&self, origin: &str) -> crate::Result<String> {
        let mut candidate: &str = origin;
        loop {
            let result = self
                .client
                .get(format!("{}/v2/zones/{}", self.endpoint, candidate))
                .send_with_retry::<Zone>(3)
                .await;
            match result {
                Ok(zone) => return Ok(zone.name),
                Err(Error::NotFound) => {}
                Err(err) => return Err(err),
            }
            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => {
                    return Err(Error::Api(format!("No Gcore zone found for {origin}")));
                }
            }
        }
    }
}

fn build_rrset(record: DnsRecord, ttl: u32) -> crate::Result<RrSet> {
    use serde_json::Value;
    let content: Vec<Value> = match record {
        DnsRecord::A(addr) => vec![Value::String(addr.to_string())],
        DnsRecord::AAAA(addr) => vec![Value::String(addr.to_string())],
        DnsRecord::CNAME(content) => vec![Value::String(content)],
        DnsRecord::NS(content) => vec![Value::String(content)],
        DnsRecord::MX(mx) => vec![
            Value::Number(mx.priority.into()),
            Value::String(mx.exchange),
        ],
        DnsRecord::TXT(content) => vec![Value::String(content)],
        DnsRecord::SRV(srv) => vec![
            Value::Number(srv.priority.into()),
            Value::Number(srv.weight.into()),
            Value::Number(srv.port.into()),
            Value::String(srv.target),
        ],
        DnsRecord::TLSA(tlsa) => vec![Value::String(tlsa.to_string())],
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.decompose();
            vec![
                Value::Number(flags.into()),
                Value::String(tag),
                Value::String(value),
            ]
        }
    };
    Ok(RrSet {
        ttl,
        resource_records: vec![ResourceRecord { content }],
    })
}
