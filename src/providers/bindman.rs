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

use base64::{Engine, engine::general_purpose::STANDARD};

use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, http::HttpClientBuilder};
use serde::Serialize;
use std::time::Duration;

#[derive(Clone)]
pub struct BindmanProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug)]
pub struct BindmanRecord<'a> {
    pub name: String,
    pub value: String,
    #[serde(rename = "type")]
    pub rr_type: &'a str,
}

impl BindmanProvider {
    pub(crate) fn new(
        manager_url: impl AsRef<str>,
        basic_auth: Option<(impl AsRef<str>, impl AsRef<str>)>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let raw = manager_url.as_ref().trim_end_matches('/');
        if raw.is_empty() {
            return Err(Error::Api("Bindman manager address is required".into()));
        }

        let mut client = HttpClientBuilder::default()
            .with_header("Accept", "application/json")
            .with_timeout(timeout);
        if let Some((user, password)) = basic_auth {
            let token = STANDARD.encode(format!("{}:{}", user.as_ref(), password.as_ref()));
            client = client.with_header("Authorization", format!("Basic {token}"));
        }

        Ok(Self {
            client,
            endpoint: raw.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().trim_end_matches('/').to_string(),
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
        let _ = (ttl, origin);
        self.upsert(name, record).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let _ = (ttl, origin);
        let fqdn = name.into_fqdn().to_string();
        self.delete_record(&fqdn, record.as_type()).await.ok();
        self.post_record(&fqdn, &record).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let _ = origin;
        let fqdn = name.into_fqdn().to_string();
        self.delete_record(&fqdn, record_type).await
    }

    async fn upsert(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
    ) -> crate::Result<()> {
        let fqdn = name.into_fqdn().to_string();
        self.post_record(&fqdn, &record).await
    }

    async fn post_record(&self, fqdn: &str, record: &DnsRecord) -> crate::Result<()> {
        let body = BindmanRecord {
            name: fqdn.to_string(),
            value: bindman_value(record)?,
            rr_type: record.as_type().as_str(),
        };
        self.client
            .post(format!("{}/records", self.endpoint))
            .with_body(body)?
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn delete_record(
        &self,
        fqdn: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/records/{}/{}",
                self.endpoint,
                fqdn,
                record_type.as_str()
            ))
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn bindman_value(record: &DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(value) => value.clone(),
        DnsRecord::NS(value) => value.clone(),
        DnsRecord::MX(mx) => mx.to_string(),
        DnsRecord::TXT(text) => text.clone(),
        DnsRecord::SRV(srv) => srv.to_string(),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    })
}
