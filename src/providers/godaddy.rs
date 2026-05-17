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
use std::time::Duration;

#[derive(Clone)]
pub struct GodaddyProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GodaddyRecord {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub record_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub data: String,
    pub ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

const DEFAULT_API_ENDPOINT: &str = "https://api.godaddy.com";

impl GodaddyProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        api_secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        let api_secret = api_secret.as_ref();
        if api_key.is_empty() || api_secret.is_empty() {
            return Err(Error::Api(
                "GoDaddy API key and secret must not be empty".to_string(),
            ));
        }

        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("sso-key {api_key}:{api_secret}"))
            .with_timeout(timeout);

        Ok(Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
        })
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
        self.replace_records(name, record, ttl, origin).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        self.replace_records(name, record, ttl, origin).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);

        self.client
            .delete(format!(
                "{}/v1/domains/{}/records/{}/{}",
                self.endpoint,
                domain,
                record_type.as_str(),
                subdomain,
            ))
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn replace_records(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let record_type = record.as_type();
        let payload = build_record(record, ttl)?;

        self.client
            .put(format!(
                "{}/v1/domains/{}/records/{}/{}",
                self.endpoint,
                domain,
                record_type.as_str(),
                subdomain,
            ))
            .with_body(vec![payload])?
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn build_record(record: DnsRecord, ttl: u32) -> crate::Result<GodaddyRecord> {
    Ok(match record {
        DnsRecord::A(addr) => GodaddyRecord {
            record_type: None,
            name: None,
            data: addr.to_string(),
            ttl,
            priority: None,
            port: None,
            weight: None,
            protocol: None,
            service: None,
        },
        DnsRecord::AAAA(addr) => GodaddyRecord {
            record_type: None,
            name: None,
            data: addr.to_string(),
            ttl,
            priority: None,
            port: None,
            weight: None,
            protocol: None,
            service: None,
        },
        DnsRecord::CNAME(content) => GodaddyRecord {
            record_type: None,
            name: None,
            data: content,
            ttl,
            priority: None,
            port: None,
            weight: None,
            protocol: None,
            service: None,
        },
        DnsRecord::NS(content) => GodaddyRecord {
            record_type: None,
            name: None,
            data: content,
            ttl,
            priority: None,
            port: None,
            weight: None,
            protocol: None,
            service: None,
        },
        DnsRecord::MX(mx) => GodaddyRecord {
            record_type: None,
            name: None,
            data: mx.exchange,
            ttl,
            priority: Some(mx.priority),
            port: None,
            weight: None,
            protocol: None,
            service: None,
        },
        DnsRecord::TXT(content) => GodaddyRecord {
            record_type: None,
            name: None,
            data: content,
            ttl,
            priority: None,
            port: None,
            weight: None,
            protocol: None,
            service: None,
        },
        DnsRecord::SRV(srv) => GodaddyRecord {
            record_type: None,
            name: None,
            data: srv.target,
            ttl,
            priority: Some(srv.priority),
            port: Some(srv.port),
            weight: Some(srv.weight),
            protocol: None,
            service: None,
        },
        DnsRecord::CAA(caa) => GodaddyRecord {
            record_type: None,
            name: None,
            data: caa.to_string(),
            ttl,
            priority: None,
            port: None,
            weight: None,
            protocol: None,
            service: None,
        },
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by GoDaddy".to_string(),
            ));
        }
    })
}
