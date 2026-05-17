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
pub struct GandiV5Provider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct RRSetPayload {
    rrset_ttl: u32,
    rrset_values: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct ApiMessage {
    #[allow(dead_code)]
    #[serde(default)]
    message: Option<String>,
}

const DEFAULT_API_ENDPOINT: &str = "https://api.gandi.net/v5/livedns";

impl GandiV5Provider {
    pub(crate) fn new(
        personal_access_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let token = personal_access_token.as_ref();
        if token.is_empty() {
            return Err(Error::Api(
                "Gandi personal access token must not be empty".to_string(),
            ));
        }

        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {token}"))
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
        self.put_rrset(name, record, ttl, origin).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        self.put_rrset(name, record, ttl, origin).await
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
                "{}/domains/{}/records/{}/{}",
                self.endpoint,
                domain,
                subdomain,
                record_type.as_str(),
            ))
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn put_rrset(
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
        let value = render_value(record)?;

        self.client
            .put(format!(
                "{}/domains/{}/records/{}/{}",
                self.endpoint,
                domain,
                subdomain,
                record_type.as_str(),
            ))
            .with_body(RRSetPayload {
                rrset_ttl: ttl,
                rrset_values: vec![value],
            })?
            .send::<ApiMessage>()
            .await
            .map(|_| ())
    }
}

fn render_value(record: DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => ensure_trailing_dot(content),
        DnsRecord::NS(content) => ensure_trailing_dot(content),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, ensure_trailing_dot(mx.exchange)),
        DnsRecord::TXT(content) => format!("\"{}\"", content.replace('\"', "\\\"")),
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            ensure_trailing_dot(srv.target),
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    })
}

fn ensure_trailing_dot(value: String) -> String {
    if value.ends_with('.') {
        value
    } else {
        format!("{value}.")
    }
}
