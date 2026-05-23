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
    utils::{strip_origin_from_name, txt_chunks_to_text},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone)]
pub struct HetznerProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct RRSetCreate<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    ttl: u32,
    records: Vec<RecordValue>,
    zone: &'a str,
}

#[derive(Serialize, Debug)]
struct RRSetReplace {
    ttl: u32,
    records: Vec<RecordValue>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RecordValue {
    value: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ActionResponse {
    #[serde(default)]
    action: Option<serde_json::Value>,
    #[serde(default)]
    rrset: Option<serde_json::Value>,
}

const DEFAULT_API_ENDPOINT: &str = "https://api.hetzner.cloud/v1";

impl HetznerProvider {
    pub(crate) fn new(
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let token = api_token.as_ref();
        if token.is_empty() {
            return Err(Error::Api(
                "Hetzner API token must not be empty".to_string(),
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let record_type = record.as_type();
        let value = render_value(record)?;

        self.client
            .post(format!("{}/zones/{}/rrsets", self.endpoint, domain))
            .with_body(RRSetCreate {
                name: &subdomain,
                record_type: record_type.as_str(),
                ttl,
                records: vec![RecordValue { value }],
                zone: domain.as_ref(),
            })?
            .send::<ActionResponse>()
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
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let record_type = record.as_type();
        let value = render_value(record)?;

        self.client
            .put(format!(
                "{}/zones/{}/rrsets/{}/{}",
                self.endpoint,
                domain,
                subdomain,
                record_type.as_str(),
            ))
            .with_body(RRSetReplace {
                ttl,
                records: vec![RecordValue { value }],
            })?
            .send::<ActionResponse>()
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
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));

        self.client
            .delete(format!(
                "{}/zones/{}/rrsets/{}/{}",
                self.endpoint,
                domain,
                subdomain,
                record_type.as_str(),
            ))
            .send_raw()
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
        DnsRecord::TXT(content) => {
            let mut out = String::with_capacity(content.len() + 4);
            txt_chunks_to_text(&mut out, &content, " ");
            out
        }
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
