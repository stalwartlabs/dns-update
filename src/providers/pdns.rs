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
    utils::txt_chunks_to_text,
};
use serde::Serialize;
use std::time::Duration;

#[derive(Clone)]
pub struct PdnsProvider {
    client: HttpClientBuilder,
    endpoint: String,
    server_name: String,
}

#[derive(Serialize, Debug)]
pub struct RRSets<'a> {
    pub rrsets: Vec<RRSet<'a>>,
}

#[derive(Serialize, Debug)]
pub struct RRSet<'a> {
    pub name: String,
    #[serde(rename = "type")]
    pub rr_type: &'static str,
    pub changetype: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records: Option<Vec<Record<'a>>>,
}

#[derive(Serialize, Debug)]
pub struct Record<'a> {
    pub content: String,
    pub disabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'a str>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub rr_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

const DEFAULT_ENDPOINT: &str = "http://localhost:8081";
const DEFAULT_SERVER: &str = "localhost";

impl PdnsProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        endpoint: Option<impl AsRef<str>>,
        server_name: Option<impl AsRef<str>>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("X-API-Key", api_key.as_ref())
            .with_header("Accept", "application/json")
            .with_timeout(timeout);

        let endpoint = endpoint
            .map(|e| e.as_ref().trim_end_matches('/').to_string())
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        let server_name = server_name
            .map(|s| s.as_ref().to_string())
            .unwrap_or_else(|| DEFAULT_SERVER.to_string());

        Self {
            client,
            endpoint,
            server_name,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().trim_end_matches('/').to_string(),
            ..self
        }
    }

    fn zone_url(&self, origin: &str) -> String {
        let zone = if origin.ends_with('.') {
            origin.to_string()
        } else {
            format!("{}.", origin)
        };
        format!(
            "{}/api/v1/servers/{}/zones/{}",
            self.endpoint, self.server_name, zone
        )
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        self.upsert(name, record, ttl, origin).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        self.upsert(name, record, ttl, origin).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let fqdn = name.into_fqdn().to_string();
        let origin = origin.into_name();
        let rrsets = RRSets {
            rrsets: vec![RRSet {
                name: fqdn,
                rr_type: record_type.as_str(),
                changetype: "DELETE",
                ttl: None,
                records: None,
            }],
        };

        self.client
            .patch(self.zone_url(origin.as_ref()))
            .with_body(rrsets)?
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn upsert(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let fqdn = name.into_fqdn().to_string();
        let origin = origin.into_name();
        let record_type = record.as_type();
        let content =
            pdns_content(&record).map_err(|err| Error::Api(err.to_string()))?;

        let rrsets = RRSets {
            rrsets: vec![RRSet {
                name: fqdn,
                rr_type: record_type.as_str(),
                changetype: "REPLACE",
                ttl: Some(ttl),
                records: Some(vec![Record {
                    content,
                    disabled: false,
                    name: None,
                    rr_type: None,
                    ttl: None,
                }]),
            }],
        };

        self.client
            .patch(self.zone_url(origin.as_ref()))
            .with_body(rrsets)?
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn pdns_content(record: &DnsRecord) -> Result<String, &'static str> {
    match record {
        DnsRecord::A(addr) => Ok(addr.to_string()),
        DnsRecord::AAAA(addr) => Ok(addr.to_string()),
        DnsRecord::CNAME(value) => Ok(ensure_trailing_dot(value)),
        DnsRecord::NS(value) => Ok(ensure_trailing_dot(value)),
        DnsRecord::MX(mx) => Ok(format!("{} {}", mx.priority, ensure_trailing_dot(&mx.exchange))),
        DnsRecord::TXT(text) => {
            let mut out = String::new();
            txt_chunks_to_text(&mut out, text, " ");
            Ok(out)
        }
        DnsRecord::SRV(srv) => Ok(format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            ensure_trailing_dot(&srv.target)
        )),
        DnsRecord::TLSA(tlsa) => Ok(tlsa.to_string()),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            Ok(format!("{} {} \"{}\"", flags, tag, value.replace('"', "\\\"")))
        }
    }
}

fn ensure_trailing_dot(value: &str) -> String {
    if value.ends_with('.') {
        value.to_string()
    } else {
        format!("{}.", value)
    }
}
