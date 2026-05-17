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
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api.autodns.com/v1";
pub const DEFAULT_CONTEXT: u32 = 4;

#[derive(Clone)]
pub struct AutodnsProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug)]
pub struct ZoneStream {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub adds: Vec<ResourceRecord>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rems: Vec<ResourceRecord>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ResourceRecord {
    pub name: String,
    pub ttl: u32,
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pref: u32,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

#[derive(Deserialize, Debug)]
pub struct Zone {
    #[serde(rename = "origin", default)]
    pub origin: String,
    #[serde(rename = "resourceRecords", default)]
    pub resource_records: Vec<ResourceRecord>,
}

#[derive(Deserialize, Debug)]
pub struct DataZoneResponse {
    #[serde(default)]
    pub data: Vec<Zone>,
}

impl AutodnsProvider {
    pub(crate) fn new(
        username: impl AsRef<str>,
        password: impl AsRef<str>,
        context: Option<u32>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let user = username.as_ref();
        let pass = password.as_ref();
        if user.is_empty() {
            return Err(Error::Api("AutoDNS username is empty".to_string()));
        }
        if pass.is_empty() {
            return Err(Error::Api("AutoDNS password is empty".to_string()));
        }
        let encoded = STANDARD.encode(format!("{user}:{pass}"));
        let ctx = context.unwrap_or(DEFAULT_CONTEXT);
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {encoded}"))
            .with_header("X-Domainrobot-Context", ctx.to_string())
            .with_header("Accept", "application/json")
            .with_timeout(timeout);
        Ok(Self {
            client,
            endpoint: DEFAULT_ENDPOINT.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    fn stream_url(&self, domain: &str) -> String {
        format!("{}/zone/{}/_stream", self.endpoint, domain)
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let domain = origin.into_name();
        let rr = build_resource_record(&name.into_fqdn(), &record, ttl);
        let body = ZoneStream {
            adds: vec![rr],
            rems: vec![],
        };
        self.client
            .post(self.stream_url(&domain))
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
        let fqdn = name.into_fqdn();
        let record_type = record.as_type();
        let new_rr = build_resource_record(&fqdn, &record, ttl);

        let existing = self.find_existing(&domain, &fqdn, record_type).await?;
        let mut rems = Vec::new();
        if let Some(r) = existing {
            rems.push(r);
        }

        let body = ZoneStream {
            adds: vec![new_rr],
            rems,
        };
        self.client
            .post(self.stream_url(&domain))
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
        let fqdn = name.into_fqdn();
        let existing = self
            .find_existing(&domain, &fqdn, record_type)
            .await?
            .ok_or_else(|| {
                Error::Api(format!(
                    "AutoDNS record {} of type {} not found",
                    fqdn.as_ref(),
                    record_type.as_str()
                ))
            })?;
        let body = ZoneStream {
            adds: vec![],
            rems: vec![existing],
        };
        self.client
            .post(self.stream_url(&domain))
            .with_body(body)?
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn find_existing(
        &self,
        domain: &str,
        fqdn: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Option<ResourceRecord>> {
        let url = format!("{}/zone/{}/_search", self.endpoint, domain);
        let response = self
            .client
            .post(url)
            .with_raw_body("{}".to_string())
            .send_raw()
            .await
            .ok();
        let Some(body) = response else {
            return Ok(None);
        };
        if body.is_empty() {
            return Ok(None);
        }
        let parsed: DataZoneResponse = match serde_json::from_str(&body) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        let target_name = strip_origin_from_name(fqdn, domain, Some("@"));
        let type_str = record_type.as_str();
        for zone in parsed.data {
            for r in zone.resource_records {
                let candidate_name = strip_origin_from_name(&r.name, domain, Some("@"));
                if candidate_name == target_name && r.record_type == type_str {
                    return Ok(Some(r));
                }
            }
        }
        Ok(None)
    }
}

fn build_resource_record(name: &str, record: &DnsRecord, ttl: u32) -> ResourceRecord {
    let (value, pref) = match record {
        DnsRecord::A(ip) => (ip.to_string(), 0),
        DnsRecord::AAAA(ip) => (ip.to_string(), 0),
        DnsRecord::CNAME(value) => (value.clone(), 0),
        DnsRecord::NS(value) => (value.clone(), 0),
        DnsRecord::MX(mx) => (mx.exchange.clone(), u32::from(mx.priority)),
        DnsRecord::TXT(value) => (value.clone(), 0),
        DnsRecord::SRV(srv) => (
            format!("{} {} {}", srv.weight, srv.port, srv.target),
            u32::from(srv.priority),
        ),
        DnsRecord::TLSA(tlsa) => (tlsa.to_string(), 0),
        DnsRecord::CAA(caa) => (caa.to_string(), 0),
    };
    ResourceRecord {
        name: name.to_string(),
        ttl,
        record_type: record.as_type().as_str().to_string(),
        value,
        pref,
    }
}
