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
pub struct PleskProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecordRequest<'a> {
    #[serde(rename = "siteId")]
    site_id: i64,
    #[serde(rename = "type")]
    record_type: &'a str,
    host: &'a str,
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    opt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct CreateRecordResponse {
    id: i64,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct PleskRecord {
    id: i64,
    #[serde(rename = "siteId")]
    site_id: Option<i64>,
    #[serde(rename = "type")]
    record_type: String,
    host: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    opt: String,
}

#[derive(Deserialize, Debug)]
struct PleskDomain {
    id: i64,
    name: String,
}

impl PleskProvider {
    pub(crate) fn new(
        base_url: impl AsRef<str>,
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("X-API-Key", api_key.as_ref())
            .with_timeout(timeout);
        Self {
            client,
            endpoint: base_url.as_ref().trim_end_matches('/').to_string(),
        }
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
        let name = name.into_name();
        let domain = origin.into_name();
        let host = strip_origin_from_name(&name, &domain, Some(""));
        let site_id = self.find_site_id(&domain).await?;
        let (record_type, value, opt) = encode_record(&record)?;

        let body = CreateRecordRequest {
            site_id,
            record_type,
            host: host.as_str(),
            value,
            opt,
            ttl: Some(ttl),
        };

        self.client
            .post(format!("{}/api/v2/dns/records", self.endpoint))
            .with_body(&body)?
            .send_with_retry::<CreateRecordResponse>(3)
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
        let name_owned = name.into_name().to_string();
        let domain_owned = origin.into_name().to_string();
        let record_type = record.as_type();

        let existing = self
            .find_record(&name_owned, &domain_owned, record_type)
            .await?;

        self.client
            .delete(format!(
                "{}/api/v2/dns/records/{}",
                self.endpoint, existing.id
            ))
            .send_raw()
            .await?;

        self.create(name_owned, record, ttl, domain_owned).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let existing = self.find_record(&name, &domain, record_type).await?;

        self.client
            .delete(format!(
                "{}/api/v2/dns/records/{}",
                self.endpoint, existing.id
            ))
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn find_site_id(&self, domain: &str) -> crate::Result<i64> {
        let query = serde_urlencoded::to_string([("name", domain)])
            .map_err(|err| Error::Serialize(err.to_string()))?;
        let domains = self
            .client
            .get(format!("{}/api/v2/domains?{}", self.endpoint, query))
            .send_with_retry::<Vec<PleskDomain>>(3)
            .await?;

        domains
            .into_iter()
            .find(|d| d.name.trim_end_matches('.') == domain.trim_end_matches('.'))
            .map(|d| d.id)
            .ok_or_else(|| Error::Api(format!("Plesk site not found for {domain}")))
    }

    async fn find_record(
        &self,
        name: &str,
        domain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<PleskRecord> {
        let site_id = self.find_site_id(domain).await?;
        let query = serde_urlencoded::to_string([("siteId", site_id.to_string())])
            .map_err(|err| Error::Serialize(err.to_string()))?;

        let records = self
            .client
            .get(format!("{}/api/v2/dns/records?{}", self.endpoint, query))
            .send_with_retry::<Vec<PleskRecord>>(3)
            .await?;

        let host_target = strip_origin_from_name(name, domain, Some(""));
        let type_str = record_type.as_str();

        records
            .into_iter()
            .find(|r| {
                r.record_type.eq_ignore_ascii_case(type_str)
                    && host_matches(&r.host, &host_target, domain)
            })
            .ok_or(Error::NotFound)
    }
}

fn host_matches(api_host: &str, expected_subdomain: &str, domain: &str) -> bool {
    let api = api_host.trim_end_matches('.');
    let expected_full = if expected_subdomain.is_empty() {
        domain.trim_end_matches('.').to_string()
    } else {
        format!(
            "{}.{}",
            expected_subdomain,
            domain.trim_end_matches('.')
        )
    };
    api.eq_ignore_ascii_case(&expected_full)
        || api.eq_ignore_ascii_case(expected_subdomain)
}

fn encode_record(record: &DnsRecord) -> crate::Result<(&'static str, String, Option<String>)> {
    Ok(match record {
        DnsRecord::A(addr) => ("A", addr.to_string(), None),
        DnsRecord::AAAA(addr) => ("AAAA", addr.to_string(), None),
        DnsRecord::CNAME(value) => ("CNAME", value.clone(), None),
        DnsRecord::NS(value) => ("NS", value.clone(), None),
        DnsRecord::MX(mx) => ("MX", mx.exchange.clone(), Some(mx.priority.to_string())),
        DnsRecord::TXT(value) => ("TXT", value.clone(), None),
        DnsRecord::SRV(srv) => (
            "SRV",
            srv.target.clone(),
            Some(format!("{} {} {}", srv.priority, srv.weight, srv.port)),
        ),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            (
                "CAA",
                value,
                Some(format!("{flags} {tag}")),
            )
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Plesk".to_string(),
            ));
        }
    })
}
