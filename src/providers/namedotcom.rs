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
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone)]
pub struct NameDotComProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecord<'a> {
    host: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    answer: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
}

#[derive(Deserialize, Debug, Clone)]
struct Record {
    id: i64,
    #[serde(default)]
    #[allow(dead_code)]
    host: Option<String>,
    #[serde(default)]
    fqdn: Option<String>,
    #[serde(rename = "type")]
    record_type: String,
}

#[derive(Deserialize, Debug)]
struct ListRecordsResponse {
    #[serde(default)]
    records: Vec<Record>,
    #[serde(default, rename = "nextPage")]
    next_page: u32,
}

const DEFAULT_API_ENDPOINT: &str = "https://api.name.com";

impl NameDotComProvider {
    pub(crate) fn new(
        username: impl AsRef<str>,
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let username = username.as_ref();
        let token = api_token.as_ref();
        if username.is_empty() || token.is_empty() {
            return Err(Error::Api(
                "Name.com username and API token must not be empty".to_string(),
            ));
        }

        let credentials = BASE64.encode(format!("{username}:{token}"));
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {credentials}"))
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
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let record_type = record.as_type();
        let priority = record.priority();
        let answer = render_answer(record)?;

        self.client
            .post(format!(
                "{}/v4/domains/{}/records",
                self.endpoint, domain
            ))
            .with_body(CreateRecord {
                host: &subdomain,
                record_type: record_type.as_str(),
                answer,
                ttl,
                priority,
            })?
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let record_type = record.as_type();
        let record_id = self
            .obtain_record_id(&domain, &name, record_type)
            .await?;
        let priority = record.priority();
        let answer = render_answer(record)?;

        self.client
            .put(format!(
                "{}/v4/domains/{}/records/{}",
                self.endpoint, domain, record_id
            ))
            .with_body(CreateRecord {
                host: &subdomain,
                record_type: record_type.as_str(),
                answer,
                ttl,
                priority,
            })?
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
        let name = name.into_name();
        let domain = origin.into_name();
        let record_id = self
            .obtain_record_id(&domain, &name, record_type)
            .await?;

        self.client
            .delete(format!(
                "{}/v4/domains/{}/records/{}",
                self.endpoint, domain, record_id
            ))
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn obtain_record_id(
        &self,
        domain: &str,
        fqdn: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<i64> {
        let target_fqdn = format!("{}.", fqdn.trim_end_matches('.'));
        let mut page: u32 = 1;
        loop {
            let response = self
                .client
                .get(format!(
                    "{}/v4/domains/{}/records?page={}",
                    self.endpoint, domain, page
                ))
                .send::<ListRecordsResponse>()
                .await?;

            for r in &response.records {
                if r.record_type == record_type.as_str()
                    && r.fqdn.as_deref().map(str::to_ascii_lowercase)
                        == Some(target_fqdn.to_ascii_lowercase())
                {
                    return Ok(r.id);
                }
            }

            if response.next_page == 0 {
                return Err(Error::Api(format!(
                    "DNS Record {} of type {} not found",
                    fqdn,
                    record_type.as_str()
                )));
            }
            page = response.next_page;
        }
    }
}

fn render_answer(record: DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content,
        DnsRecord::NS(content) => content,
        DnsRecord::MX(mx) => mx.exchange,
        DnsRecord::TXT(content) => content,
        DnsRecord::SRV(srv) => format!("{} {} {}", srv.weight, srv.port, srv.target),
        DnsRecord::CAA(caa) => caa.to_string(),
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Name.com".to_string(),
            ));
        }
    })
}
