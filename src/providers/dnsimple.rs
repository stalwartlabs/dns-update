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

const DEFAULT_ENDPOINT: &str = "https://api.dnsimple.com/v2";

#[derive(Clone)]
pub struct DNSimpleProvider {
    client: HttpClientBuilder,
    account_id: String,
    endpoint: String,
}

#[derive(Deserialize, Debug)]
pub struct ApiResponse<T> {
    pub data: T,
}

#[derive(Deserialize, Debug)]
pub struct RecordEntry {
    pub id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    pub ttl: u32,
    pub priority: Option<u16>,
}

#[derive(Serialize, Debug)]
pub struct CreateRecordParams {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    pub ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
}

#[derive(Serialize, Debug)]
struct ListRecordsQuery<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    type_filter: &'a str,
}

#[derive(Serialize, Debug)]
pub struct UpdateRecordParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
}

impl DNSimpleProvider {
    pub(crate) fn new(
        auth_token: impl AsRef<str>,
        account_id: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", auth_token.as_ref()))
            .with_timeout(timeout);
        Self {
            client,
            account_id: account_id.as_ref().to_string(),
            endpoint: DEFAULT_ENDPOINT.to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    fn base_url(&self) -> String {
        format!("{}/{}/zones", self.endpoint, self.account_id)
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let zone = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &zone, Some(""));
        let params = CreateRecordParams::from_record(&record, &subdomain, ttl);

        self.client
            .post(format!("{}/{}/records", self.base_url(), zone))
            .with_body(params)?
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
        let zone = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &zone, Some(""));
        let record_type = record_type_str(&record);
        let record_id = self
            .obtain_record_id(&subdomain, &zone, record_type)
            .await?;
        let (content, priority) = record_content_and_priority(&record);

        self.client
            .patch(format!(
                "{}/{}/records/{}",
                self.base_url(),
                zone,
                record_id
            ))
            .with_body(UpdateRecordParams {
                content: Some(content),
                ttl: Some(ttl),
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
        let zone = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &zone, Some(""));
        let type_str = record_type_to_str(record_type);
        let record_id = self.obtain_record_id(&subdomain, &zone, type_str).await?;

        self.client
            .delete(format!(
                "{}/{}/records/{}",
                self.base_url(),
                zone,
                record_id
            ))
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn obtain_record_id(
        &self,
        subdomain: &str,
        zone: &str,
        record_type: &str,
    ) -> crate::Result<i64> {
        let query = ListRecordsQuery {
            name: subdomain,
            type_filter: record_type,
        };
        let url = format!(
            "{}/{}/records?{}",
            self.base_url(),
            zone,
            serde_urlencoded::to_string(query).unwrap_or_default()
        );
        self.client
            .get(url)
            .send_with_retry::<ApiResponse<Vec<RecordEntry>>>(3)
            .await
            .and_then(|response| {
                response
                    .data
                    .into_iter()
                    .find(|r| r.name == subdomain && r.record_type == record_type)
                    .map(|r| r.id)
                    .ok_or_else(|| {
                        Error::Api(format!(
                            "DNS record {} ({}) not found",
                            subdomain, record_type
                        ))
                    })
            })
    }
}

fn record_type_str(record: &DnsRecord) -> &'static str {
    match record {
        DnsRecord::A(..) => "A",
        DnsRecord::AAAA(..) => "AAAA",
        DnsRecord::CNAME(..) => "CNAME",
        DnsRecord::NS(..) => "NS",
        DnsRecord::MX(..) => "MX",
        DnsRecord::TXT(..) => "TXT",
        DnsRecord::SRV(..) => "SRV",
        DnsRecord::TLSA(..) => "TLSA",
        DnsRecord::CAA(..) => "CAA",
    }
}

fn record_type_to_str(t: DnsRecordType) -> &'static str {
    match t {
        DnsRecordType::A => "A",
        DnsRecordType::AAAA => "AAAA",
        DnsRecordType::CNAME => "CNAME",
        DnsRecordType::NS => "NS",
        DnsRecordType::MX => "MX",
        DnsRecordType::TXT => "TXT",
        DnsRecordType::SRV => "SRV",
        DnsRecordType::TLSA => "TLSA",
        DnsRecordType::CAA => "CAA",
    }
}

fn record_content_and_priority(record: &DnsRecord) -> (String, Option<u16>) {
    match record {
        DnsRecord::A(content) => (content.to_string(), None),
        DnsRecord::AAAA(content) => (content.to_string(), None),
        DnsRecord::CNAME(content) => (content.clone(), None),
        DnsRecord::NS(content) => (content.clone(), None),
        DnsRecord::MX(mx) => (mx.exchange.clone(), Some(mx.priority)),
        DnsRecord::TXT(content) => (content.clone(), None),
        DnsRecord::SRV(srv) => (
            format!("{} {} {}", srv.weight, srv.port, srv.target),
            Some(srv.priority),
        ),
        DnsRecord::TLSA(value) => (value.to_string(), None),
        DnsRecord::CAA(caa) => (caa.to_string(), None),
    }
}

impl CreateRecordParams {
    fn from_record(record: &DnsRecord, name: &str, ttl: u32) -> Self {
        let (content, priority) = record_content_and_priority(record);
        CreateRecordParams {
            name: name.to_string(),
            record_type: record_type_str(record).to_string(),
            content,
            ttl,
            priority,
        }
    }
}
