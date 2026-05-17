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

const DEFAULT_ENDPOINT: &str = "https://api.infomaniak.com";

#[derive(Clone)]
pub struct InfomaniakProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Deserialize, Debug)]
struct ApiResponse<T> {
    #[serde(default)]
    result: String,
    #[serde(default)]
    data: Option<T>,
    #[serde(default)]
    error: Option<ApiErrorBody>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ApiErrorBody {
    #[serde(default)]
    code: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize, Debug)]
struct Domain {
    id: u64,
    #[serde(default, rename = "customer_name")]
    customer_name: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ExistingRecord {
    id: String,
    #[serde(default)]
    source: String,
    #[serde(default, rename = "source_idn")]
    source_idn: Option<String>,
    #[serde(default, rename = "type")]
    record_type: String,
    #[serde(default)]
    target: String,
}

#[derive(Serialize, Debug)]
struct RecordPayload<'a> {
    source: &'a str,
    target: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
}

impl InfomaniakProvider {
    pub(crate) fn new(access_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", access_token.as_ref()))
            .with_header("Accept", "application/json")
            .with_timeout(timeout);
        Self {
            client,
            endpoint: DEFAULT_ENDPOINT.to_string(),
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
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let ik_domain = self.find_domain(&domain).await?;
        let source = source_from_name(&name, &ik_domain.customer_name);
        let (record_type, target, priority) = encode_record(&record)?;

        let payload = RecordPayload {
            source: &source,
            target: &target,
            record_type,
            ttl,
            priority,
        };

        let url = format!(
            "{}/1/domain/{}/dns/record",
            self.endpoint, ik_domain.id
        );
        self.send_expect_success::<serde_json::Value>(
            self.client.post(url).with_body(payload)?,
        )
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
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let ik_domain = self.find_domain(&domain).await?;
        let source = source_from_name(&name, &ik_domain.customer_name);
        let record_type = record.as_type();
        let record_id = self
            .find_record_id(ik_domain.id, &source, record_type.as_str())
            .await?;
        let (record_type_str, target, priority) = encode_record(&record)?;

        let payload = RecordPayload {
            source: &source,
            target: &target,
            record_type: record_type_str,
            ttl,
            priority,
        };

        let url = format!(
            "{}/1/domain/{}/dns/record/{}",
            self.endpoint, ik_domain.id, record_id
        );
        self.send_expect_success::<serde_json::Value>(
            self.client.put(url).with_body(payload)?,
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let ik_domain = self.find_domain(&domain).await?;
        let source = source_from_name(&name, &ik_domain.customer_name);
        let record_id = self
            .find_record_id(ik_domain.id, &source, record_type.as_str())
            .await?;

        let url = format!(
            "{}/1/domain/{}/dns/record/{}",
            self.endpoint, ik_domain.id, record_id
        );
        self.send_expect_success::<serde_json::Value>(self.client.delete(url))
            .await
            .map(|_| ())
    }

    async fn find_domain(&self, name: &str) -> crate::Result<Domain> {
        let mut candidate = name.trim_end_matches('.');
        loop {
            let url = format!(
                "{}/1/product?service_name=domain&customer_name={}",
                self.endpoint, candidate
            );
            let domains = self
                .send_expect_success::<Vec<Domain>>(self.client.get(url))
                .await?;
            if let Some(domain) = domains
                .into_iter()
                .find(|d| d.customer_name == candidate)
            {
                return Ok(domain);
            }
            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => {
                    return Err(Error::Api(format!(
                        "No Infomaniak domain found for {}",
                        name
                    )));
                }
            }
        }
    }

    async fn find_record_id(
        &self,
        domain_id: u64,
        source: &str,
        record_type: &str,
    ) -> crate::Result<String> {
        let url = format!("{}/1/domain/{}/dns/record", self.endpoint, domain_id);
        let records = self
            .send_expect_success::<Vec<ExistingRecord>>(self.client.get(url))
            .await?;

        records
            .into_iter()
            .find(|r| {
                (r.source == source
                    || r.source_idn.as_deref() == Some(source))
                    && r.record_type.eq_ignore_ascii_case(record_type)
            })
            .map(|r| r.id)
            .ok_or_else(|| {
                Error::Api(format!(
                    "DNS Record {} of type {} not found in Infomaniak domain",
                    source, record_type
                ))
            })
    }

    async fn send_expect_success<T>(&self, request: crate::http::HttpClient) -> crate::Result<T>
    where
        T: serde::de::DeserializeOwned + Default,
    {
        let response: ApiResponse<T> = request.send().await?;
        if response.result != "success" {
            return Err(Error::Api(format!(
                "Infomaniak API error: {:?}",
                response.error
            )));
        }
        Ok(response.data.unwrap_or_default())
    }
}

fn source_from_name(name: &str, domain: &str) -> String {
    strip_origin_from_name(name, domain, Some(""))
}

fn encode_record(record: &DnsRecord) -> crate::Result<(&'static str, String, Option<u16>)> {
    Ok(match record {
        DnsRecord::A(addr) => ("A", addr.to_string(), None),
        DnsRecord::AAAA(addr) => ("AAAA", addr.to_string(), None),
        DnsRecord::CNAME(value) => ("CNAME", value.clone(), None),
        DnsRecord::NS(value) => ("NS", value.clone(), None),
        DnsRecord::MX(mx) => ("MX", mx.exchange.clone(), Some(mx.priority)),
        DnsRecord::TXT(value) => (
            "TXT",
            format!("\"{}\"", value.replace('"', "\\\"")),
            None,
        ),
        DnsRecord::SRV(srv) => (
            "SRV",
            format!(
                "{} {} {} {}",
                srv.priority, srv.weight, srv.port, srv.target
            ),
            None,
        ),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            (
                "CAA",
                format!("{} {} \"{}\"", flags, tag, value.replace('"', "\\\"")),
                None,
            )
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Infomaniak".to_string(),
            ));
        }
    })
}
