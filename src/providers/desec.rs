/*
 * Copyright Stalwart Labs Ltd. See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{http::HttpClientBuilder, DnsRecord, IntoFqdn};

#[derive(Clone)]
pub struct DesecProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct CreateDnsRecordParams<'a> {
    pub subname: &'a str,
    #[serde(rename = "type")]
    pub rr_type: &'a str,
    pub ttl: Option<u32>,
    #[serde(flatten)]
    pub records: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct UpdateDnsRecordParams<'a> {
    pub subname: &'a str,
    #[serde(rename = "type")]
    pub rr_type: &'a str,
    pub ttl: Option<u32>,
    #[serde(flatten)]
    pub records: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct ApiResult<T> {
    errors: Vec<ApiError>,
    success: bool,
    result: T,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ApiError {
    pub code: u16,
    pub message: String,
}

const DEFAULT_API_ENDPOINT: &str = "https://desec.io/api/v1";

impl DesecProvider {
    pub(crate) fn new(auth_token: impl AsRef<str>, endpoint: Option<impl AsRef<str>>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Token {}", auth_token.as_ref()))
            .with_timeout(timeout);

        let endpoint = endpoint
            .map(|e| e.as_ref().to_string())
            .unwrap_or_else(|| DEFAULT_API_ENDPOINT.to_string());

        Self { client, endpoint }
    }
    
    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let rr_type = &record.to_string();
        let rr_content = convert_record(record)?;
        self.client
            .post(format!(
                "{endpoint}/domains/{name}/rrsets/{subname}/{rr_type}/",
                endpoint = self.endpoint,
                name = origin.into_name().as_ref(),
                subname = &name,
                rr_type = rr_type,
            ))
            .with_body(CreateDnsRecordParams {
                subname: &name,
                rr_type: &rr_type,
                ttl: Some(ttl),
                records: vec![rr_content.into()],
            })?
            .send_with_retry::<ApiResult<Value>>(3)
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
        let rr_type = &record.to_string();
        let rr_content = convert_record(record)?;
        self.client
            .put(format!(
                "{endpoint}/domains/{name}/rrsets/{subname}/{rr_type}/",
                endpoint = self.endpoint,
                name = origin.into_name().as_ref(),
                subname = &name,
                rr_type = &rr_type,
            ))
            .with_body(UpdateDnsRecordParams {
                subname: &name,
                rr_type: &rr_type,
                ttl: Some(ttl),
                records: vec![rr_content.into()],
            })?
            .send_with_retry::<ApiResult<Value>>(3)
            .await
            .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record: DnsRecord,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let rr_type = &record.to_string();
        self.client
            .delete(format!(
                "{endpoint}/domains/{name}/rrsets/{subname}/{rtype}/",
                endpoint = self.endpoint,
                name = origin.into_name().as_ref(),
                subname = name.as_ref(),
                rtype = &rr_type,
            ))
            .send_with_retry::<ApiResult<Value>>(3)
            .await
            .map(|_| ())
    }
}

fn convert_record(record: DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A { content } => content.to_string(),
        DnsRecord::AAAA { content } => content.to_string(),
        DnsRecord::CNAME { content } => content,
        DnsRecord::NS { content } => content,
        DnsRecord::MX { content, priority } =>
            format!("{priority} {name}",
               priority = priority,
               name = content),
        DnsRecord::TXT { content } => content,
        DnsRecord::SRV { content, priority, weight, port } =>
            format!("{priority} {weight} {port} {name}",
                priority = priority,
                weight = weight,
                port = port,
                name = content)
        ,
    })
}
