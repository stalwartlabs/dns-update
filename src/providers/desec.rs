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

use crate::{http::HttpClientBuilder, DnsRecord, Error, IntoFqdn};

#[derive(Clone)]
pub struct DesecProvider {
    client: HttpClientBuilder,
}

#[derive(Deserialize, Debug)]
pub struct IdMap {
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Debug)]
pub struct Query {
    name: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct CreateDnsRecordParams<'a> {
    pub subname: &'a str,
    pub r#type: &'a str,
    pub ttl: Option<u32>,
    #[serde(flatten)]
    pub records: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct UpdateDnsRecordParams<'a> {
    pub subname: &'a str,
    pub r#type: &'a str,
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

const DEFAULT_API_ENDPOINT: &str = "https://desec.io/api/v1/";

impl DesecProvider {
    pub(crate) fn new(auth_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Token {}", auth_token.as_ref()))
            .with_timeout(timeout);
        Self { client }
    }

    async fn check_ownership(&self, origin: impl IntoFqdn<'_>) -> crate::Result<String> {
        let origin = origin.into_name();
        self.client
            .get(format!(
                "{endpoint}/domains/?owns_qname={qname}",
                endpoint = DEFAULT_API_ENDPOINT,
                qname = Query::name(origin.as_ref()).serialize()
            ))
            .send::<ApiResult<Vec<IdMap>>>()
            .await
            .and_then(|r| r.unwrap_response("list zones"))
            .and_then(|result| {
                result
                    .into_iter()
                    .find(|zone| zone.name == origin.as_ref())
                    .map(|zone| zone.id)
                    .ok_or_else(|| Error::Api(format!("Zone {} not found", origin.as_ref())))
            })
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
                "{endpoint}/domains/{name}/rrsets/{subname}/{rtype}",
                endpoint = DEFAULT_API_ENDPOINT,
                name = origin.into_name().as_ref(),
                subname = &name,
                rtype = rr_type,
            ))
            .with_body(CreateDnsRecordParams {
                subname: &name,
                r#type: &rr_type,
                ttl: Some(ttl),
                records: vec![rr_content.into()],
            })?
            .send::<ApiResult<Value>>()
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
            .patch(format!(
                "{endpoint}/domains/{name}/rrsets/{subname}/{rtype}",
                endpoint = DEFAULT_API_ENDPOINT,
                name = origin.into_name().as_ref(),
                subname = &name,
                rtype = &rr_type,
            ))
            .with_body(UpdateDnsRecordParams {
                subname: &name,
                r#type: &rr_type,
                ttl: Some(ttl),
                records: vec![rr_content.into()],
            })?
            .send::<ApiResult<Value>>()
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
                "{endpoint}/domains/{name}/rrsets/{subname}/{rtype}",
                endpoint = DEFAULT_API_ENDPOINT,
                name = origin.into_name().as_ref(),
                subname = name.as_ref(),
                rtype = &rr_type,
            ))
            .send::<ApiResult<Value>>()
            .await
            .map(|_| ())
    }
}

impl<T> ApiResult<T> {
    fn unwrap_response(self, action_name: &str) -> crate::Result<T> {
        if self.success {
            Ok(self.result)
        } else {
            Err(Error::Api(format!(
                "Failed to {action_name}: {:?}",
                self.errors
            )))
        }
    }
}

impl Query {
    pub fn name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub fn serialize(&self) -> String {
        serde_urlencoded::to_string(self).unwrap()
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
