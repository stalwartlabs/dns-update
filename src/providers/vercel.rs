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
use std::{borrow::Cow, time::Duration};

const DEFAULT_API_ENDPOINT: &str = "https://api.vercel.com";

#[derive(Clone)]
pub struct VercelProvider {
    client: HttpClientBuilder,
    endpoint: Cow<'static, str>,
    team_id: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ListRecordsResponse {
    records: Vec<VercelRecord>,
}

#[derive(Deserialize, Debug)]
struct VercelRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
}

#[derive(Serialize, Debug)]
struct CreateRecord<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'static str,
    value: String,
    ttl: u32,
    #[serde(rename = "mxPriority", skip_serializing_if = "Option::is_none")]
    mx_priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    srv: Option<SrvData<'a>>,
}

#[derive(Serialize, Debug)]
struct UpdateRecord<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'static str,
    value: String,
    ttl: u32,
    #[serde(rename = "mxPriority", skip_serializing_if = "Option::is_none")]
    mx_priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    srv: Option<SrvData<'a>>,
}

#[derive(Serialize, Debug)]
struct SrvData<'a> {
    priority: u16,
    weight: u16,
    port: u16,
    target: &'a str,
}

impl VercelProvider {
    pub(crate) fn new(
        auth_token: impl AsRef<str>,
        team_id: Option<impl AsRef<str>>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", auth_token.as_ref()))
            .with_timeout(timeout);
        Self {
            client,
            endpoint: Cow::Borrowed(DEFAULT_API_ENDPOINT),
            team_id: team_id.map(|t| t.as_ref().to_string()),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl Into<Cow<'static, str>>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..self
        }
    }

    fn append_team_query(&self, mut url: String) -> String {
        if let Some(team_id) = &self.team_id {
            if url.contains('?') {
                url.push('&');
            } else {
                url.push('?');
            }
            url.push_str("teamId=");
            url.push_str(team_id);
        }
        url
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let domain = origin.into_name();
        let name = name.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let body = build_create(&subdomain, &record, ttl)?;

        let url = self.append_team_query(format!(
            "{}/v2/domains/{}/records",
            self.endpoint, domain
        ));
        self.client
            .post(url)
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
        let name = name.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let record_id = self
            .obtain_record_id(&domain, &subdomain, record.as_type())
            .await?;
        let body = build_update(&subdomain, &record, ttl)?;

        let url = self.append_team_query(format!(
            "{}/v1/domains/records/{}",
            self.endpoint, record_id
        ));
        self.client
            .patch(url)
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
        let name = name.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let record_id = self
            .obtain_record_id(&domain, &subdomain, record_type)
            .await?;

        let url = self.append_team_query(format!(
            "{}/v2/domains/{}/records/{}",
            self.endpoint, domain, record_id
        ));
        self.client.delete(url).send_raw().await.map(|_| ())
    }

    async fn obtain_record_id(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<String> {
        let wanted_type = record_type.as_str();
        let url = self.append_team_query(format!(
            "{}/v4/domains/{}/records",
            self.endpoint, domain
        ));
        self.client
            .get(url)
            .send_with_retry::<ListRecordsResponse>(3)
            .await
            .and_then(|response| {
                response
                    .records
                    .into_iter()
                    .find(|r| r.name == subdomain && r.record_type == wanted_type)
                    .map(|r| r.id)
                    .ok_or_else(|| {
                        Error::Api(format!(
                            "DNS Record {subdomain} of type {wanted_type} not found"
                        ))
                    })
            })
    }
}

fn record_value(record: &DnsRecord) -> crate::Result<String> {
    match record {
        DnsRecord::A(addr) => Ok(addr.to_string()),
        DnsRecord::AAAA(addr) => Ok(addr.to_string()),
        DnsRecord::CNAME(content) => Ok(content.clone()),
        DnsRecord::NS(content) => Ok(content.clone()),
        DnsRecord::MX(mx) => Ok(mx.exchange.clone()),
        DnsRecord::TXT(content) => Ok(content.clone()),
        DnsRecord::SRV(srv) => Ok(srv.target.clone()),
        DnsRecord::TLSA(tlsa) => Ok(tlsa.to_string()),
        DnsRecord::CAA(caa) => Ok(caa.to_string()),
    }
}

fn build_create<'a>(
    subdomain: &'a str,
    record: &'a DnsRecord,
    ttl: u32,
) -> crate::Result<CreateRecord<'a>> {
    Ok(CreateRecord {
        name: subdomain,
        record_type: record.as_type().as_str(),
        value: record_value(record)?,
        ttl,
        mx_priority: match record {
            DnsRecord::MX(mx) => Some(mx.priority),
            _ => None,
        },
        srv: match record {
            DnsRecord::SRV(srv) => Some(SrvData {
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
                target: &srv.target,
            }),
            _ => None,
        },
    })
}

fn build_update<'a>(
    subdomain: &'a str,
    record: &'a DnsRecord,
    ttl: u32,
) -> crate::Result<UpdateRecord<'a>> {
    Ok(UpdateRecord {
        name: subdomain,
        record_type: record.as_type().as_str(),
        value: record_value(record)?,
        ttl,
        mx_priority: match record {
            DnsRecord::MX(mx) => Some(mx.priority),
            _ => None,
        },
        srv: match record {
            DnsRecord::SRV(srv) => Some(SrvData {
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
                target: &srv.target,
            }),
            _ => None,
        },
    })
}
