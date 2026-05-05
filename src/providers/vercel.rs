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
    http::HttpClientBuilder, utils::strip_origin_from_name, DnsRecord, DnsRecordType, Error,
    IntoFqdn,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api.vercel.com";

#[derive(Clone)]
pub struct VercelProvider {
    client: HttpClientBuilder,
    team_id: Option<String>,
    slug: Option<String>,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct VercelSrv {
    target: String,
    weight: u16,
    port: u16,
    priority: u16,
}

#[derive(Serialize, Debug)]
struct VercelRecordRequest<'a> {
    #[serde(rename = "type")]
    record_type: &'a str,
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'a str>,
    #[serde(rename = "mxPriority", skip_serializing_if = "Option::is_none")]
    mx_priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    srv: Option<VercelSrv>,
}

#[derive(Deserialize, Debug)]
struct VercelRecordListResponse {
    pagination: Option<VercelPagination>,
    records: Vec<VercelRecord>,
}

#[derive(Deserialize, Debug)]
struct VercelPagination {
    count: usize,
    next: Option<u64>,
}

#[derive(Deserialize, Debug)]
struct VercelRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
}

impl VercelProvider {
    pub(crate) fn new(
        token: impl AsRef<str>,
        team_id: Option<String>,
        slug: Option<String>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", token.as_ref()))
            .with_timeout(timeout);

        Self {
            client,
            team_id,
            slug,
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

    fn build_url(&self, path: &str, mut params: Vec<(&str, String)>) -> String {
        let mut url = format!("{}{}", self.endpoint, path);
        if let Some(team_id) = &self.team_id {
            params.push(("teamId", team_id.clone()));
        }
        if let Some(slug) = &self.slug {
            params.push(("slug", slug.clone()));
        }
        if !params.is_empty() {
            let query = params
                .into_iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&query);
        }
        url
    }

    /// Creates a new DNS record on Vercel
    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let origin = origin.into_name();
        let name = name.into_name();
        // Vercel expects an empty string for the apex domain instead of '@'.
        let subdomain = strip_origin_from_name(&name, &origin, Some(""));

        let mut req = record_to_vercel(&record);
        req.name = &subdomain;
        req.ttl = Some(ttl);
        req.comment = Some("Managed by Stalwart");

        self.client
            .post(self.build_url(&format!("/v2/domains/{}/records", origin), vec![]))
            .with_body(req)?
            .send_with_retry::<serde_json::Value>(3)
            .await?;

        Ok(())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let origin = origin.into_name();
        let name = name.into_name();
        // Vercel expects an empty string for the apex domain instead of '@'.
        let subdomain = strip_origin_from_name(&name, &origin, Some(""));
        let record_type = record.as_type();

        let record_id = self.find_record_id(&origin, &subdomain, record_type).await?;

        let mut req = record_to_vercel(&record);
        req.name = &subdomain;
        req.ttl = Some(ttl);
        req.comment = Some("Managed by Stalwart");

        self.client
            .patch(self.build_url(&format!("/v1/domains/records/{}", record_id), vec![]))
            .with_body(req)?
            .send_with_retry::<serde_json::Value>(3)
            .await?;

        Ok(())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let origin = origin.into_name();
        let name = name.into_name();
        // Vercel expects an empty string for the apex domain instead of '@'.
        let subdomain = strip_origin_from_name(&name, &origin, Some(""));

        let record_id = self.find_record_id(&origin, &subdomain, record_type).await?;

        self.client
            .delete(self.build_url(
                &format!("/v2/domains/{}/records/{}", origin, record_id),
                vec![],
            ))
            .send_with_retry::<serde_json::Value>(3)
            .await?;

        Ok(())
    }

    /// Finds the Vercel internal ID for a given DNS record.
    /// Since Vercel requires IDs for updates and deletions, we need to locate it first.
    /// Handles pagination natively by checking 'since' timestamp bounds.
    async fn find_record_id(
        &self,
        origin: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<String> {
        let record_type_str = record_type.as_str();
        let mut since: Option<String> = None;

        loop {
            let mut params = vec![];
            if let Some(s) = &since {
                params.push(("since", s.clone()));
            }

            let response: VercelRecordListResponse = self
                .client
                .get(self.build_url(&format!("/v5/domains/{}/records", origin), params))
                .send_with_retry(3)
                .await?;

            for record in &response.records {
                if record.name == subdomain && record.record_type == record_type_str {
                    return Ok(record.id.clone());
                }
            }

            if let Some(pagination) = response.pagination {
                if let Some(next) = pagination.next {
                    since = Some(next.to_string());
                    if pagination.count == 0 {
                        break;
                    }
                    continue;
                }
            }

            break;
        }

        Err(Error::NotFound)
    }
}

fn record_to_vercel(record: &DnsRecord) -> VercelRecordRequest<'static> {
    let mut req = VercelRecordRequest {
        record_type: record.as_type().as_str(),
        name: "",
        value: None,
        ttl: None,
        comment: None,
        mx_priority: None,
        srv: None,
    };

    match record {
        DnsRecord::A(ip) => req.value = Some(ip.to_string()),
        DnsRecord::AAAA(ip) => req.value = Some(ip.to_string()),
        DnsRecord::CNAME(target) => req.value = Some(target.to_string()),
        DnsRecord::NS(target) => req.value = Some(target.to_string()),
        DnsRecord::MX(mx) => {
            req.value = Some(mx.exchange.clone());
            req.mx_priority = Some(mx.priority);
        }
        DnsRecord::TXT(txt) => req.value = Some(txt.to_string()),
        DnsRecord::SRV(srv) => {
            req.srv = Some(VercelSrv {
                target: srv.target.clone(),
                weight: srv.weight,
                port: srv.port,
                priority: srv.priority,
            });
        }
        DnsRecord::TLSA(tlsa) => {
            req.value = Some(format!(
                "{} {} {} {}",
                u8::from(tlsa.cert_usage),
                u8::from(tlsa.selector),
                u8::from(tlsa.matching),
                tlsa.cert_data
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            ));
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            req.value = Some(format!("{} {} \"{}\"", flags, tag, value));
        }
    }

    req
}
