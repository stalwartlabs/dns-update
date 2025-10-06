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

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{
    http::HttpClientBuilder, strip_origin_from_name, DnsRecord, DnsRecordTrait, DnsRecordType,
    IntoFqdn,
};

pub struct DesecDnsRecordRepresentation {
    pub record_type: String,
    pub content: String,
}

#[derive(Clone)]
pub struct DesecProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

/// The parameters for creation and modification requests of the desec API.
#[derive(Serialize, Clone, Debug)]
pub struct DnsRecordParams<'a> {
    pub subname: &'a str,
    #[serde(rename = "type")]
    pub rr_type: &'a str,
    pub ttl: Option<u32>,
    pub records: Vec<String>,
}

/// The response for creation and modification requests of the desec API.
#[derive(Deserialize, Debug)]
pub struct DesecApiResponse {
    pub created: String,
    pub domain: String,
    pub subname: String,
    pub name: String,
    pub records: Vec<String>,
    pub ttl: u32,
    #[serde(rename = "type")]
    pub record_type: String,
    pub touched: String,
}

#[derive(Deserialize)]
struct DesecEmptyResponse {}

/// The default endpoint for the desec API.
const DEFAULT_API_ENDPOINT: &str = "https://desec.io/api/v1";

impl DesecProvider {
    pub(crate) fn new(auth_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Token {}", auth_token.as_ref()))
            .with_timeout(timeout);

        Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
        }
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
        let subdomain = strip_origin_from_name(&name, &domain);

        let desec_record = DesecDnsRecordRepresentation::from(record);
        self.client
            .post(format!(
                "{endpoint}/domains/{domain}/rrsets/",
                endpoint = self.endpoint,
                domain = domain
            ))
            .with_body(DnsRecordParams {
                subname: &subdomain,
                rr_type: &desec_record.record_type,
                ttl: Some(ttl),
                records: vec![desec_record.content],
            })?
            .send_with_retry::<DesecApiResponse>(3)
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
        let subdomain = strip_origin_from_name(&name, &domain);

        let desec_record = DesecDnsRecordRepresentation::from(record);
        self.client
            .put(format!(
                "{endpoint}/domains/{domain}/rrsets/{subdomain}/{rr_type}/",
                endpoint = self.endpoint,
                domain = &domain,
                subdomain = &subdomain,
                rr_type = &desec_record.record_type,
            ))
            .with_body(DnsRecordParams {
                subname: &subdomain,
                rr_type: desec_record.record_type.as_str(),
                ttl: Some(ttl),
                records: vec![desec_record.content],
            })?
            .send_with_retry::<DesecApiResponse>(3)
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
        let subdomain = strip_origin_from_name(&name, &domain);

        let rr_type = &record_type.to_string();
        self.client
            .delete(format!(
                "{endpoint}/domains/{domain}/rrsets/{subdomain}/{rtype}/",
                endpoint = self.endpoint,
                domain = &domain,
                subdomain = &subdomain,
                rtype = &rr_type.to_string(),
            ))
            .send_with_retry::<DesecEmptyResponse>(3)
            .await
            .map(|_| ())
    }
}

/// Converts a DNS record into a representation that can be sent to the desec API.
impl From<DnsRecord> for DesecDnsRecordRepresentation {
    fn from(record: DnsRecord) -> Self {
        let (mut content, rtype) = record.fmt_ovh_desec();
        if let DnsRecord::TXT { .. } = record {
            // desec requires additional JSON quoting around https://desec.readthedocs.io/en/latest/dns/rrsets.html#caveats
            // the "proper" way to do this is serde_json, but there's no need to overcomplicate things when Stalwart only
            // uses dns-update internally for letsencrypt certificates, so the following suffices:
            content = serde_json::Value::String(content).to_string();
        }
        let record_type = rtype.to_string();
        Self {
            content,
            record_type,
        }
    }
}
