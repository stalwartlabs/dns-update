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

use crate::{DnsRecord, Error, IntoFqdn, http::HttpClientBuilder, utils::strip_origin_from_name};
use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

#[derive(Clone)]
pub struct PorkBunProvider {
    client: HttpClientBuilder,
    api_key: String,
    secret_api_key: String,
    endpoint: String,
}

/// The parameters for authenticating requests to the Porkbun API.
#[derive(Serialize, Debug)]
pub struct AuthParams<'a> {
    pub secretapikey: &'a str,
    pub apikey: &'a str,
}

/// The parameters for create and update requests to the Porkbun API.
// Note: there are some fields in this struct that are only needed when
// creating a new record, not when modifying an existing one, we use the same
// struct for both operations because it simplifies the code and the extra
// fields are simply ignored by the API during an update operation.
#[derive(Serialize, Debug)]
pub struct DnsRecordParams<'a> {
    #[serde(flatten)]
    pub auth: AuthParams<'a>,
    pub name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<&'a str>,
    #[serde(flatten)]
    content: RecordData,
}

/// The response for create and update requests to the Porkbun API.
#[derive(Deserialize, Debug)]
pub struct ApiResponse {
    pub status: String,
    pub message: Option<String>,
}

// Note: some of these types are not supported at the `dns-update` library
// level, but we include them here for completeness.
#[derive(Serialize, Clone, Debug)]
#[serde(tag = "type")]
#[allow(clippy::upper_case_acronyms)]
pub enum RecordData {
    A { content: Ipv4Addr },
    MX { content: String, prio: u16 },
    CNAME { content: String },
    ALIAS { content: String },
    TXT { content: String },
    NS { content: String },
    AAAA { content: Ipv6Addr },
    SRV { content: String, prio: u16 },
    TLSA { content: String },
    CAA { content: String },
    HTTPS { content: String },
    SVCB { content: String },
    SSHFP { content: String },
}

/// The default endpoint for the Porkbun API.
const DEFAULT_API_ENDPOINT: &str = "https://api.porkbun.com/api/json/v3";

impl PorkBunProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        secret_api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default().with_timeout(timeout);

        Self {
            client,
            api_key: api_key.as_ref().to_string(),
            secret_api_key: secret_api_key.as_ref().to_string(),
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
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));

        self.client
            .post(format!(
                "{endpoint}/dns/create/{domain}",
                endpoint = self.endpoint,
                domain = domain
            ))
            .with_body(DnsRecordParams {
                auth: AuthParams {
                    secretapikey: &self.secret_api_key,
                    apikey: &self.api_key,
                },
                name: &subdomain,
                ttl: Some(ttl),
                notes: None,
                content: record.into(),
            })?
            .send_with_retry::<ApiResponse>(3)
            .await?
            .into_result()
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
        let content: RecordData = record.into();

        self.client
            .post(format!(
                "{endpoint}/dns/editByNameType/{domain}/{type}/{subdomain}",
                endpoint = self.endpoint,
                domain = domain,
                type = content.variant_name(),
                subdomain = subdomain,
            ))
            .with_body(DnsRecordParams {
                auth: AuthParams {
                    secretapikey: &self.secret_api_key,
                    apikey: &self.api_key,
                },
                name: &subdomain,
                ttl: Some(ttl),
                notes: None,
                content,
            })?
            .send_with_retry::<ApiResponse>(3)
            .await?
            .into_result()
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: crate::DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));

        self.client
            .post(format!(
                "{endpoint}/dns/deleteByNameType/{domain}/{type}/{subdomain}",
                endpoint = self.endpoint,
                domain = domain,
                type = record_type,
                subdomain = subdomain,
            ))
            .with_body(AuthParams {
                secretapikey: &self.secret_api_key,
                apikey: &self.api_key,
            })?
            .send_with_retry::<ApiResponse>(3)
            .await?
            .into_result()
    }
}

impl ApiResponse {
    fn into_result(self) -> crate::Result<()> {
        if self.status == "SUCCESS" {
            Ok(())
        } else {
            Err(Error::Api(self.message.unwrap_or(self.status)))
        }
    }
}

impl RecordData {
    pub fn variant_name(&self) -> &'static str {
        match self {
            RecordData::A { .. } => "A",
            RecordData::MX { .. } => "MX",
            RecordData::CNAME { .. } => "CNAME",
            RecordData::ALIAS { .. } => "ALIAS",
            RecordData::TXT { .. } => "TXT",
            RecordData::NS { .. } => "NS",
            RecordData::AAAA { .. } => "AAAA",
            RecordData::SRV { .. } => "SRV",
            RecordData::TLSA { .. } => "TLSA",
            RecordData::CAA { .. } => "CAA",
            RecordData::HTTPS { .. } => "HTTPS",
            RecordData::SVCB { .. } => "SVCB",
            RecordData::SSHFP { .. } => "SSHFP",
        }
    }
}

impl From<DnsRecord> for RecordData {
    fn from(record: DnsRecord) -> Self {
        match record {
            DnsRecord::A(content) => RecordData::A { content },
            DnsRecord::AAAA(content) => RecordData::AAAA { content },
            DnsRecord::CNAME(content) => RecordData::CNAME { content },
            DnsRecord::NS(content) => RecordData::NS { content },
            DnsRecord::MX(mx) => RecordData::MX {
                content: mx.exchange,
                prio: mx.priority,
            },
            DnsRecord::TXT(content) => RecordData::TXT { content },
            DnsRecord::SRV(srv) => RecordData::SRV {
                content: format!("{} {} {}", srv.weight, srv.port, srv.target),
                prio: srv.priority,
            },
            DnsRecord::TLSA(tlsa) => RecordData::TLSA {
                content: tlsa.to_string(),
            },
            DnsRecord::CAA(caa) => RecordData::CAA {
                content: caa.to_string(),
            },
        }
    }
}
