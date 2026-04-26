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

use crate::{DnsRecord, Error, IntoFqdn, utils::strip_origin_from_name};
use reqwest::Method;
use serde::Serialize;
use std::time::Duration;

#[derive(Clone)]
pub struct GandiProvider {
    token: String,
    pub(crate) endpoint: String,
    timeout: Duration,
}

#[derive(Serialize, Debug)]
pub struct UpdateDnsRecordParams {
    #[serde(rename = "rrset_values")]
    pub values: Vec<String>,
    #[serde(rename = "rrset_ttl")]
    pub ttl: u32,
}

#[derive(Debug)]
pub struct GandiRecordFormat {
    pub kind: String,
    pub value: String,
}

const GANDIV5_LIVEDNS_URL: &str = "https://api.gandi.net/v5/livedns";

impl From<&DnsRecord> for GandiRecordFormat {
    fn from(record: &DnsRecord) -> Self {
        match record {
            DnsRecord::A(content) => GandiRecordFormat {
                kind: "A".to_string(),
                value: content.to_string(),
            },
            DnsRecord::AAAA(content) => GandiRecordFormat {
                kind: "AAAA".to_string(),
                value: content.to_string(),
            },
            DnsRecord::CNAME(content) => GandiRecordFormat {
                kind: "CNAME".to_string(),
                value: content.clone(),
            },
            DnsRecord::NS(content) => GandiRecordFormat {
                kind: "NS".to_string(),
                value: content.clone(),
            },
            DnsRecord::MX(mx) => GandiRecordFormat {
                kind: "MX".to_string(),
                value: mx.to_string(),
            },
            DnsRecord::TXT(content) => GandiRecordFormat {
                kind: "TXT".to_string(),
                value: content.clone(),
            },
            DnsRecord::SRV(srv) => GandiRecordFormat {
                kind: "SRV".to_string(),
                value: srv.to_string(),
            },
            DnsRecord::TLSA(tlsa) => GandiRecordFormat {
                kind: "TLSA".to_string(),
                value: tlsa.to_string(),
            },
            DnsRecord::CAA(caa) => GandiRecordFormat {
                kind: "CAA".to_string(),
                value: caa.to_string(),
            },
        }
    }
}

impl GandiProvider {
    pub(crate) fn new(
        token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(Self {
            token: token.as_ref().to_string(),
            endpoint: GANDIV5_LIVEDNS_URL.to_string(),
            timeout: timeout.unwrap_or(Duration::from_secs(30)),
        })
    }

    async fn send_record_request(
        &self,
        zone: &str,
        name: &str,
        kind: &str,
        method: Method,
        body: Option<&str>,
    ) -> crate::Result<()> {
        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| Error::Client(format!("Failed to create HTTP client: {}", e)))?;

        let url = format!("{}/domains/{}/records/{}/{}", self.endpoint, zone, name, kind);

        let mut request = client
            .request(method, url)
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {0}", self.token))
            .header("Content-Type", "application/json");

        if let Some(body) = body {
            request = request.body(body.to_string());
        }

        let response = request
            .send()
            .await
            .map_err(|e| Error::Api(format!("Failed to send request: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Api(format!(
                "Failed to update record: HTTP {} - {}",
                status, error_text
            )));
        }

        Ok(())
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name.into_name(), &domain, None);

        let gandi_record: GandiRecordFormat = (&record).into();
        let (kind, values) = (gandi_record.kind, vec![gandi_record.value]);

        let params = UpdateDnsRecordParams { values, ttl };
        let body = serde_json::to_string(&params)
            .map_err(|e| Error::Serialize(format!("Failed to serialize record: {}", e)))?;

        self.send_record_request(&domain, &subdomain, &kind, Method::POST, Some(&body)).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name.into_name(), &domain, None);

        let gandi_record: GandiRecordFormat = (&record).into();
        let (kind, values) = (gandi_record.kind, vec![gandi_record.value]);

        let params = UpdateDnsRecordParams { values, ttl };
        let body = serde_json::to_string(&params)
            .map_err(|e| Error::Serialize(format!("Failed to serialize record: {}", e)))?;

        self.send_record_request(&domain, &subdomain, &kind, Method::PUT, Some(&body)).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: crate::DnsRecordType,
    ) -> crate::Result<()> {
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name.into_name(), &domain, None);
        self.send_record_request(&domain, &subdomain, record_type.as_str(), Method::DELETE, None).await
    }
}
