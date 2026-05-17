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

use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, http::HttpClientBuilder};
use serde::Deserialize;
use std::time::Duration;

#[derive(Clone)]
pub struct TechnitiumProvider {
    client: HttpClientBuilder,
    endpoint: String,
    token: String,
}

#[derive(Deserialize, Debug)]
struct ApiResponse {
    status: String,
    #[serde(rename = "errorMessage", default)]
    error_message: Option<String>,
}

const DEFAULT_ENDPOINT: &str = "http://localhost:5380";

impl TechnitiumProvider {
    pub(crate) fn new(
        base_url: impl AsRef<str>,
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let token = api_token.as_ref();
        if token.is_empty() {
            return Err(Error::Api("Technitium API token is required".into()));
        }
        let raw = base_url.as_ref();
        let endpoint = if raw.is_empty() {
            DEFAULT_ENDPOINT.to_string()
        } else {
            raw.trim_end_matches('/').to_string()
        };

        let client = HttpClientBuilder::default()
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_header("Accept", "application/json")
            .with_timeout(timeout);

        Ok(Self {
            client,
            endpoint,
            token: token.to_string(),
        })
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
        let _ = origin;
        let body = self.encode_record_form(name.into_name().as_ref(), &record, Some(ttl), false)?;
        self.call("add", body).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let _ = origin;
        let domain = name.into_name().to_string();
        self.delete_record(&domain, record.as_type()).await.ok();
        let body = self.encode_record_form(&domain, &record, Some(ttl), false)?;
        self.call("add", body).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let _ = origin;
        let domain = name.into_name().to_string();
        self.delete_record(&domain, record_type).await
    }

    async fn delete_record(
        &self,
        domain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let mut pairs: Vec<(&str, String)> = Vec::new();
        pairs.push(("token", self.token.clone()));
        pairs.push(("domain", domain.to_string()));
        pairs.push(("type", record_type.as_str().to_string()));
        let body = serde_urlencoded::to_string(&pairs)
            .map_err(|err| Error::Serialize(err.to_string()))?;
        self.call("delete", body).await
    }

    fn encode_record_form(
        &self,
        domain: &str,
        record: &DnsRecord,
        ttl: Option<u32>,
        _update: bool,
    ) -> crate::Result<String> {
        let mut pairs: Vec<(&str, String)> = Vec::new();
        pairs.push(("token", self.token.clone()));
        pairs.push(("domain", domain.to_string()));
        let rtype = record.as_type();
        pairs.push(("type", rtype.as_str().to_string()));
        if let Some(ttl) = ttl {
            pairs.push(("ttl", ttl.to_string()));
        }
        match record {
            DnsRecord::A(addr) => pairs.push(("ipAddress", addr.to_string())),
            DnsRecord::AAAA(addr) => pairs.push(("ipAddress", addr.to_string())),
            DnsRecord::CNAME(value) => pairs.push(("cname", value.clone())),
            DnsRecord::NS(value) => pairs.push(("nameServer", value.clone())),
            DnsRecord::MX(mx) => {
                pairs.push(("preference", mx.priority.to_string()));
                pairs.push(("exchange", mx.exchange.clone()));
            }
            DnsRecord::TXT(text) => pairs.push(("text", text.clone())),
            DnsRecord::SRV(srv) => {
                pairs.push(("priority", srv.priority.to_string()));
                pairs.push(("weight", srv.weight.to_string()));
                pairs.push(("port", srv.port.to_string()));
                pairs.push(("target", srv.target.clone()));
            }
            DnsRecord::CAA(caa) => {
                let (flags, tag, value) = caa.clone().decompose();
                pairs.push(("flags", flags.to_string()));
                pairs.push(("tag", tag));
                pairs.push(("value", value));
            }
            DnsRecord::TLSA(_) => {
                return Err(Error::Api(
                    "TLSA records are not supported by Technitium".into(),
                ));
            }
        }
        serde_urlencoded::to_string(&pairs).map_err(|err| Error::Serialize(err.to_string()))
    }

    async fn call(&self, action: &str, body: String) -> crate::Result<()> {
        let url = format!("{}/api/zones/records/{}", self.endpoint, action);
        let response: ApiResponse = self
            .client
            .post(url)
            .with_raw_body(body)
            .send()
            .await?;
        if response.status != "ok" {
            return Err(Error::Api(format!(
                "Technitium API returned status {}: {}",
                response.status,
                response.error_message.unwrap_or_default()
            )));
        }
        Ok(())
    }
}
