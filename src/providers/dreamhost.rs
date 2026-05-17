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

const DEFAULT_API_ENDPOINT: &str = "https://api.dreamhost.com";

#[derive(Clone)]
pub struct DreamhostProvider {
    client: HttpClientBuilder,
    endpoint: String,
    api_key: String,
}

#[derive(Deserialize, Debug)]
struct ApiResponse {
    result: String,
    #[serde(default)]
    data: serde_json::Value,
}

#[derive(Deserialize, Debug)]
struct ListResponse {
    result: String,
    #[serde(default)]
    data: Vec<DreamhostRecord>,
}

#[derive(Deserialize, Debug, Clone)]
struct DreamhostRecord {
    record: String,
    #[serde(rename = "type")]
    rr_type: String,
    value: String,
}

impl DreamhostProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default().with_timeout(timeout);
        Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            api_key: api_key.as_ref().to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    fn build_query(&self, params: &[(&str, &str)]) -> String {
        let mut all: Vec<(&str, &str)> = Vec::with_capacity(params.len() + 2);
        all.push(("key", self.api_key.as_str()));
        all.push(("format", "json"));
        all.extend_from_slice(params);
        serde_urlencoded::to_string(all).unwrap_or_default()
    }

    async fn add_record(&self, name: &str, rr_type: &str, value: &str) -> crate::Result<()> {
        let qs = self.build_query(&[
            ("cmd", "dns-add_record"),
            ("record", name),
            ("type", rr_type),
            ("value", value),
            ("comment", "Managed By dns-update"),
        ]);
        let body = self
            .client
            .get(format!("{}/?{qs}", self.endpoint))
            .send_raw()
            .await?;
        let parsed: ApiResponse = serde_json::from_str(&body).map_err(|err| {
            Error::Serialize(format!("Failed to parse Dreamhost response: {err}"))
        })?;
        if parsed.result == "success" {
            Ok(())
        } else {
            Err(Error::Api(format!(
                "Dreamhost add record failed: {}",
                parsed.data
            )))
        }
    }

    async fn remove_record(&self, name: &str, rr_type: &str, value: &str) -> crate::Result<()> {
        let qs = self.build_query(&[
            ("cmd", "dns-remove_record"),
            ("record", name),
            ("type", rr_type),
            ("value", value),
        ]);
        let body = self
            .client
            .get(format!("{}/?{qs}", self.endpoint))
            .send_raw()
            .await?;
        let parsed: ApiResponse = serde_json::from_str(&body).map_err(|err| {
            Error::Serialize(format!("Failed to parse Dreamhost response: {err}"))
        })?;
        if parsed.result == "success" {
            Ok(())
        } else {
            Err(Error::Api(format!(
                "Dreamhost remove record failed: {}",
                parsed.data
            )))
        }
    }

    async fn find_record_value(&self, name: &str, rr_type: &str) -> crate::Result<String> {
        let qs = self.build_query(&[("cmd", "dns-list_records")]);
        let body = self
            .client
            .get(format!("{}/?{qs}", self.endpoint))
            .send_raw()
            .await?;
        let parsed: ListResponse = serde_json::from_str(&body).map_err(|err| {
            Error::Serialize(format!("Failed to parse Dreamhost list response: {err}"))
        })?;
        if parsed.result != "success" {
            return Err(Error::Api("Dreamhost list records failed".to_string()));
        }
        parsed
            .data
            .into_iter()
            .find(|r| r.record == name && r.rr_type == rr_type)
            .map(|r| r.value)
            .ok_or_else(|| {
                Error::Api(format!("Dreamhost record {name} of type {rr_type} not found"))
            })
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        _ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let fqdn = name.into_name().to_string();
        let rr_type = record.as_type().as_str();
        let value = render_value(&record)?;
        self.add_record(&fqdn, rr_type, &value).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        _ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let fqdn = name.into_name().to_string();
        let rr_type = record.as_type().as_str();
        let new_value = render_value(&record)?;
        let old_value = self.find_record_value(&fqdn, rr_type).await?;
        if old_value != new_value {
            self.remove_record(&fqdn, rr_type, &old_value).await?;
            self.add_record(&fqdn, rr_type, &new_value).await?;
        }
        Ok(())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        _origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let fqdn = name.into_name().to_string();
        let rr_type = record_type.as_str();
        let value = self.find_record_value(&fqdn, rr_type).await?;
        self.remove_record(&fqdn, rr_type, &value).await
    }
}

fn render_value(record: &DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content.clone(),
        DnsRecord::NS(content) => content.clone(),
        DnsRecord::TXT(content) => content.clone(),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, mx.exchange),
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority, srv.weight, srv.port, srv.target
        ),
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Dreamhost".to_string(),
            ));
        }
        DnsRecord::CAA(caa) => caa.to_string(),
    })
}
