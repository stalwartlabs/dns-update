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

use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

const DEFAULT_WAPI_VERSION: &str = "2.11";
const DEFAULT_PORT: &str = "443";
const DEFAULT_VIEW: &str = "External";

#[derive(Debug, Clone)]
pub struct InfobloxConfig {
    pub host: String,
    pub port: Option<String>,
    pub username: String,
    pub password: String,
    pub wapi_version: Option<String>,
    pub dns_view: Option<String>,
    pub request_timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct InfobloxProvider {
    client: Client,
    base_url: String,
    auth_header: String,
    dns_view: String,
}

#[derive(Deserialize, Debug)]
struct ObjectRef {
    _ref: String,
}

#[derive(Deserialize, Debug)]
struct InfobloxError {
    #[serde(default, rename = "Error")]
    error: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

impl InfobloxProvider {
    pub(crate) fn new(config: InfobloxConfig) -> Result<Self> {
        if config.host.is_empty() {
            return Err(Error::Client("Infoblox host is required".into()));
        }
        if config.username.is_empty() || config.password.is_empty() {
            return Err(Error::Client("Infoblox credentials are required".into()));
        }

        let mut builder = Client::builder();
        if let Some(timeout) = config.request_timeout {
            builder = builder.timeout(timeout);
        }
        let client = builder.build().map_err(|err| {
            Error::Client(format!("Failed to build Infoblox HTTP client: {err}"))
        })?;

        let port = config.port.unwrap_or_else(|| DEFAULT_PORT.to_string());
        let version = config
            .wapi_version
            .unwrap_or_else(|| DEFAULT_WAPI_VERSION.to_string());
        let scheme = if config.host.starts_with("http://") || config.host.starts_with("https://") {
            ""
        } else {
            "https://"
        };
        let host = config.host.trim_end_matches('/');
        let base_url = if scheme.is_empty() {
            format!("{host}/wapi/v{version}")
        } else if port == "443" {
            format!("{scheme}{host}/wapi/v{version}")
        } else {
            format!("{scheme}{host}:{port}/wapi/v{version}")
        };

        let credentials = format!("{}:{}", config.username, config.password);
        let auth_header = format!("Basic {}", BASE64_STANDARD.encode(credentials.as_bytes()));

        Ok(Self {
            client,
            base_url,
            auth_header,
            dns_view: config.dns_view.unwrap_or_else(|| DEFAULT_VIEW.to_string()),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        self.base_url = endpoint.as_ref().trim_end_matches('/').to_string();
        self
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        let name = name.into_name().to_string();
        let body = build_create_body(&name, &record, ttl, &self.dns_view)?;
        let object = wapi_object(&record);

        let response = self
            .client
            .post(format!("{}/{object}", self.base_url))
            .header(reqwest::header::AUTHORIZATION, &self.auth_header)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|err| Error::Api(format!("Infoblox create request failed: {err}")))?;
        self.handle_response_empty(response, "create").await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        let name = name.into_name().to_string();
        let object = wapi_object(&record);
        let reference = self.find_reference(object, &name, None, None).await?;
        let body = build_update_body(&record, ttl)?;

        let response = self
            .client
            .put(format!("{}/{}", self.base_url, reference))
            .header(reqwest::header::AUTHORIZATION, &self.auth_header)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|err| Error::Api(format!("Infoblox update request failed: {err}")))?;
        self.handle_response_empty(response, "update").await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        _origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> Result<()> {
        let name = name.into_name().to_string();
        let object = wapi_object_for_type(record_type)?;
        let reference = self.find_reference(object, &name, None, Some(record_type)).await?;

        let response = self
            .client
            .delete(format!("{}/{}", self.base_url, reference))
            .header(reqwest::header::AUTHORIZATION, &self.auth_header)
            .send()
            .await
            .map_err(|err| Error::Api(format!("Infoblox delete request failed: {err}")))?;
        self.handle_response_empty(response, "delete").await
    }

    async fn find_reference(
        &self,
        object: &str,
        name: &str,
        record_for_match: Option<&DnsRecord>,
        _record_type_hint: Option<DnsRecordType>,
    ) -> Result<String> {
        let query = format!(
            "{base}/{object}?name={name}&view={view}",
            base = self.base_url,
            view = self.dns_view
        );
        let response = self
            .client
            .get(&query)
            .header(reqwest::header::AUTHORIZATION, &self.auth_header)
            .send()
            .await
            .map_err(|err| Error::Api(format!("Infoblox lookup request failed: {err}")))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| Error::Api(format!("Infoblox lookup read failed: {err}")))?;
        if !status.is_success() {
            return Err(match status.as_u16() {
                401 | 403 => Error::Unauthorized,
                404 => Error::NotFound,
                _ => Error::Api(format!("Infoblox lookup returned {status}: {body}")),
            });
        }
        let values: Vec<Value> = serde_json::from_str(&body).map_err(|err| {
            Error::Api(format!("Failed to parse Infoblox lookup response: {err}"))
        })?;
        let matched = values
            .into_iter()
            .find(|value| match record_for_match {
                None => true,
                Some(record) => infoblox_value_matches(value, record),
            })
            .ok_or(Error::NotFound)?;
        let reference: ObjectRef = serde_json::from_value(matched).map_err(|err| {
            Error::Api(format!("Failed to parse Infoblox lookup reference: {err}"))
        })?;
        Ok(reference._ref)
    }

    async fn handle_response_empty(
        &self,
        response: reqwest::Response,
        action: &str,
    ) -> Result<()> {
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let body = response.text().await.unwrap_or_default();
        match status.as_u16() {
            401 | 403 => Err(Error::Unauthorized),
            404 => Err(Error::NotFound),
            400 => Err(Error::BadRequest),
            _ => Err(Error::Api(format!(
                "Infoblox {action} returned {status}: {}",
                infoblox_error_message(&body)
            ))),
        }
    }
}

fn wapi_object(record: &DnsRecord) -> &'static str {
    match record {
        DnsRecord::A(_) => "record:a",
        DnsRecord::AAAA(_) => "record:aaaa",
        DnsRecord::CNAME(_) => "record:cname",
        DnsRecord::NS(_) => "record:ns",
        DnsRecord::MX(_) => "record:mx",
        DnsRecord::TXT(_) => "record:txt",
        DnsRecord::SRV(_) => "record:srv",
        DnsRecord::TLSA(_) => "record:tlsa",
        DnsRecord::CAA(_) => "record:caa",
    }
}

fn wapi_object_for_type(record_type: DnsRecordType) -> Result<&'static str> {
    Ok(match record_type {
        DnsRecordType::A => "record:a",
        DnsRecordType::AAAA => "record:aaaa",
        DnsRecordType::CNAME => "record:cname",
        DnsRecordType::NS => "record:ns",
        DnsRecordType::MX => "record:mx",
        DnsRecordType::TXT => "record:txt",
        DnsRecordType::SRV => "record:srv",
        DnsRecordType::CAA => "record:caa",
        DnsRecordType::TLSA => {
            return Err(Error::Api(
                "TLSA records are not supported by Infoblox".into(),
            ));
        }
    })
}

fn build_create_body(name: &str, record: &DnsRecord, ttl: u32, view: &str) -> Result<Value> {
    let mut body = build_update_body(record, ttl)?;
    if let Value::Object(ref mut map) = body {
        map.insert("name".to_string(), Value::String(name.to_string()));
        map.insert("view".to_string(), Value::String(view.to_string()));
    }
    Ok(body)
}

fn build_update_body(record: &DnsRecord, ttl: u32) -> Result<Value> {
    let mut body = match record {
        DnsRecord::A(ip) => json!({ "ipv4addr": ip.to_string() }),
        DnsRecord::AAAA(ip) => json!({ "ipv6addr": ip.to_string() }),
        DnsRecord::CNAME(target) => json!({ "canonical": target }),
        DnsRecord::NS(target) => json!({ "nameserver": target }),
        DnsRecord::MX(mx) => json!({
            "mail_exchanger": mx.exchange,
            "preference": mx.priority,
        }),
        DnsRecord::TXT(value) => json!({ "text": value }),
        DnsRecord::SRV(srv) => json!({
            "priority": srv.priority,
            "weight": srv.weight,
            "port": srv.port,
            "target": srv.target,
        }),
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Infoblox".into(),
            ));
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            json!({
                "ca_flag": flags,
                "ca_tag": tag,
                "ca_value": value,
            })
        }
    };
    if let Value::Object(ref mut map) = body {
        map.insert("ttl".to_string(), Value::Number(ttl.into()));
        map.insert("use_ttl".to_string(), Value::Bool(true));
    }
    Ok(body)
}

fn infoblox_value_matches(value: &Value, record: &DnsRecord) -> bool {
    match record {
        DnsRecord::A(ip) => value
            .get("ipv4addr")
            .and_then(Value::as_str)
            .is_some_and(|content| content == ip.to_string()),
        DnsRecord::AAAA(ip) => value
            .get("ipv6addr")
            .and_then(Value::as_str)
            .is_some_and(|content| content == ip.to_string()),
        DnsRecord::CNAME(target) => value
            .get("canonical")
            .and_then(Value::as_str)
            .is_some_and(|content| content.trim_end_matches('.') == target.trim_end_matches('.')),
        DnsRecord::NS(target) => value
            .get("nameserver")
            .and_then(Value::as_str)
            .is_some_and(|content| content.trim_end_matches('.') == target.trim_end_matches('.')),
        DnsRecord::MX(mx) => {
            let exchange = value
                .get("mail_exchanger")
                .and_then(Value::as_str)
                .map(|value| value.trim_end_matches('.'));
            exchange.is_some_and(|content| content == mx.exchange.trim_end_matches('.'))
        }
        DnsRecord::TXT(text) => value
            .get("text")
            .and_then(Value::as_str)
            .is_some_and(|content| content == text),
        DnsRecord::SRV(srv) => {
            let target_matches = value
                .get("target")
                .and_then(Value::as_str)
                .map(|target| target.trim_end_matches('.') == srv.target.trim_end_matches('.'))
                .unwrap_or(false);
            let port_matches = value
                .get("port")
                .and_then(Value::as_u64)
                .map(|port| port as u16 == srv.port)
                .unwrap_or(false);
            target_matches && port_matches
        }
        DnsRecord::CAA(_) => true,
        DnsRecord::TLSA(_) => false,
    }
}

fn infoblox_error_message(body: &str) -> String {
    if let Ok(value) = serde_json::from_str::<InfobloxError>(body)
        && let Some(message) = value.error.or(value.text)
            && !message.is_empty()
        {
            return message;
        }
    body.to_string()
}

