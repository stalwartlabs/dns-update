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

use crate::utils::strip_origin_from_name;
use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct AzureDnsConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub subscription_id: String,
    pub resource_group: String,
    pub environment: AzureEnvironment,
    pub request_timeout: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AzureEnvironment {
    Public,
    China,
    UsGovernment,
}

impl AzureEnvironment {
    pub fn from_str_lossy(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "china" => AzureEnvironment::China,
            "usgovernment" => AzureEnvironment::UsGovernment,
            _ => AzureEnvironment::Public,
        }
    }

    fn login_host(self) -> &'static str {
        match self {
            AzureEnvironment::Public => "https://login.microsoftonline.com",
            AzureEnvironment::China => "https://login.chinacloudapi.cn",
            AzureEnvironment::UsGovernment => "https://login.microsoftonline.us",
        }
    }

    fn management_host(self) -> &'static str {
        match self {
            AzureEnvironment::Public => "https://management.azure.com",
            AzureEnvironment::China => "https://management.chinacloudapi.cn",
            AzureEnvironment::UsGovernment => "https://management.usgovcloudapi.net",
        }
    }

    fn scope(self) -> &'static str {
        match self {
            AzureEnvironment::Public => "https://management.azure.com/.default",
            AzureEnvironment::China => "https://management.chinacloudapi.cn/.default",
            AzureEnvironment::UsGovernment => "https://management.usgovcloudapi.net/.default",
        }
    }
}

#[derive(Clone)]
pub struct AzureDnsProvider {
    client: Client,
    config: AzureDnsConfig,
    token: Arc<Mutex<Option<(String, Instant)>>>,
    endpoints: AzureEndpoints,
}

#[derive(Clone)]
struct AzureEndpoints {
    login_url: String,
    management_url: String,
}

const API_VERSION: &str = "2018-05-01";

impl AzureDnsProvider {
    pub fn new(config: AzureDnsConfig) -> Result<Self> {
        let mut builder = Client::builder();
        if let Some(timeout) = config.request_timeout {
            builder = builder.timeout(timeout);
        }
        let client = builder
            .build()
            .map_err(|err| Error::Client(format!("Failed to build reqwest client: {err}")))?;

        let endpoints = AzureEndpoints {
            login_url: config.environment.login_host().to_string(),
            management_url: config.environment.management_host().to_string(),
        };

        Ok(Self {
            client,
            config,
            token: Arc::new(Mutex::new(None)),
            endpoints,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoints(
        mut self,
        login_url: impl AsRef<str>,
        management_url: impl AsRef<str>,
    ) -> Self {
        self.endpoints = AzureEndpoints {
            login_url: login_url.as_ref().trim_end_matches('/').to_string(),
            management_url: management_url.as_ref().trim_end_matches('/').to_string(),
        };
        self
    }

    #[cfg(test)]
    pub(crate) fn with_cached_token(self, token: impl Into<String>) -> Self {
        *self.token.lock().expect("test token lock") =
            Some((token.into(), Instant::now() + Duration::from_secs(55 * 60)));
        self
    }

    async fn ensure_token(&self) -> Result<String> {
        if let Some((ref token, expiry)) = *self.token_lock()?
            && Instant::now() < expiry
        {
            return Ok(token.clone());
        }

        let url = format!(
            "{}/{}/oauth2/v2.0/token",
            self.endpoints.login_url, self.config.tenant_id
        );
        let form = serde_urlencoded::to_string([
            ("grant_type", "client_credentials"),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("scope", self.config.environment.scope()),
        ])
        .map_err(|e| Error::Api(format!("Failed to encode token request: {e}")))?;

        let response = self
            .client
            .post(&url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .map_err(|e| Error::Api(format!("Azure token request failed: {e}")))?;

        let token_response: AzureTokenResponse =
            self.parse_json_response(response, "parse token response").await?;

        if token_response.access_token.is_empty() {
            return Err(Error::Api("Azure token response missing access_token".into()));
        }

        let lifetime = token_response.expires_in.unwrap_or(3600).saturating_sub(60).max(60);
        let expiry = Instant::now() + Duration::from_secs(lifetime);
        *self.token_lock()? = Some((token_response.access_token.clone(), expiry));
        Ok(token_response.access_token)
    }

    pub async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        self.put_record(name, record, ttl, origin, false).await
    }

    pub async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        self.put_record(name, record, ttl, origin, true).await
    }

    pub async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> Result<()> {
        let zone = origin.into_name().to_ascii_lowercase();
        let fqdn = name.into_name().to_ascii_lowercase();
        let relative = relative_record_name(&fqdn, &zone);
        let type_segment = azure_record_type(&record_type)?;
        let url = self.record_url(&zone, type_segment, &relative);
        let token = self.ensure_token().await?;

        let response = self
            .client
            .delete(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| Error::Api(format!("Azure delete request failed: {e}")))?;

        let status = response.status();
        if status.is_success() || status.as_u16() == 204 || status.as_u16() == 404 {
            return Ok(());
        }
        Err(self.map_error(response).await)
    }

    async fn put_record(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
        is_update: bool,
    ) -> Result<()> {
        let zone = origin.into_name().to_ascii_lowercase();
        let fqdn = name.into_name().to_ascii_lowercase();
        let relative = relative_record_name(&fqdn, &zone);
        let record_type = record.as_type();
        let type_segment = azure_record_type(&record_type)?;
        let token = self.ensure_token().await?;
        let url = self.record_url(&zone, type_segment, &relative);

        let mut properties = serde_json::Map::new();
        properties.insert("TTL".to_string(), json!(ttl));
        insert_record_payload(&mut properties, &record);

        let mut body = serde_json::Map::new();
        body.insert("properties".to_string(), Value::Object(properties));

        let mut request = self.client.put(&url).bearer_auth(&token).json(&body);
        if is_update {
            request = request.header("if-match", "*");
        }

        let response = request
            .send()
            .await
            .map_err(|e| Error::Api(format!("Azure record set request failed: {e}")))?;

        if response.status().is_success() {
            return Ok(());
        }
        Err(self.map_error(response).await)
    }

    fn record_url(&self, zone: &str, type_segment: &str, relative: &str) -> String {
        format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/{}/{}?api-version={}",
            self.endpoints.management_url,
            self.config.subscription_id,
            self.config.resource_group,
            zone,
            type_segment,
            relative,
            API_VERSION,
        )
    }

    async fn map_error(&self, response: reqwest::Response) -> Error {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        match status.as_u16() {
            400 => Error::BadRequest,
            401 | 403 => Error::Unauthorized,
            404 => Error::NotFound,
            _ => Error::Api(azure_error_message(&body, status.as_u16())),
        }
    }

    async fn parse_json_response<T>(&self, response: reqwest::Response, context: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = response.status();
        if !status.is_success() {
            return Err(self.map_error(response).await);
        }
        response
            .json::<T>()
            .await
            .map_err(|e| Error::Api(format!("{context}: {e}")))
    }

    fn token_lock(&self) -> Result<std::sync::MutexGuard<'_, Option<(String, Instant)>>> {
        self.token
            .lock()
            .map_err(|_| Error::Client("Azure DNS token cache lock poisoned".into()))
    }
}

fn relative_record_name(fqdn: &str, zone: &str) -> String {
    let stripped = strip_origin_from_name(fqdn, zone, Some("@"));
    if stripped.is_empty() { "@".to_string() } else { stripped }
}

fn azure_record_type(rt: &DnsRecordType) -> Result<&'static str> {
    Ok(match rt {
        DnsRecordType::A => "A",
        DnsRecordType::AAAA => "AAAA",
        DnsRecordType::CNAME => "CNAME",
        DnsRecordType::MX => "MX",
        DnsRecordType::NS => "NS",
        DnsRecordType::TXT => "TXT",
        DnsRecordType::SRV => "SRV",
        DnsRecordType::CAA => "CAA",
        DnsRecordType::TLSA => {
            return Err(Error::Api(
                "TLSA records are not supported by Azure DNS".to_string(),
            ));
        }
    })
}

fn insert_record_payload(props: &mut serde_json::Map<String, Value>, record: &DnsRecord) {
    match record {
        DnsRecord::A(ip) => {
            props.insert(
                "ARecords".to_string(),
                json!([{"ipv4Address": ip.to_string()}]),
            );
        }
        DnsRecord::AAAA(ip) => {
            props.insert(
                "AAAARecords".to_string(),
                json!([{"ipv6Address": ip.to_string()}]),
            );
        }
        DnsRecord::CNAME(target) => {
            props.insert(
                "CNAMERecord".to_string(),
                json!({"cname": target.trim_end_matches('.')}),
            );
        }
        DnsRecord::NS(target) => {
            props.insert(
                "NSRecords".to_string(),
                json!([{"nsdname": target.trim_end_matches('.')}]),
            );
        }
        DnsRecord::MX(mx) => {
            props.insert(
                "MXRecords".to_string(),
                json!([{"preference": mx.priority, "exchange": mx.exchange.trim_end_matches('.')}]),
            );
        }
        DnsRecord::TXT(txt) => {
            props.insert("TXTRecords".to_string(), json!([{"value": [txt]}]));
        }
        DnsRecord::SRV(srv) => {
            props.insert(
                "SRVRecords".to_string(),
                json!([{
                    "priority": srv.priority,
                    "weight": srv.weight,
                    "port": srv.port,
                    "target": srv.target.trim_end_matches('.')
                }]),
            );
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            props.insert(
                "CAARecords".to_string(),
                json!([{"flags": flags, "tag": tag, "value": value}]),
            );
        }
        DnsRecord::TLSA(_) => {}
    }
}

fn azure_error_message(body: &str, status: u16) -> String {
    if let Ok(value) = serde_json::from_str::<Value>(body)
        && let Some(message) = value
            .get("error")
            .and_then(|v| v.get("message").or_else(|| v.get("code")))
            .and_then(Value::as_str)
    {
        return format!("Azure DNS error ({status}): {message}");
    }
    if body.is_empty() {
        format!("Azure DNS error ({status})")
    } else {
        format!("Azure DNS error ({status}): {body}")
    }
}

#[derive(Deserialize)]
struct AzureTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}
