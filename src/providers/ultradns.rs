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
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_ENDPOINT: &str = "https://api.ultradns.com";

#[derive(Clone)]
pub struct UltraDnsProvider {
    client: Client,
    username: String,
    password: String,
    endpoint: String,
    token: Arc<Mutex<Option<TokenState>>>,
}

#[derive(Clone)]
struct TokenState {
    access_token: String,
    refresh_token: Option<String>,
    expires: Instant,
}

#[derive(Deserialize, Debug)]
struct TokenResponse {
    #[serde(rename = "accessToken", alias = "access_token")]
    access_token: String,
    #[serde(rename = "refreshToken", alias = "refresh_token", default)]
    refresh_token: Option<String>,
    #[serde(rename = "expiresIn", alias = "expires_in", default)]
    expires_in: Option<serde_json::Value>,
}

#[derive(Serialize, Debug)]
struct RrsetBody<'a> {
    ttl: u32,
    rdata: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'a str>,
}

#[derive(Deserialize, Debug)]
struct ApiError {
    #[serde(default, rename = "errorMessage")]
    error_message: Option<String>,
}

impl UltraDnsProvider {
    pub(crate) fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        endpoint: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let mut builder = Client::builder();
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        let client = builder.build().map_err(|err| {
            Error::Client(format!("Failed to build UltraDNS HTTP client: {err}"))
        })?;
        Ok(Self {
            client,
            username: username.into(),
            password: password.into(),
            endpoint: endpoint
                .map(|value| value.trim_end_matches('/').to_string())
                .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string()),
            token: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        self.endpoint = endpoint.as_ref().trim_end_matches('/').to_string();
        self
    }

    #[cfg(test)]
    pub(crate) fn with_cached_token(self, token: impl Into<String>) -> Self {
        *self
            .token
            .lock()
            .expect("UltraDNS test token lock") = Some(TokenState {
            access_token: token.into(),
            refresh_token: None,
            expires: Instant::now() + Duration::from_secs(55 * 60),
        });
        self
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        let owner = name.into_fqdn().to_string();
        let zone = origin.into_fqdn().to_string();
        let record_type = ultradns_record_type(&record);
        let rdata = ultradns_rdata(&record)?;
        let url = self.rrset_url(&zone, record_type, &owner);

        let token = self.ensure_token().await?;
        let response = self
            .client
            .post(&url)
            .bearer_auth(&token)
            .json(&RrsetBody {
                ttl,
                rdata,
                profile: None,
            })
            .send()
            .await
            .map_err(|err| Error::Api(format!("UltraDNS create request failed: {err}")))?;
        self.handle_response_empty(response, "create").await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        let owner = name.into_fqdn().to_string();
        let zone = origin.into_fqdn().to_string();
        let record_type = ultradns_record_type(&record);
        let rdata = ultradns_rdata(&record)?;
        let url = self.rrset_url(&zone, record_type, &owner);

        let token = self.ensure_token().await?;
        let response = self
            .client
            .put(&url)
            .bearer_auth(&token)
            .json(&RrsetBody {
                ttl,
                rdata,
                profile: None,
            })
            .send()
            .await
            .map_err(|err| Error::Api(format!("UltraDNS update request failed: {err}")))?;
        self.handle_response_empty(response, "update").await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> Result<()> {
        let owner = name.into_fqdn().to_string();
        let zone = origin.into_fqdn().to_string();
        let record_type_str = ultradns_record_type_str(record_type);
        let url = self.rrset_url(&zone, record_type_str, &owner);

        let token = self.ensure_token().await?;
        let response = self
            .client
            .delete(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|err| Error::Api(format!("UltraDNS delete request failed: {err}")))?;
        self.handle_response_empty(response, "delete").await
    }

    fn rrset_url(&self, zone: &str, record_type: &str, owner: &str) -> String {
        let zone = ensure_fqdn(zone);
        let owner = ensure_fqdn(owner);
        format!(
            "{base}/v3/zones/{zone}/rrsets/{record_type}/{owner}",
            base = self.endpoint
        )
    }

    async fn ensure_token(&self) -> Result<String> {
        if let Some(state) = self.token.lock().ok().and_then(|guard| guard.clone())
            && Instant::now() < state.expires
        {
            return Ok(state.access_token);
        }

        let refresh = self
            .token
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().and_then(|state| state.refresh_token.clone()));

        let body = if let Some(refresh) = refresh.as_deref() {
            serde_urlencoded::to_string([
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
            ])
        } else {
            serde_urlencoded::to_string([
                ("grant_type", "password"),
                ("username", self.username.as_str()),
                ("password", self.password.as_str()),
            ])
        }
        .map_err(|err| Error::Api(format!("UltraDNS token body encode failed: {err}")))?;

        let response = self
            .client
            .post(format!("{}/v2/authorization/token", self.endpoint))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await
            .map_err(|err| Error::Api(format!("UltraDNS token request failed: {err}")))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| Error::Api(format!("UltraDNS token read failed: {err}")))?;
        if !status.is_success() {
            return Err(match status.as_u16() {
                401 | 403 => Error::Unauthorized,
                _ => Error::Api(format!("UltraDNS token request returned {status}: {body}")),
            });
        }

        let token: TokenResponse = serde_json::from_str(&body).map_err(|err| {
            Error::Api(format!("Failed to parse UltraDNS token response: {err}"))
        })?;

        let lifetime = token
            .expires_in
            .as_ref()
            .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
            .unwrap_or(55 * 60);

        let state = TokenState {
            access_token: token.access_token.clone(),
            refresh_token: token.refresh_token,
            expires: Instant::now() + Duration::from_secs(lifetime.saturating_sub(30)),
        };

        if let Ok(mut guard) = self.token.lock() {
            *guard = Some(state);
        }
        Ok(token.access_token)
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
            400 => Err(Error::Api(format!(
                "UltraDNS {action} bad request: {}",
                api_error_message(&body)
            ))),
            _ => Err(Error::Api(format!(
                "UltraDNS {action} returned {status}: {}",
                api_error_message(&body)
            ))),
        }
    }
}

fn ensure_fqdn(value: &str) -> String {
    if value.ends_with('.') {
        value.to_string()
    } else {
        format!("{value}.")
    }
}

fn ultradns_record_type(record: &DnsRecord) -> &'static str {
    match record {
        DnsRecord::A(_) => "A",
        DnsRecord::AAAA(_) => "AAAA",
        DnsRecord::CNAME(_) => "CNAME",
        DnsRecord::NS(_) => "NS",
        DnsRecord::MX(_) => "MX",
        DnsRecord::TXT(_) => "TXT",
        DnsRecord::SRV(_) => "SRV",
        DnsRecord::TLSA(_) => "TLSA",
        DnsRecord::CAA(_) => "CAA",
    }
}

fn ultradns_record_type_str(record_type: DnsRecordType) -> &'static str {
    match record_type {
        DnsRecordType::A => "A",
        DnsRecordType::AAAA => "AAAA",
        DnsRecordType::CNAME => "CNAME",
        DnsRecordType::NS => "NS",
        DnsRecordType::MX => "MX",
        DnsRecordType::TXT => "TXT",
        DnsRecordType::SRV => "SRV",
        DnsRecordType::TLSA => "TLSA",
        DnsRecordType::CAA => "CAA",
    }
}

fn ultradns_rdata(record: &DnsRecord) -> Result<Vec<String>> {
    Ok(match record {
        DnsRecord::A(ip) => vec![ip.to_string()],
        DnsRecord::AAAA(ip) => vec![ip.to_string()],
        DnsRecord::CNAME(target) => vec![ensure_fqdn(target)],
        DnsRecord::NS(target) => vec![ensure_fqdn(target)],
        DnsRecord::MX(mx) => vec![format!("{} {}", mx.priority, ensure_fqdn(&mx.exchange))],
        DnsRecord::TXT(value) => vec![format!("\"{}\"", value.replace('"', "\\\""))],
        DnsRecord::SRV(srv) => vec![format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            ensure_fqdn(&srv.target)
        )],
        DnsRecord::TLSA(tlsa) => vec![tlsa.to_string()],
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            vec![format!("{flags} {tag} \"{value}\"")]
        }
    })
}

fn api_error_message(body: &str) -> String {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(array) = value.as_array() {
            let messages: Vec<String> = array
                .iter()
                .filter_map(|item| serde_json::from_value::<ApiError>(item.clone()).ok())
                .filter_map(|item| item.error_message)
                .collect();
            if !messages.is_empty() {
                return messages.join("; ");
            }
        }
        if let Ok(item) = serde_json::from_value::<ApiError>(value)
            && let Some(message) = item.error_message
        {
            return message;
        }
    }
    body.to_string()
}
