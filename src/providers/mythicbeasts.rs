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
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_API_ENDPOINT: &str = "https://api.mythic-beasts.com/dns/v2";
const DEFAULT_AUTH_ENDPOINT: &str = "https://auth.mythic-beasts.com/login";

#[derive(Clone)]
pub struct MythicBeastsProvider {
    auth: Arc<Mutex<AuthState>>,
    username: String,
    password: String,
    api_endpoint: String,
    auth_endpoint: String,
    timeout: Option<Duration>,
}

struct AuthState {
    token: Option<(String, Instant)>,
}

#[derive(Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    #[serde(default)]
    token_type: String,
}

#[derive(Serialize, Debug)]
struct CreateRecordsBody<'a> {
    records: Vec<RecordPayload<'a>>,
}

#[derive(Serialize, Debug)]
struct RecordPayload<'a> {
    host: &'a str,
    ttl: u32,
    #[serde(rename = "type")]
    record_type: &'a str,
    data: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct MutationResponse {
    #[serde(default)]
    records_added: i64,
    #[serde(default)]
    records_removed: i64,
    #[serde(default)]
    message: String,
}

impl MythicBeastsProvider {
    pub(crate) fn new(
        username: impl AsRef<str>,
        password: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let username = username.as_ref().to_string();
        let password = password.as_ref().to_string();
        if username.is_empty() || password.is_empty() {
            return Err(Error::Api(
                "Mythic Beasts username and password must not be empty".to_string(),
            ));
        }

        Ok(Self {
            auth: Arc::new(Mutex::new(AuthState { token: None })),
            username,
            password,
            api_endpoint: DEFAULT_API_ENDPOINT.to_string(),
            auth_endpoint: DEFAULT_AUTH_ENDPOINT.to_string(),
            timeout,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        let base = endpoint.as_ref().trim_end_matches('/').to_string();
        Self {
            api_endpoint: format!("{base}/dns/v2"),
            auth_endpoint: format!("{base}/auth/login"),
            ..self
        }
    }

    fn api_client(&self, token: &str) -> HttpClientBuilder {
        HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {token}"))
            .with_header("Accept", "application/json")
            .with_timeout(self.timeout)
    }

    async fn ensure_token(&self) -> crate::Result<String> {
        {
            let guard = self
                .auth
                .lock()
                .map_err(|_| Error::Client("Mythic Beasts token lock poisoned".to_string()))?;
            if let Some((token, expiry)) = &guard.token
                && Instant::now() < *expiry
            {
                return Ok(token.clone());
            }
        }

        let credentials = STANDARD.encode(format!("{}:{}", self.username, self.password));
        let auth_client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {credentials}"))
            .with_header("Accept", "application/json")
            .with_timeout(self.timeout);

        let body: TokenResponse = auth_client
            .post(self.auth_endpoint.clone())
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_raw_body("grant_type=client_credentials".to_string())
            .send()
            .await?;

        if !body.token_type.eq_ignore_ascii_case("bearer") && !body.token_type.is_empty() {
            return Err(Error::Api(format!(
                "Unexpected token type: {}",
                body.token_type
            )));
        }

        let expiry = Instant::now() + Duration::from_secs(body.expires_in.saturating_sub(60));
        let mut guard = self
            .auth
            .lock()
            .map_err(|_| Error::Client("Mythic Beasts token lock poisoned".to_string()))?;
        guard.token = Some((body.access_token.clone(), expiry));
        Ok(body.access_token)
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
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let record_type = record.as_type();
        let data = render_value(record)?;
        let token = self.ensure_token().await?;

        let payload = CreateRecordsBody {
            records: vec![RecordPayload {
                host: &subdomain,
                ttl,
                record_type: record_type.as_str(),
                data: data.clone(),
            }],
        };

        let _: MutationResponse = self
            .api_client(&token)
            .post(format!(
                "{}/zones/{}/records/{}/{}",
                self.api_endpoint,
                domain,
                subdomain,
                record_type.as_str(),
            ))
            .with_body(payload)?
            .send()
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let record_type = record.as_type();
        let data = render_value(record)?;
        let token = self.ensure_token().await?;

        let payload = CreateRecordsBody {
            records: vec![RecordPayload {
                host: &subdomain,
                ttl,
                record_type: record_type.as_str(),
                data,
            }],
        };

        let _: MutationResponse = self
            .api_client(&token)
            .put(format!(
                "{}/zones/{}/records/{}/{}",
                self.api_endpoint,
                domain,
                subdomain,
                record_type.as_str(),
            ))
            .with_body(payload)?
            .send()
            .await?;
        Ok(())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let token = self.ensure_token().await?;

        self.api_client(&token)
            .delete(format!(
                "{}/zones/{}/records/{}/{}",
                self.api_endpoint,
                domain,
                subdomain,
                record_type.as_str(),
            ))
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn render_value(record: DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content,
        DnsRecord::NS(content) => content,
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, mx.exchange),
        DnsRecord::TXT(content) => content,
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority, srv.weight, srv.port, srv.target
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.decompose();
            format!("{flags} {tag} \"{value}\"")
        }
    })
}
