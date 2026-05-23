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

#![cfg(any(feature = "ring", feature = "aws-lc-rs"))]

use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn,
    http::HttpClientBuilder,
    jwt::rsa_sha512_sign,
    utils::strip_origin_from_name,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_API_ENDPOINT: &str = "https://api.transip.nl/v6";

#[derive(Clone)]
pub struct TransipProvider {
    auth: Arc<Mutex<AuthState>>,
    login: String,
    private_key_pem: String,
    endpoint: String,
    timeout: Option<Duration>,
}

struct AuthState {
    token: Option<(String, Instant)>,
}

#[derive(Serialize, Debug)]
struct AuthRequest<'a> {
    login: &'a str,
    nonce: String,
    read_only: bool,
    expiration_time: &'a str,
    label: String,
    global_key: bool,
}

#[derive(Deserialize, Debug)]
struct AuthResponse {
    token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DnsEntry {
    name: String,
    expire: u32,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
}

#[derive(Deserialize, Debug)]
struct DnsEntriesResponse {
    #[serde(rename = "dnsEntries", default)]
    dns_entries: Vec<DnsEntry>,
}

#[derive(Serialize, Debug)]
struct DnsEntryRequest<'a> {
    #[serde(rename = "dnsEntry")]
    dns_entry: &'a DnsEntry,
}

impl TransipProvider {
    pub(crate) fn new(
        login: impl AsRef<str>,
        private_key_pem: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let login = login.as_ref().to_string();
        let private_key_pem = private_key_pem.as_ref().to_string();
        if login.is_empty() || private_key_pem.is_empty() {
            return Err(Error::Api(
                "TransIP login and private key must not be empty".to_string(),
            ));
        }
        Ok(Self {
            auth: Arc::new(Mutex::new(AuthState { token: None })),
            login,
            private_key_pem,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            timeout,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().trim_end_matches('/').to_string(),
            ..self
        }
    }

    #[cfg(test)]
    pub(crate) fn with_cached_token(self, token: impl Into<String>) -> Self {
        if let Ok(mut guard) = self.auth.lock() {
            guard.token = Some((token.into(), Instant::now() + Duration::from_secs(30 * 60)));
        }
        self
    }

    async fn ensure_token(&self) -> crate::Result<String> {
        {
            let guard = self
                .auth
                .lock()
                .map_err(|_| Error::Client("TransIP token lock poisoned".to_string()))?;
            if let Some((token, expiry)) = &guard.token
                && Instant::now() < *expiry
            {
                return Ok(token.clone());
            }
        }

        let nonce = generate_nonce();
        let body = AuthRequest {
            login: &self.login,
            nonce: nonce.clone(),
            read_only: false,
            expiration_time: "30 minutes",
            label: format!("dns-update-{nonce}"),
            global_key: false,
        };

        let payload = serde_json::to_string(&body)
            .map_err(|e| Error::Serialize(format!("Failed to encode TransIP auth body: {e}")))?;
        let signature = rsa_sha512_sign(&self.private_key_pem, payload.as_bytes())
            .map_err(|e| Error::Api(format!("Failed to sign TransIP request: {e}")))?;
        let signature_b64 = STANDARD.encode(&signature);

        let response: AuthResponse = HttpClientBuilder::default()
            .with_header("Signature", signature_b64)
            .with_header("Accept", "application/json")
            .with_timeout(self.timeout)
            .post(format!("{}/auth", self.endpoint))
            .with_raw_body(payload)
            .send()
            .await?;

        let expiry = Instant::now() + Duration::from_secs(25 * 60);
        let mut guard = self
            .auth
            .lock()
            .map_err(|_| Error::Client("TransIP token lock poisoned".to_string()))?;
        guard.token = Some((response.token.clone(), expiry));
        Ok(response.token)
    }

    fn authed_client(&self, token: &str) -> HttpClientBuilder {
        HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {token}"))
            .with_header("Accept", "application/json")
            .with_timeout(self.timeout)
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
        let content = render_value(record)?;

        let entry = DnsEntry {
            name: subdomain,
            expire: ttl,
            record_type: record_type.as_str().to_string(),
            content,
        };
        let token = self.ensure_token().await?;

        self.authed_client(&token)
            .post(format!("{}/domains/{}/dns", self.endpoint, domain))
            .with_body(DnsEntryRequest { dns_entry: &entry })?
            .send_raw()
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
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let record_type = record.as_type();
        let content = render_value(record)?;

        let entry = DnsEntry {
            name: subdomain,
            expire: ttl,
            record_type: record_type.as_str().to_string(),
            content,
        };
        let token = self.ensure_token().await?;

        self.authed_client(&token)
            .patch(format!("{}/domains/{}/dns", self.endpoint, domain))
            .with_body(DnsEntryRequest { dns_entry: &entry })?
            .send_raw()
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
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let token = self.ensure_token().await?;

        let entries: DnsEntriesResponse = self
            .authed_client(&token)
            .get(format!("{}/domains/{}/dns", self.endpoint, domain))
            .send()
            .await?;

        let target_type = record_type.as_str();
        let matching: Vec<DnsEntry> = entries
            .dns_entries
            .into_iter()
            .filter(|e| e.name == subdomain && e.record_type == target_type)
            .collect();

        if matching.is_empty() {
            return Ok(());
        }

        for entry in matching {
            self.authed_client(&token)
                .delete(format!("{}/domains/{}/dns", self.endpoint, domain))
                .with_body(DnsEntryRequest { dns_entry: &entry })?
                .send_raw()
                .await?;
        }
        Ok(())
    }
}

pub(crate) fn generate_nonce() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0) as u64;
    format!("dnsu{now:016x}")
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
