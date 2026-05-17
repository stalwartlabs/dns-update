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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_API_ENDPOINT: &str = "https://dmapi.joker.com/request";

#[derive(Clone)]
pub struct JokerProvider {
    auth: Arc<Mutex<AuthState>>,
    credentials: Credentials,
    endpoint: String,
    timeout: Option<Duration>,
}

#[derive(Clone)]
struct Credentials {
    api_key: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

struct AuthState {
    session: Option<(String, Instant)>,
}

impl JokerProvider {
    pub(crate) fn new_api_key(
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let key = api_key.as_ref().to_string();
        if key.is_empty() {
            return Err(Error::Api(
                "Joker API key must not be empty".to_string(),
            ));
        }
        Ok(Self {
            auth: Arc::new(Mutex::new(AuthState { session: None })),
            credentials: Credentials {
                api_key: Some(key),
                username: None,
                password: None,
            },
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            timeout,
        })
    }

    pub(crate) fn new_password(
        username: impl AsRef<str>,
        password: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let username = username.as_ref().to_string();
        let password = password.as_ref().to_string();
        if username.is_empty() || password.is_empty() {
            return Err(Error::Api(
                "Joker username and password must not be empty".to_string(),
            ));
        }
        Ok(Self {
            auth: Arc::new(Mutex::new(AuthState { session: None })),
            credentials: Credentials {
                api_key: None,
                username: Some(username),
                password: Some(password),
            },
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

    fn http_client(&self) -> HttpClientBuilder {
        HttpClientBuilder::default()
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_header("Accept", "text/plain")
            .with_timeout(self.timeout)
    }

    async fn ensure_session(&self) -> crate::Result<String> {
        {
            let guard = self
                .auth
                .lock()
                .map_err(|_| Error::Client("Joker session lock poisoned".to_string()))?;
            if let Some((sid, expiry)) = &guard.session
                && Instant::now() < *expiry
            {
                return Ok(sid.clone());
            }
        }

        let params = if let Some(key) = &self.credentials.api_key {
            vec![("api-key", key.clone())]
        } else {
            vec![
                (
                    "username",
                    self.credentials.username.clone().unwrap_or_default(),
                ),
                (
                    "password",
                    self.credentials.password.clone().unwrap_or_default(),
                ),
            ]
        };

        let body = serde_urlencoded::to_string(&params)
            .map_err(|e| Error::Serialize(e.to_string()))?;

        let response = self
            .http_client()
            .post(format!("{}/login", self.endpoint))
            .with_raw_body(body)
            .send_raw()
            .await?;

        let parsed = parse_response(&response);
        check_status(&parsed)?;
        let sid = parsed
            .auth_sid
            .ok_or_else(|| Error::Api("Joker login did not return Auth-Sid".to_string()))?;

        let expiry = Instant::now() + Duration::from_secs(50 * 60);
        let mut guard = self
            .auth
            .lock()
            .map_err(|_| Error::Client("Joker session lock poisoned".to_string()))?;
        guard.session = Some((sid.clone(), expiry));
        Ok(sid)
    }

    async fn get_zone(&self, domain: &str) -> crate::Result<String> {
        let sid = self.ensure_session().await?;
        let params = [("auth-sid", sid.as_str()), ("domain", domain)];
        let body = serde_urlencoded::to_string(params)
            .map_err(|e| Error::Serialize(e.to_string()))?;
        let response = self
            .http_client()
            .post(format!("{}/dns-zone-get", self.endpoint))
            .with_raw_body(body)
            .send_raw()
            .await?;

        let parsed = parse_response(&response);
        check_status(&parsed)?;
        Ok(parsed.body)
    }

    async fn put_zone(&self, domain: &str, zone: String) -> crate::Result<()> {
        let sid = self.ensure_session().await?;
        let params = [
            ("auth-sid", sid.as_str()),
            ("domain", domain),
            ("zone", zone.trim()),
        ];
        let body = serde_urlencoded::to_string(params)
            .map_err(|e| Error::Serialize(e.to_string()))?;
        let response = self
            .http_client()
            .post(format!("{}/dns-zone-put", self.endpoint))
            .with_raw_body(body)
            .send_raw()
            .await?;
        let parsed = parse_response(&response);
        check_status(&parsed)?;
        Ok(())
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
        let entry = render_zone_entry(&subdomain, record, ttl)?;

        let zone = self.get_zone(&domain).await?;
        let mut updated = remove_entries(&zone, &subdomain, record_type);
        if !updated.is_empty() && !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(&entry);
        self.put_zone(&domain, updated).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        self.create(name, record, ttl, origin).await
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
        let zone = self.get_zone(&domain).await?;
        let updated = remove_entries(&zone, &subdomain, record_type);
        if updated.trim() == zone.trim() {
            return Ok(());
        }
        self.put_zone(&domain, updated).await
    }
}

#[derive(Default, Debug)]
struct ParsedResponse {
    status_code: Option<i64>,
    status_text: String,
    auth_sid: Option<String>,
    body: String,
}

fn parse_response(message: &str) -> ParsedResponse {
    let mut parsed = ParsedResponse::default();
    let (head, body) = match message.split_once("\n\n") {
        Some(parts) => parts,
        None => (message, ""),
    };
    for line in head.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let value = v.trim();
            match key {
                "Status-Code" => parsed.status_code = value.parse().ok(),
                "Status-Text" => parsed.status_text = value.to_string(),
                "Auth-Sid" => parsed.auth_sid = Some(value.to_string()),
                _ => {}
            }
        }
    }
    parsed.body = body.to_string();
    parsed
}

fn check_status(parsed: &ParsedResponse) -> crate::Result<()> {
    match parsed.status_code {
        Some(0) | None => Ok(()),
        Some(code) => Err(Error::Api(format!(
            "Joker DMAPI error {}: {}",
            code, parsed.status_text
        ))),
    }
}

fn render_zone_entry(host: &str, record: DnsRecord, ttl: u32) -> crate::Result<String> {
    let (label, priority, value) = match record {
        DnsRecord::A(addr) => ("A", 0, addr.to_string()),
        DnsRecord::AAAA(addr) => ("AAAA", 0, addr.to_string()),
        DnsRecord::CNAME(content) => ("CNAME", 0, ensure_dot(&content)),
        DnsRecord::NS(content) => ("NS", 0, ensure_dot(&content)),
        DnsRecord::MX(mx) => ("MX", mx.priority, ensure_dot(&mx.exchange)),
        DnsRecord::TXT(content) => ("TXT", 0, format!("\"{}\"", content.replace('"', "\\\""))),
        DnsRecord::SRV(srv) => (
            "SRV",
            srv.priority,
            format!("{} {} {}", srv.weight, srv.port, ensure_dot(&srv.target)),
        ),
        DnsRecord::TLSA(tlsa) => ("TLSA", 0, tlsa.to_string()),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.decompose();
            ("CAA", 0, format!("{flags} {tag} \"{value}\""))
        }
    };
    Ok(format!("{host} {label} {priority} {value} {ttl}"))
}

fn ensure_dot(value: &str) -> String {
    if value.ends_with('.') {
        value.to_string()
    } else {
        format!("{value}.")
    }
}

fn remove_entries(zone: &str, host: &str, record_type: DnsRecordType) -> String {
    let prefix_type = format!("{} {}", host, record_type.as_str());
    let mut out = String::new();
    for line in zone.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(&prefix_type)
            && trimmed[prefix_type.len()..].starts_with([' ', '\t'])
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.trim_end().to_string()
}
