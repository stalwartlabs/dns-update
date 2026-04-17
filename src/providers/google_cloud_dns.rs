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
use crate::jwt::{ServiceAccount, create_jwt, exchange_jwt_for_token};
use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Configuration for Google Cloud DNS provider.
#[derive(Debug, Clone)]
pub struct GoogleCloudDnsConfig {
    /// Service account JSON content.
    pub service_account_json: String,
    /// Google Cloud project ID.
    pub project_id: String,
    /// Optional explicit managed zone name. If None, the provider will resolve the zone by longest suffix match.
    pub managed_zone: Option<String>,
    /// Whether to restrict to private zones only.
    pub private_zone: bool,
    /// Optional service account email to impersonate.
    pub impersonate_service_account: Option<String>,
    /// Optional request timeout.
    pub request_timeout: Option<Duration>,
}

/// Google Cloud DNS provider implementation.
#[derive(Clone)]
pub struct GoogleCloudDnsProvider {
    client: Client,
    config: GoogleCloudDnsConfig,
    token: Arc<Mutex<Option<(String, Instant)>>>,
    endpoints: GoogleCloudDnsEndpoints,
}

#[derive(Clone)]
struct GoogleCloudDnsEndpoints {
    dns_base_url: String,
    iam_base_url: String,
}

impl GoogleCloudDnsProvider {
    pub fn new(config: GoogleCloudDnsConfig) -> Result<Self> {
        let mut client_builder = Client::builder();
        if let Some(timeout) = config.request_timeout {
            client_builder = client_builder.timeout(timeout);
        }

        let client = client_builder
            .build()
            .map_err(|err| Error::Client(format!("Failed to build reqwest client: {err}")))?;

        Ok(Self {
            client,
            config,
            token: Arc::new(Mutex::new(None)),
            endpoints: GoogleCloudDnsEndpoints::default(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoints(
        mut self,
        dns_base_url: impl AsRef<str>,
        iam_base_url: impl AsRef<str>,
    ) -> Self {
        self.endpoints = GoogleCloudDnsEndpoints {
            dns_base_url: dns_base_url.as_ref().trim_end_matches('/').to_string(),
            iam_base_url: iam_base_url.as_ref().trim_end_matches('/').to_string(),
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

        let sa: ServiceAccount = serde_json::from_str(&self.config.service_account_json)
            .map_err(|e| Error::Api(format!("Failed to parse service account JSON: {}", e)))?;

        let jwt = create_jwt(
            &sa,
            "https://www.googleapis.com/auth/ndev.clouddns.readwrite",
        )
        .map_err(|e| Error::Api(format!("Failed to create JWT: {}", e)))?;
        let mut access_token = exchange_jwt_for_token(&sa.token_uri, &jwt)
            .await
            .map_err(|e| Error::Api(format!("Token exchange failed: {}", e)))?;

        if let Some(ref impersonate) = self.config.impersonate_service_account {
            access_token = self
                .impersonate_access_token(&access_token, impersonate)
                .await?;
        }

        let expiry = Instant::now() + Duration::from_secs(55 * 60);
        *self.token_lock()? = Some((access_token.clone(), expiry));
        Ok(access_token)
    }

    async fn resolve_managed_zone(&self, name: &str) -> Result<String> {
        if let Some(ref zone) = self.config.managed_zone {
            return Ok(zone.clone());
        }

        let token = self.ensure_token().await?;
        let url = format!(
            "{}/dns/v1/projects/{}/managedZones",
            self.endpoints.dns_base_url, self.config.project_id
        );

        let response = self
            .client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| Error::Api(format!("Failed to list managed zones: {}", e)))?;
        let resp: Value = self
            .parse_json_response(response, "Failed to parse zones list")
            .await?;

        let zones = resp
            .get("managedZones")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::Api("No managedZones field in response".into()))?;

        let mut best: Option<(String, usize)> = None;
        for zone in zones {
            if self.config.private_zone
                && zone.get("visibility").and_then(Value::as_str) != Some("private")
            {
                continue;
            }

            let dns_name = zone
                .get("dnsName")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Api("Zone missing dnsName".into()))?;
            let name_trim = name.trim_end_matches('.');
            let dns_trim = dns_name.trim_end_matches('.');
            if name_trim.ends_with(dns_trim) {
                let len = dns_trim.len();
                if best.as_ref().is_none_or(|(_, l)| len > *l) {
                    let zone_name = zone
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| Error::Api("Zone missing name".into()))?;
                    best = Some((zone_name.to_string(), len));
                }
            }
        }
        best.map(|(z, _)| z)
            .ok_or_else(|| Error::Api(format!("No matching managed zone for {}", name)))
    }

    fn record_to_rrset(&self, name: &str, record: &DnsRecord, ttl: u32) -> GoogleRrset {
        let rrdatas = match record {
            DnsRecord::A(ip) => vec![ip.to_string()],
            DnsRecord::AAAA(ip) => vec![ip.to_string()],
            DnsRecord::CNAME(c) => vec![format_fqdn_data(c)],
            DnsRecord::NS(ns) => vec![format_fqdn_data(ns)],
            DnsRecord::MX(mx) => vec![mx.to_string()],
            DnsRecord::TXT(txt) => vec![format!(
                "\"{}\"",
                txt.replace('\\', "\\\\").replace('"', "\\\"")
            )],
            DnsRecord::SRV(srv) => vec![srv.to_string()],
            DnsRecord::TLSA(tlsa) => vec![tlsa.to_string()],
            DnsRecord::CAA(caa) => {
                let (flags, tag, value) = caa.clone().decompose();
                vec![format!("{} {} \"{}\"", flags, tag, value)]
            }
        };

        GoogleRrset {
            name: format!("{}.", name.trim_end_matches('.')),
            r#type: record.as_type().to_string(),
            ttl,
            rrdatas,
        }
    }

    pub async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        let name = name.into_fqdn();
        let zone = self.resolve_managed_zone(&name).await?;
        let rrset = self.record_to_rrset(&name, &record, ttl);
        let token = self.ensure_token().await?;

        self.submit_change(
            &zone,
            &token,
            GoogleChange {
                additions: Some(vec![rrset]),
                deletions: None,
            },
        )
        .await
    }

    pub async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        let name = name.into_fqdn();
        let zone = self.resolve_managed_zone(&name).await?;
        let token = self.ensure_token().await?;
        let new_rrset = self.record_to_rrset(&name, &record, ttl);
        let existing = self
            .fetch_existing_rrset(&zone, &token, &name, record.as_type())
            .await?;

        self.submit_change(
            &zone,
            &token,
            GoogleChange {
                additions: Some(vec![new_rrset]),
                deletions: existing.map(|rrset| vec![rrset]),
            },
        )
        .await
    }

    pub async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        _origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> Result<()> {
        let name = name.into_fqdn();
        let zone = self.resolve_managed_zone(&name).await?;
        let token = self.ensure_token().await?;

        let Some(existing) = self
            .fetch_existing_rrset(&zone, &token, &name, record_type)
            .await?
        else {
            return Ok(());
        };

        self.submit_change(
            &zone,
            &token,
            GoogleChange {
                additions: None,
                deletions: Some(vec![existing]),
            },
        )
        .await
    }

    async fn fetch_existing_rrset(
        &self,
        zone: &str,
        token: &str,
        name: &str,
        record_type: DnsRecordType,
    ) -> Result<Option<Value>> {
        let query = serde_urlencoded::to_string([
            ("name", name),
            ("type", record_type_to_string_static(&record_type)),
        ])
        .map_err(|e| Error::Api(format!("Failed to encode RRSet query: {}", e)))?;
        let list_url = format!(
            "{}/dns/v1/projects/{}/managedZones/{}/rrsets?{}",
            self.endpoints.dns_base_url, self.config.project_id, zone, query
        );
        let response = self
            .client
            .get(&list_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| Error::Api(format!("List RRSet failed: {}", e)))?;
        let resp: Value = self
            .parse_json_response(response, "Parse RRSet list failed")
            .await?;
        let rrsets = resp
            .get("rrsets")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Api("No rrsets field in response".into()))?;

        if rrsets.is_empty() {
            return Ok(None);
        }

        if rrsets.len() > 1 {
            return Err(Error::Api(format!(
                "Multiple RRsets found for {} {}",
                name,
                record_type_to_string_static(&record_type)
            )));
        }

        Ok(rrsets.first().cloned())
    }

    async fn submit_change(&self, zone: &str, token: &str, change: GoogleChange) -> Result<()> {
        let url = format!(
            "{}/dns/v1/projects/{}/managedZones/{}/changes",
            self.endpoints.dns_base_url, self.config.project_id, zone
        );
        let response = self
            .client
            .post(&url)
            .bearer_auth(token)
            .json(&change)
            .send()
            .await
            .map_err(|e| Error::Api(format!("Change request failed: {}", e)))?;
        self.expect_success(response).await.map(|_| ())
    }

    pub(crate) async fn impersonate_access_token(
        &self,
        access_token: &str,
        impersonate: &str,
    ) -> Result<String> {
        let url = format!(
            "{}/v1/projects/-/serviceAccounts/{}:generateAccessToken",
            self.endpoints.iam_base_url, impersonate
        );

        #[derive(Serialize)]
        struct ImpersonateRequest {
            scope: Vec<String>,
            lifetime: String,
        }

        let body = ImpersonateRequest {
            scope: vec!["https://www.googleapis.com/auth/ndev.clouddns.readwrite".to_string()],
            lifetime: "3600s".to_string(),
        };

        let response = self
            .client
            .post(&url)
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Api(format!("Impersonation request failed: {}", e)))?;
        let resp: Value = self
            .parse_json_response(response, "Failed to parse impersonation response")
            .await?;

        if let Some(token) = resp.get("accessToken").and_then(Value::as_str) {
            if token.is_empty() {
                return Err(Error::Api(
                    "Impersonation returned an empty accessToken".into(),
                ));
            }

            Ok(token.to_string())
        } else {
            Err(Error::Api(
                "Impersonation did not return accessToken".into(),
            ))
        }
    }

    async fn expect_success(&self, response: reqwest::Response) -> Result<reqwest::Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        let body = response
            .text()
            .await
            .map_err(|e| Error::Api(format!("Failed to read error response: {e}")))?;

        match status.as_u16() {
            400 => Err(Error::BadRequest),
            401 | 403 => Err(Error::Unauthorized),
            404 => Err(Error::NotFound),
            _ => Err(Error::Api(api_error_message(&body))),
        }
    }

    async fn parse_json_response<T>(&self, response: reqwest::Response, context: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let response = self.expect_success(response).await?;
        response
            .json::<T>()
            .await
            .map_err(|e| Error::Api(format!("{}: {}", context, e)))
    }

    fn token_lock(&self) -> Result<std::sync::MutexGuard<'_, Option<(String, Instant)>>> {
        self.token
            .lock()
            .map_err(|_| Error::Client("Google Cloud DNS token cache lock poisoned".into()))
    }
}

/// Helper struct for Google RRSet JSON.
#[derive(Debug, Serialize, Deserialize)]
struct GoogleRrset {
    name: String,
    #[serde(rename = "type")]
    r#type: String,
    ttl: u32,
    rrdatas: Vec<String>,
}

#[derive(Debug, Serialize)]
struct GoogleChange {
    #[serde(skip_serializing_if = "Option::is_none")]
    additions: Option<Vec<GoogleRrset>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deletions: Option<Vec<Value>>,
}

impl Default for GoogleCloudDnsEndpoints {
    fn default() -> Self {
        Self {
            dns_base_url: "https://dns.googleapis.com".to_string(),
            iam_base_url: "https://iamcredentials.googleapis.com".to_string(),
        }
    }
}

fn record_type_to_string_static(rt: &DnsRecordType) -> &'static str {
    match rt {
        DnsRecordType::A => "A",
        DnsRecordType::AAAA => "AAAA",
        DnsRecordType::CNAME => "CNAME",
        DnsRecordType::MX => "MX",
        DnsRecordType::TXT => "TXT",
        DnsRecordType::SRV => "SRV",
        DnsRecordType::NS => "NS",
        DnsRecordType::TLSA => "TLSA",
        DnsRecordType::CAA => "CAA",
    }
}

fn format_fqdn_data(value: &str) -> String {
    format!("{}.", value.trim_end_matches('.'))
}

fn api_error_message(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|json| {
            json.get("error")
                .and_then(|error| error.get("message").or_else(|| error.get("status")))
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .or_else(|| {
                    json.get("error_description")
                        .and_then(Value::as_str)
                        .map(ToString::to_string)
                })
        })
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| body.to_string())
}
