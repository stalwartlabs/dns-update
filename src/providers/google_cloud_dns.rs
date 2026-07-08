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

use crate::http::{HttpClient, HttpClientBuilder};
use crate::jwt::{ServiceAccount, create_jwt, exchange_jwt_for_token};
use crate::utils::split_caa_value;
use crate::utils::txt_chunks_to_text;
use crate::utils::{
    decode_hex, tlsa_cert_usage_from_u8, tlsa_matching_from_u8, tlsa_selector_from_u8,
};
use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, Result, SRVRecord, TLSARecord,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::{Ipv4Addr, Ipv6Addr};
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
    client: HttpClient,
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
        let client = HttpClientBuilder::default()
            .with_timeout(config.request_timeout)
            .build();

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

        let resp: Value = self
            .client
            .get(&url)
            .with_header("authorization", format!("Bearer {token}"))
            .send_with_retry(3)
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

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        check_record_types(record_type, &records)?;
        let name = name.into_fqdn();
        let fqdn = format!("{}.", name.trim_end_matches('.'));
        let zone = self.resolve_managed_zone(&name).await?;
        let token = self.ensure_token().await?;
        let existing = self
            .fetch_existing_rrset(&zone, &token, &name, record_type)
            .await?;

        if records.is_empty() {
            let Some(existing) = existing else {
                return Ok(());
            };
            return self
                .submit_change(
                    &zone,
                    &token,
                    GoogleChange {
                        additions: None,
                        deletions: Some(vec![existing]),
                    },
                )
                .await;
        }

        let rrdatas = build_rrdatas(&records);
        let desired = GoogleRrset {
            name: fqdn,
            r#type: record_type.as_str().to_string(),
            ttl,
            rrdatas,
        };

        if let Some(ref current) = existing
            && rrset_matches(current, &desired)
        {
            return Ok(());
        }

        self.submit_change(
            &zone,
            &token,
            GoogleChange {
                additions: Some(vec![desired]),
                deletions: existing.map(|rrset| vec![rrset]),
            },
        )
        .await
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_fqdn();
        let fqdn = format!("{}.", name.trim_end_matches('.'));
        let zone = self.resolve_managed_zone(&name).await?;
        let token = self.ensure_token().await?;
        let existing = self
            .fetch_existing_rrset(&zone, &token, &name, record_type)
            .await?;

        let new_rrdatas = build_rrdatas(&records);
        let existing_rrdatas: Vec<String> = existing
            .as_ref()
            .and_then(|v| v.get("rrdatas").and_then(Value::as_array))
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        let mut union = existing_rrdatas.clone();
        for entry in &new_rrdatas {
            if !union.iter().any(|e| e == entry) {
                union.push(entry.clone());
            }
        }

        let existing_ttl = existing
            .as_ref()
            .and_then(|v| v.get("ttl").and_then(Value::as_u64))
            .map(|t| t as u32);

        if union == existing_rrdatas && existing_ttl == Some(ttl) {
            return Ok(());
        }

        let desired = GoogleRrset {
            name: fqdn,
            r#type: record_type.as_str().to_string(),
            ttl,
            rrdatas: union,
        };

        self.submit_change(
            &zone,
            &token,
            GoogleChange {
                additions: Some(vec![desired]),
                deletions: existing.map(|rrset| vec![rrset]),
            },
        )
        .await
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_fqdn();
        let fqdn = format!("{}.", name.trim_end_matches('.'));
        let zone = self.resolve_managed_zone(&name).await?;
        let token = self.ensure_token().await?;
        let Some(existing) = self
            .fetch_existing_rrset(&zone, &token, &name, record_type)
            .await?
        else {
            return Ok(());
        };

        let to_remove = build_rrdatas(&records);
        let existing_rrdatas: Vec<String> = existing
            .get("rrdatas")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        let filtered: Vec<String> = existing_rrdatas
            .iter()
            .filter(|e| !to_remove.iter().any(|r| r == *e))
            .cloned()
            .collect();

        if filtered == existing_rrdatas {
            return Ok(());
        }

        if filtered.is_empty() {
            return self
                .submit_change(
                    &zone,
                    &token,
                    GoogleChange {
                        additions: None,
                        deletions: Some(vec![existing]),
                    },
                )
                .await;
        }

        let existing_ttl = existing
            .get("ttl")
            .and_then(Value::as_u64)
            .map(|t| t as u32)
            .unwrap_or(0);

        let desired = GoogleRrset {
            name: fqdn,
            r#type: record_type.as_str().to_string(),
            ttl: existing_ttl,
            rrdatas: filtered,
        };

        self.submit_change(
            &zone,
            &token,
            GoogleChange {
                additions: Some(vec![desired]),
                deletions: Some(vec![existing]),
            },
        )
        .await
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _origin: impl IntoFqdn<'_>,
    ) -> Result<Vec<DnsRecord>> {
        let name = name.into_fqdn();
        let zone = self.resolve_managed_zone(&name).await?;
        let token = self.ensure_token().await?;
        let Some(existing) = self
            .fetch_existing_rrset(&zone, &token, &name, record_type)
            .await?
        else {
            return Ok(Vec::new());
        };

        let rrdatas = existing
            .get("rrdatas")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Api("RRSet missing rrdatas field".into()))?;

        let mut out = Vec::with_capacity(rrdatas.len());
        for entry in rrdatas {
            let text = entry
                .as_str()
                .ok_or_else(|| Error::Api("rrdatas entry is not a string".into()))?;
            out.push(parse_rrdata(record_type, text)?);
        }
        Ok(out)
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
        let resp: Value = self
            .client
            .get(&list_url)
            .with_header("authorization", format!("Bearer {token}"))
            .send_with_retry(3)
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
        self.client
            .post(&url)
            .with_header("authorization", format!("Bearer {token}"))
            .with_body(&change)?
            .send_with_retry::<Value>(3)
            .await
            .map(|_| ())
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

        let resp: Value = self
            .client
            .post(&url)
            .with_header("authorization", format!("Bearer {access_token}"))
            .with_body(&body)?
            .send_with_retry(3)
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
    rt.as_str()
}

fn format_fqdn_data(value: &str) -> String {
    format!("{}.", value.trim_end_matches('.'))
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> Result<()> {
    for r in records {
        if r.as_type() != expected {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected.as_str(),
                r.as_type().as_str(),
            )));
        }
    }
    Ok(())
}

fn build_rrdatas(records: &[DnsRecord]) -> Vec<String> {
    records.iter().map(rrdata_for_record).collect()
}

fn rrdata_for_record(record: &DnsRecord) -> String {
    match record {
        DnsRecord::A(ip) => ip.to_string(),
        DnsRecord::AAAA(ip) => ip.to_string(),
        DnsRecord::CNAME(c) => format_fqdn_data(c),
        DnsRecord::NS(ns) => format_fqdn_data(ns),
        DnsRecord::MX(mx) => format!("{} {}.", mx.priority, mx.exchange.trim_end_matches('.')),
        DnsRecord::TXT(txt) => {
            let mut rdata = String::new();
            txt_chunks_to_text(&mut rdata, txt, " ");
            rdata
        }
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}.",
            srv.priority,
            srv.weight,
            srv.port,
            srv.target.trim_end_matches('.')
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            format!("{} {} \"{}\"", flags, tag, value)
        }
    }
}

fn rrset_matches(current: &Value, desired: &GoogleRrset) -> bool {
    let current_name = current.get("name").and_then(Value::as_str).unwrap_or("");
    let current_type = current.get("type").and_then(Value::as_str).unwrap_or("");
    let current_ttl = current
        .get("ttl")
        .and_then(Value::as_u64)
        .map(|t| t as u32)
        .unwrap_or(0);
    let current_rrdatas: Vec<&str> = current
        .get("rrdatas")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    current_name == desired.name
        && current_type == desired.r#type
        && current_ttl == desired.ttl
        && current_rrdatas.len() == desired.rrdatas.len()
        && current_rrdatas
            .iter()
            .zip(desired.rrdatas.iter())
            .all(|(a, b)| *a == b.as_str())
}

fn parse_rrdata(record_type: DnsRecordType, text: &str) -> Result<DnsRecord> {
    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(
            text.parse::<Ipv4Addr>()
                .map_err(|e| Error::Parse(format!("Invalid A rrdata '{text}': {e}")))?,
        ),
        DnsRecordType::AAAA => DnsRecord::AAAA(
            text.parse::<Ipv6Addr>()
                .map_err(|e| Error::Parse(format!("Invalid AAAA rrdata '{text}': {e}")))?,
        ),
        DnsRecordType::CNAME => DnsRecord::CNAME(text.trim_end_matches('.').to_string()),
        DnsRecordType::NS => DnsRecord::NS(text.trim_end_matches('.').to_string()),
        DnsRecordType::MX => {
            let (prio, exchange) = text
                .split_once(' ')
                .ok_or_else(|| Error::Parse(format!("Invalid MX rrdata '{text}'")))?;
            let priority = prio
                .parse::<u16>()
                .map_err(|e| Error::Parse(format!("Invalid MX priority '{prio}': {e}")))?;
            DnsRecord::MX(MXRecord {
                priority,
                exchange: exchange.trim().trim_end_matches('.').to_string(),
            })
        }
        DnsRecordType::TXT => DnsRecord::TXT(parse_txt_rrdata(text)),
        DnsRecordType::SRV => {
            let mut parts = text.split_whitespace();
            let priority = parts
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .ok_or_else(|| Error::Parse(format!("Invalid SRV priority in '{text}'")))?;
            let weight = parts
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .ok_or_else(|| Error::Parse(format!("Invalid SRV weight in '{text}'")))?;
            let port = parts
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .ok_or_else(|| Error::Parse(format!("Invalid SRV port in '{text}'")))?;
            let target = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("Invalid SRV target in '{text}'")))?;
            DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target: target.trim_end_matches('.').to_string(),
            })
        }
        DnsRecordType::TLSA => {
            let mut parts = text.split_whitespace();
            let usage = parts
                .next()
                .and_then(|p| p.parse::<u8>().ok())
                .ok_or_else(|| Error::Parse(format!("Invalid TLSA usage in '{text}'")))?;
            let selector = parts
                .next()
                .and_then(|p| p.parse::<u8>().ok())
                .ok_or_else(|| Error::Parse(format!("Invalid TLSA selector in '{text}'")))?;
            let matching = parts
                .next()
                .and_then(|p| p.parse::<u8>().ok())
                .ok_or_else(|| Error::Parse(format!("Invalid TLSA matching in '{text}'")))?;
            let hex = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("Invalid TLSA cert data in '{text}'")))?;
            DnsRecord::TLSA(TLSARecord {
                cert_usage: tlsa_cert_usage_from_u8(usage)?,
                selector: tlsa_selector_from_u8(selector)?,
                matching: tlsa_matching_from_u8(matching)?,
                cert_data: decode_hex(hex)?,
            })
        }
        DnsRecordType::CAA => parse_caa_rrdata(text)?,
    })
}

fn parse_txt_rrdata(text: &str) -> String {
    let mut out = String::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push(bytes[i + 1] as char);
                    i += 2;
                } else {
                    out.push(bytes[i] as char);
                    i += 1;
                }
            }
            if i < bytes.len() {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    if out.is_empty() {
        text.to_string()
    } else {
        out
    }
}

fn parse_caa_rrdata(text: &str) -> Result<DnsRecord> {
    let mut parts = text.splitn(3, ' ');
    let flags = parts
        .next()
        .and_then(|p| p.parse::<u8>().ok())
        .ok_or_else(|| Error::Parse(format!("Invalid CAA flags in '{text}'")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("Invalid CAA tag in '{text}'")))?;
    let value_raw = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("Invalid CAA value in '{text}'")))?;
    let value = value_raw.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(value)
        .to_string();
    let issuer_critical = flags & 0x80 != 0;

    Ok(DnsRecord::CAA(match tag {
        "issue" => {
            let (name, options) = split_caa_value(&value);
            CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }
        }
        "issuewild" => {
            let (name, options) = split_caa_value(&value);
            CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            }
        }
        "iodef" => CAARecord::Iodef {
            issuer_critical,
            url: value,
        },
        other => {
            return Err(Error::Parse(format!("unknown CAA tag: {other}")));
        }
    }))
}
