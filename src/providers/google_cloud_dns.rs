use crate::jwt::{ServiceAccount, create_jwt, exchange_jwt_for_token};
use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, Result};
use hex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
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
    // Cached access token and its expiry instant.
    token: Arc<Mutex<Option<(String, Instant)>>>,
}

impl GoogleCloudDnsProvider {
    pub fn new(config: GoogleCloudDnsConfig) -> Self {
        let client_builder = Client::builder();
        let client = if let Some(to) = config.request_timeout {
            client_builder
                .timeout(to)
                .build()
                .expect("Failed to build reqwest client")
        } else {
            client_builder
                .build()
                .expect("Failed to build reqwest client")
        };
        Self {
            client,
            config,
            token: Arc::new(Mutex::new(None)),
        }
    }

    /// Ensure a valid access token is available, refreshing if needed.
    async fn ensure_token(&self) -> Result<String> {
        // Check cached token.
        if let Some((ref token, expiry)) = *self.token.lock().unwrap() {
            if Instant::now() < expiry {
                return Ok(token.clone());
            }
        }
        // Parse service account JSON.
        let sa: ServiceAccount = serde_json::from_str(&self.config.service_account_json)
            .map_err(|e| Error::Api(format!("Failed to parse service account JSON: {}", e)))?;
        // Create JWT with required scope.
        let jwt = create_jwt(
            &sa,
            "https://www.googleapis.com/auth/ndev.clouddns.readwrite",
        )
        .map_err(|e| Error::Api(format!("Failed to create JWT: {}", e)))?;
        // Exchange for access token.
        let mut access_token = exchange_jwt_for_token(&sa.token_uri, &jwt)
            .await
            .map_err(|e| Error::Api(format!("Token exchange failed: {}", e)))?;
        // If impersonation requested, obtain impersonated token.
        if let Some(ref impersonate) = self.config.impersonate_service_account {
            // IAMCredentials endpoint.
            let url = format!(
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{}:generateAccessToken",
                impersonate
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
            let resp: serde_json::Value = self
                .client
                .post(&url)
                .bearer_auth(&access_token)
                .json(&body)
                .send()
                .await
                .map_err(|e| Error::Api(format!("Impersonation request failed: {}", e)))?
                .json()
                .await
                .map_err(|e| {
                    Error::Api(format!("Failed to parse impersonation response: {}", e))
                })?;
            if let Some(tok) = resp.get("accessToken") {
                access_token = tok.as_str().unwrap_or_default().to_string();
            } else {
                return Err(Error::Api(
                    "Impersonation did not return accessToken".into(),
                ));
            }
        }
        // Cache token for ~55 minutes (Google tokens are valid 1h).
        let expiry = Instant::now() + Duration::from_secs(55 * 60);
        *self.token.lock().unwrap() = Some((access_token.clone(), expiry));
        Ok(access_token)
    }

    /// Resolve managed zone name. If config.managed_zone is set, use it; otherwise perform longest suffix match.
    async fn resolve_managed_zone(&self, name: &str) -> Result<String> {
        if let Some(ref zone) = self.config.managed_zone {
            return Ok(zone.clone());
        }
        // List zones.
        let token = self.ensure_token().await?;
        let url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones",
            self.config.project_id
        );
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| Error::Api(format!("Failed to list managed zones: {}", e)))?
            .json()
            .await
            .map_err(|e| Error::Api(format!("Failed to parse zones list: {}", e)))?;
        let zones = resp
            .get("managedZones")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::Api("No managedZones field in response".into()))?;
        // Find longest suffix match.
        let mut best: Option<(String, usize)> = None;
        for zone in zones {
            let dns_name = zone
                .get("dnsName")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Api("Zone missing dnsName".into()))?;
            let name_trim = name.trim_end_matches('.');
            let dns_trim = dns_name.trim_end_matches('.');
            if name_trim.ends_with(dns_trim) {
                let len = dns_trim.len();
                if best.as_ref().map_or(true, |(_, l)| len > *l) {
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

    /// Convert DnsRecord to Google RRSet JSON representation.
    fn record_to_rrset(&self, name: &str, record: &DnsRecord, ttl: u32) -> Result<GoogleRrset> {
        let rrdatas = match record {
            DnsRecord::A(ip) => vec![ip.to_string()],
            DnsRecord::AAAA(ip) => vec![ip.to_string()],
            DnsRecord::CNAME(c) => vec![c.clone()],
            DnsRecord::NS(ns) => vec![ns.clone()],
            DnsRecord::MX(mx) => vec![format!("{} {}", mx.priority, mx.exchange)],
            DnsRecord::TXT(txt) => vec![txt.clone()],
            DnsRecord::SRV(srv) => vec![format!(
                "{} {} {} {}",
                srv.priority, srv.weight, srv.port, srv.target
            )],
            DnsRecord::TLSA(tlsa) => {
                let cert_data = hex::encode(&tlsa.cert_data);
                vec![format!(
                    "{} {} {} {}",
                    tlsa.cert_usage as u8, tlsa.selector as u8, tlsa.matching as u8, cert_data
                )]
            }
            DnsRecord::CAA(caa) => {
                // Format: "flags tag value"
                let (flags, tag, value) = match caa {
                    crate::CAARecord::Issue {
                        issuer_critical,
                        name,
                        options,
                    } => {
                        let flags = if *issuer_critical { 128 } else { 0 };
                        let mut value = name.clone().unwrap_or_default();
                        for kv in options {
                            value.push_str(&format!("; {}={}", kv.key, kv.value));
                        }
                        (
                            flags,
                            "issue",
                            format!("\"{}\"", value.trim_start_matches("; ")),
                        )
                    }
                    crate::CAARecord::IssueWild {
                        issuer_critical,
                        name,
                        options,
                    } => {
                        let flags = if *issuer_critical { 128 } else { 0 };
                        let mut value = name.clone().unwrap_or_default();
                        for kv in options {
                            value.push_str(&format!("; {}={}", kv.key, kv.value));
                        }
                        (
                            flags,
                            "issuewild",
                            format!("\"{}\"", value.trim_start_matches("; ")),
                        )
                    }
                    crate::CAARecord::Iodef {
                        issuer_critical,
                        url,
                    } => {
                        let flags = if *issuer_critical { 128 } else { 0 };
                        (flags, "iodef", format!("\"{}\"", url))
                    }
                };
                vec![format!("{} {} {}", flags, tag, value)]
            }
        };
        Ok(GoogleRrset {
            name: format!("{}.", name.trim_end_matches('.')),
            r#type: self.record_type_to_string(record),
            ttl,
            rrdatas,
        })
    }

    fn record_type_to_string(&self, record: &DnsRecord) -> String {
        match record {
            DnsRecord::A(_) => "A".to_string(),
            DnsRecord::AAAA(_) => "AAAA".to_string(),
            DnsRecord::CNAME(_) => "CNAME".to_string(),
            DnsRecord::MX(_) => "MX".to_string(),
            DnsRecord::TXT(_) => "TXT".to_string(),
            DnsRecord::SRV(_) => "SRV".to_string(),
            DnsRecord::NS(_) => "NS".to_string(),
            DnsRecord::TLSA(_) => "TLSA".to_string(),
            DnsRecord::CAA(_) => "CAA".to_string(),
        }
    }

    /// Create a new DNS record.
    pub async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        let name = name.into_fqdn();
        let zone = self.resolve_managed_zone(&name).await?;
        let rrset = self.record_to_rrset(&name, &record, ttl)?;
        let token = self.ensure_token().await?;
        let url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/changes",
            self.config.project_id, zone
        );
        #[derive(Serialize)]
        struct Change {
            additions: Vec<GoogleRrset>,
        }
        let change = Change {
            additions: vec![rrset],
        };
        self.client
            .post(&url)
            .bearer_auth(&token)
            .json(&change)
            .send()
            .await
            .map_err(|e| Error::Api(format!("Create request failed: {}", e)))?;
        Ok(())
    }

    /// Update (upsert) a DNS record.
    pub async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        let name_str = name.into_fqdn().into_owned();
        let origin_str = _origin.into_fqdn().into_owned();
        // Google DNS does not have explicit upsert; we perform delete then add.
        self.delete(
            name_str.clone(),
            origin_str.clone(),
            self.get_record_type(&record),
        )
        .await?;
        self.create(name_str, record, ttl, origin_str).await
    }

    /// Delete a DNS record.
    pub async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        _origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> Result<()> {
        let name = name.into_fqdn();
        let zone = self.resolve_managed_zone(&name).await?;
        let token = self.ensure_token().await?;
        // Fetch existing RRSet.
        let list_url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/rrsets?name={}&type={}",
            self.config.project_id,
            zone,
            name,
            record_type_to_string_static(&record_type)
        );
        let resp: serde_json::Value = self
            .client
            .get(&list_url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| Error::Api(format!("List RRSet failed: {}", e)))?
            .json()
            .await
            .map_err(|e| Error::Api(format!("Parse RRSet list failed: {}", e)))?;
        let rrsets = resp
            .get("rrsets")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::Api("No rrsets field in response".into()))?;
        if rrsets.is_empty() {
            // Idempotent delete.
            return Ok(());
        }
        if rrsets.len() > 1 {
            return Err(Error::Api(format!(
                "Multiple RRsets found for {} {}",
                name,
                record_type_to_string_static(&record_type)
            )));
        }
        let rrset_json = &rrsets[0];
        // Build deletion change.
        let delete_change = rrset_json.clone();
        #[derive(Serialize)]
        struct DeleteChange {
            deletions: Vec<serde_json::Value>,
        }
        let change = DeleteChange {
            deletions: vec![delete_change],
        };
        let change_url = format!(
            "https://dns.googleapis.com/dns/v1/projects/{}/managedZones/{}/changes",
            self.config.project_id, zone
        );
        self.client
            .post(&change_url)
            .bearer_auth(&token)
            .json(&change)
            .send()
            .await
            .map_err(|e| Error::Api(format!("Delete request failed: {}", e)))?;
        Ok(())
    }

    fn get_record_type(&self, record: &DnsRecord) -> DnsRecordType {
        match record {
            DnsRecord::A(_) => DnsRecordType::A,
            DnsRecord::AAAA(_) => DnsRecordType::AAAA,
            DnsRecord::CNAME(_) => DnsRecordType::CNAME,
            DnsRecord::MX(_) => DnsRecordType::MX,
            DnsRecord::TXT(_) => DnsRecordType::TXT,
            DnsRecord::SRV(_) => DnsRecordType::SRV,
            DnsRecord::NS(_) => DnsRecordType::NS,
            DnsRecord::TLSA(_) => DnsRecordType::TLSA,
            DnsRecord::CAA(_) => DnsRecordType::CAA,
        }
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
