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
    strip_origin_from_name, ApiCacheFetcher, ApiCacheManager, DnsRecord, DnsRecordTrait, Error,
    IntoFqdn,
};
use reqwest::Method;
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::{
    hash::{Hash, Hasher},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct OvhProvider {
    data: OvhData,
    record_cache: ApiCacheManager<u64>,
}

#[derive(Clone)]
pub struct OvhData {
    application_key: String,
    application_secret: String,
    consumer_key: String,
    pub(crate) endpoint: String,
    timeout: Duration,
}

struct OvhRecordFetcher<'a> {
    data: &'a OvhData,
    zone: &'a str,
    name: &'a str,
    record_type: &'a str,
}

#[derive(Serialize, Debug)]
pub struct CreateDnsRecordParams {
    #[serde(rename = "fieldType")]
    pub field_type: String,
    #[serde(rename = "subDomain")]
    pub sub_domain: String,
    pub target: String,
    pub ttl: u32,
}

#[derive(Serialize, Debug)]
pub struct UpdateDnsRecordParams {
    pub target: String,
    pub ttl: u32,
}

#[derive(Debug)]
pub struct OvhRecordFormat {
    pub field_type: String,
    pub target: String,
}

#[derive(Debug)]
pub enum OvhEndpoint {
    OvhEu,
    OvhCa,
    KimsufiEu,
    KimsufiCa,
    SoyoustartEu,
    SoyoustartCa,
}

impl OvhEndpoint {
    fn api_url(&self) -> &'static str {
        match self {
            OvhEndpoint::OvhEu => "https://eu.api.ovh.com/1.0",
            OvhEndpoint::OvhCa => "https://ca.api.ovh.com/1.0",
            OvhEndpoint::KimsufiEu => "https://eu.api.kimsufi.com/1.0",
            OvhEndpoint::KimsufiCa => "https://ca.api.kimsufi.com/1.0",
            OvhEndpoint::SoyoustartEu => "https://eu.api.soyoustart.com/1.0",
            OvhEndpoint::SoyoustartCa => "https://ca.api.soyoustart.com/1.0",
        }
    }
}

impl std::str::FromStr for OvhEndpoint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ovh-eu" => Ok(OvhEndpoint::OvhEu),
            "ovh-ca" => Ok(OvhEndpoint::OvhCa),
            "kimsufi-eu" => Ok(OvhEndpoint::KimsufiEu),
            "kimsufi-ca" => Ok(OvhEndpoint::KimsufiCa),
            "soyoustart-eu" => Ok(OvhEndpoint::SoyoustartEu),
            "soyoustart-ca" => Ok(OvhEndpoint::SoyoustartCa),
            _ => Err(Error::Parse(format!("Invalid OVH endpoint: {}", s))),
        }
    }
}

impl From<&DnsRecord> for OvhRecordFormat {
    fn from(record: &DnsRecord) -> Self {
        let (target, ftype) = record.fmt_ovh_desec();
        let field_type = ftype.to_string();
        OvhRecordFormat { target, field_type }
    }
}

impl OvhData {
    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    fn generate_signature(&self, method: &str, url: &str, body: &str, timestamp: u64) -> String {
        let data = format!(
            "{}+{}+{}+{}+{}+{}",
            self.application_secret, self.consumer_key, method, url, body, timestamp
        );

        let mut hasher = Sha1::new();
        hasher.update(data.as_bytes());
        let hash = hasher.finalize();
        let hex_string = hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        format!("$1${}", hex_string)
    }

    async fn send_authenticated_request(
        &self,
        method: Method,
        url: &str,
        body: &str,
    ) -> crate::Result<reqwest::Response> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Client(format!("Failed to get timestamp: {}", e)))?
            .as_secs();

        let signature = self.generate_signature(method.as_str(), url, body, timestamp);

        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| Error::Client(format!("Failed to create HTTP client: {}", e)))?;
        let mut request = client
            .request(method, url)
            .header("X-Ovh-Application", &self.application_key)
            .header("X-Ovh-Consumer", &self.consumer_key)
            .header("X-Ovh-Signature", signature)
            .header("X-Ovh-Timestamp", timestamp.to_string())
            .header("Content-Type", "application/json");

        if !body.is_empty() {
            request = request.body(body.to_string());
        }

        request
            .send()
            .await
            .map_err(|e| Error::Api(format!("Failed to send request: {}", e)))
    }

    async fn get_zone_name(&self, origin: impl IntoFqdn<'_>) -> crate::Result<String> {
        let domain = origin.into_name();
        let domain_name = domain.trim_end_matches('.');

        let url = format!("{}/domain/zone/{}", self.endpoint, domain_name);
        let response = self
            .send_authenticated_request(Method::GET, &url, "")
            .await?;

        if response.status().is_success() {
            Ok(domain_name.to_string())
        } else {
            Err(Error::Api(format!(
                "Zone {} not found or not accessible",
                domain_name
            )))
        }
    }
}

impl<'a> ApiCacheFetcher<u64> for OvhRecordFetcher<'a> {
    async fn fetch_api_response(&mut self) -> crate::Result<u64> {
        let name = self.name.into_name(); // uses IntoFqdn
        let subdomain = strip_origin_from_name(&name, self.zone);
        let subdomain = if subdomain == "@" { "" } else { &subdomain };

        let url = format!(
            "{}/domain/zone/{}/record?fieldType={}&subDomain={}",
            self.data.endpoint, self.zone, self.record_type, subdomain
        );

        let response = self
            .data
            .send_authenticated_request(Method::GET, &url, "")
            .await?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "Failed to list records: HTTP {}",
                response.status()
            )));
        }

        let record_ids: Vec<u64> = serde_json::from_slice(
            response
                .bytes()
                .await
                .map_err(|e| Error::Api(format!("Failed to fetch record list: {}", e)))?
                .as_ref(),
        )
        .map_err(|e| Error::Api(format!("Failed to parse record list: {}", e)))?;

        record_ids.into_iter().next().ok_or(Error::NotFound)
    }
}

impl Hash for OvhRecordFetcher<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.zone.hash(state);
        self.name.hash(state);
        self.record_type.hash(state);
    }
}

impl OvhProvider {
    pub(crate) fn new(
        application_key: impl AsRef<str>,
        application_secret: impl AsRef<str>,
        consumer_key: impl AsRef<str>,
        endpoint: OvhEndpoint,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let data = OvhData {
            application_key: application_key.as_ref().to_string(),
            application_secret: application_secret.as_ref().to_string(),
            consumer_key: consumer_key.as_ref().to_string(),
            endpoint: endpoint.api_url().to_string(),
            timeout: timeout.unwrap_or(Duration::from_secs(30)),
        };
        Ok(Self {
            data,
            record_cache: ApiCacheManager::default(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        let data = self.data.with_endpoint(endpoint);
        Self { data, ..self }
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let zone = self.data.get_zone_name(origin).await?;
        let name = name.into_name();
        let subdomain = strip_origin_from_name(&name, &zone);
        let subdomain = if subdomain == "@" {
            String::new()
        } else {
            subdomain
        };

        let ovh_record: OvhRecordFormat = (&record).into();
        let (field_type, target) = (ovh_record.field_type, ovh_record.target);

        let params = CreateDnsRecordParams {
            field_type,
            sub_domain: subdomain,
            target,
            ttl,
        };

        let body = serde_json::to_string(&params)
            .map_err(|e| Error::Serialize(format!("Failed to serialize record: {}", e)))?;

        let url = format!("{}/domain/zone/{}/record", self.data.endpoint, zone);
        let response = self
            .data
            .send_authenticated_request(Method::POST, &url, &body)
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Api(format!(
                "Failed to create record: HTTP {} - {}",
                status, error_text
            )));
        }

        let url = format!("{}/domain/zone/{}/refresh", self.data.endpoint, zone);
        let _response = self
            .data
            .send_authenticated_request(Method::POST, &url, "")
            .await
            .map_err(|e| {
                Error::Api(format!(
                    "Failed to refresh zone (record created but zone not refreshed): {:?}",
                    e
                ))
            })?;

        Ok(())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let zone = self.data.get_zone_name(origin).await?;
        let name = name.into_name();

        let ovh_record: OvhRecordFormat = (&record).into();
        let (field_type, target) = (ovh_record.field_type, ovh_record.target);

        let record_id = self
            .record_cache
            .get_or_update(&mut OvhRecordFetcher {
                data: &self.data,
                zone: zone.as_ref(),
                name: name.as_ref(),
                record_type: field_type.as_ref(),
            })
            .await?;

        let params = UpdateDnsRecordParams { target, ttl };

        let body = serde_json::to_string(&params)
            .map_err(|e| Error::Serialize(format!("Failed to serialize record: {}", e)))?;

        let url = format!(
            "{}/domain/zone/{}/record/{}",
            self.data.endpoint, zone, record_id
        );
        let response = self
            .data
            .send_authenticated_request(Method::PUT, &url, &body)
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Api(format!(
                "Failed to update record: HTTP {} - {}",
                status, error_text
            )));
        }

        let url = format!("{}/domain/zone/{}/refresh", self.data.endpoint, zone);
        let _response = self
            .data
            .send_authenticated_request(Method::POST, &url, "")
            .await
            .map_err(|e| {
                Error::Api(format!(
                    "Failed to refresh zone (record updated but zone not refreshed): {:?}",
                    e
                ))
            })?;

        Ok(())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: crate::DnsRecordType,
    ) -> crate::Result<()> {
        let zone = self.data.get_zone_name(origin).await?;
        let record_id = self
            .record_cache
            .get_or_update(&mut OvhRecordFetcher {
                data: &self.data,
                zone: zone.as_ref(),
                name: name.into_name().as_ref(),
                record_type: &record_type.to_string(),
            })
            .await?;

        let url = format!(
            "{}/domain/zone/{}/record/{}",
            self.data.endpoint, zone, record_id
        );
        let response = self
            .data
            .send_authenticated_request(Method::DELETE, &url, "")
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Api(format!(
                "Failed to delete record: HTTP {} - {}",
                status, error_text
            )));
        }

        let url = format!("{}/domain/zone/{}/refresh", self.data.endpoint, zone);
        let _response = self
            .data
            .send_authenticated_request(Method::POST, &url, "")
            .await
            .map_err(|e| {
                Error::Api(format!(
                    "Failed to refresh zone (record deleted but zone not refreshed): {:?}",
                    e
                ))
            })?;

        Ok(())
    }
}
