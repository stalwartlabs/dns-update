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

use crate::crypto::sha256_digest;
use crate::jwt::{parse_rsa_pkcs8_pem, rsa_sha256_sign};
use crate::utils::txt_chunks_to_text;
use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::Utc;
use reqwest::Method;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "ring")]
use ring::signature::RsaKeyPair;

#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
use aws_lc_rs::signature::RsaKeyPair;

#[derive(Debug, Clone)]
pub struct OracleCloudConfig {
    pub tenancy_ocid: String,
    pub user_ocid: String,
    pub fingerprint: String,
    pub private_key_pem: String,
    pub private_key_password: Option<String>,
    pub region: String,
    pub compartment_ocid: String,
    pub request_timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct OracleCloudProvider {
    config: OracleCloudConfig,
    key_pair: Arc<RsaKeyPair>,
    endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct OciRecord {
    domain: String,
    rtype: String,
    rdata: String,
    ttl: u32,
    #[serde(rename = "isProtected", skip_serializing_if = "Option::is_none")]
    is_protected: Option<bool>,
    #[serde(rename = "recordHash", skip_serializing_if = "Option::is_none")]
    record_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct UpdateRecordsRequest {
    items: Vec<OciRecord>,
}

#[derive(Debug, Deserialize)]
struct RecordCollection {
    items: Vec<OciRecord>,
}

#[derive(Debug, Deserialize)]
struct Zone {
    name: String,
    id: String,
}

impl OracleCloudProvider {
    pub(crate) fn new(config: OracleCloudConfig) -> Result<Self> {
        if config.tenancy_ocid.is_empty() {
            return Err(Error::Client("tenancy_ocid is required".into()));
        }
        if config.user_ocid.is_empty() {
            return Err(Error::Client("user_ocid is required".into()));
        }
        if config.fingerprint.is_empty() {
            return Err(Error::Client("fingerprint is required".into()));
        }
        if config.region.is_empty() {
            return Err(Error::Client("region is required".into()));
        }
        if config.compartment_ocid.is_empty() {
            return Err(Error::Client("compartment_ocid is required".into()));
        }
        if config
            .private_key_password
            .as_ref()
            .is_some_and(|p| !p.is_empty())
        {
            return Err(Error::Api(
                "OCI private keys with a passphrase are not supported".into(),
            ));
        }

        let key_pair = parse_rsa_pkcs8_pem(&config.private_key_pem).map_err(|e| {
            Error::Client(format!("Failed to parse OCI private key: {}", e))
        })?;

        let endpoint = format!("https://dns.{}.oraclecloud.com", config.region);

        Ok(Self {
            config,
            key_pair: Arc::new(key_pair),
            endpoint,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into().trim_end_matches('/').to_string();
        self
    }

    fn key_id(&self) -> String {
        format!(
            "{}/{}/{}",
            self.config.tenancy_ocid, self.config.user_ocid, self.config.fingerprint
        )
    }

    fn sign_request(
        &self,
        method: &Method,
        url: &str,
        body: Option<&str>,
    ) -> Result<HeaderMap> {
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| Error::Client(format!("Failed to parse URL {}: {}", url, e)))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| Error::Client(format!("URL missing host: {}", url)))?
            .to_string();
        let host_header = if let Some(port) = parsed.port() {
            format!("{}:{}", host, port)
        } else {
            host.clone()
        };
        let mut path_and_query = parsed.path().to_string();
        if let Some(q) = parsed.query() {
            path_and_query.push('?');
            path_and_query.push_str(q);
        }

        let method_lower = method.as_str().to_lowercase();
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

        let mut signed_pairs: Vec<(String, String)> = Vec::new();
        signed_pairs.push((
            "(request-target)".to_string(),
            format!("{} {}", method_lower, path_and_query),
        ));
        signed_pairs.push(("host".to_string(), host_header.clone()));
        signed_pairs.push(("date".to_string(), date.clone()));

        let needs_body_headers = matches!(*method, Method::POST | Method::PUT | Method::PATCH);
        let body_bytes = body.unwrap_or("").as_bytes();
        let content_sha256 = B64.encode(sha256_digest(body_bytes));
        let content_length = body_bytes.len().to_string();
        if needs_body_headers {
            signed_pairs.push(("x-content-sha256".to_string(), content_sha256.clone()));
            signed_pairs.push(("content-type".to_string(), "application/json".to_string()));
            signed_pairs.push(("content-length".to_string(), content_length.clone()));
        }

        let signing_string = signed_pairs
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect::<Vec<_>>()
            .join("\n");
        let signature = rsa_sha256_sign(&self.key_pair, signing_string.as_bytes())
            .map_err(|e| Error::Client(format!("Failed to sign request: {}", e)))?;
        let signature_b64 = B64.encode(&signature);

        let headers_list = signed_pairs
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let authorization = format!(
            "Signature version=\"1\",keyId=\"{}\",algorithm=\"rsa-sha256\",headers=\"{}\",signature=\"{}\"",
            self.key_id(),
            headers_list,
            signature_b64,
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_str(&host_header)
                .map_err(|e| Error::Client(format!("Invalid host header: {}", e)))?,
        );
        headers.insert(
            "date",
            HeaderValue::from_str(&date)
                .map_err(|e| Error::Client(format!("Invalid date header: {}", e)))?,
        );
        headers.insert(
            "authorization",
            HeaderValue::from_str(&authorization)
                .map_err(|e| Error::Client(format!("Invalid authorization header: {}", e)))?,
        );
        if needs_body_headers {
            headers.insert(
                "x-content-sha256",
                HeaderValue::from_str(&content_sha256)
                    .map_err(|e| Error::Client(format!("Invalid x-content-sha256: {}", e)))?,
            );
            headers.insert(
                "content-type",
                HeaderValue::from_static("application/json"),
            );
            headers.insert(
                "content-length",
                HeaderValue::from_str(&content_length)
                    .map_err(|e| Error::Client(format!("Invalid content-length: {}", e)))?,
            );
        }

        Ok(headers)
    }

    async fn send_signed(
        &self,
        method: Method,
        url: &str,
        body: Option<String>,
    ) -> Result<(reqwest::StatusCode, String)> {
        let headers = self.sign_request(&method, url, body.as_deref())?;
        let client = reqwest::Client::builder()
            .timeout(self.config.request_timeout.unwrap_or(Duration::from_secs(30)))
            .build()
            .map_err(|e| Error::Client(format!("Failed to build HTTP client: {}", e)))?;

        let mut request = client.request(method, url).headers(headers);
        if let Some(b) = body {
            request = request.body(b);
        }

        let response = request
            .send()
            .await
            .map_err(|e| Error::Api(format!("Failed to send request to {}: {}", url, e)))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| Error::Api(format!("Failed to read response body: {}", e)))?;
        Ok((status, text))
    }

    fn record_to_rdata(record: &DnsRecord) -> Result<(String, String)> {
        let (rtype, rdata) = match record {
            DnsRecord::A(ip) => ("A".to_string(), ip.to_string()),
            DnsRecord::AAAA(ip) => ("AAAA".to_string(), ip.to_string()),
            DnsRecord::CNAME(c) => ("CNAME".to_string(), format_target(c)),
            DnsRecord::NS(n) => ("NS".to_string(), format_target(n)),
            DnsRecord::MX(mx) => (
                "MX".to_string(),
                format!("{} {}", mx.priority, format_target(&mx.exchange)),
            ),
            DnsRecord::TXT(txt) => {
                let mut rdata = String::new();
                txt_chunks_to_text(&mut rdata, txt, " ");
                ("TXT".to_string(), rdata)
            }
            DnsRecord::SRV(srv) => (
                "SRV".to_string(),
                format!(
                    "{} {} {} {}",
                    srv.priority,
                    srv.weight,
                    srv.port,
                    format_target(&srv.target)
                ),
            ),
            DnsRecord::CAA(caa) => {
                let (flags, tag, value) = caa.clone().decompose();
                ("CAA".to_string(), format!("{} {} \"{}\"", flags, tag, value))
            }
            DnsRecord::TLSA(_) => {
                return Err(Error::Api(
                    "TLSA records are not supported by Oracle Cloud DNS".into(),
                ));
            }
        };
        Ok((rtype, rdata))
    }

    async fn resolve_zone(&self, origin: &str) -> Result<String> {
        let trimmed = origin.trim_end_matches('.');
        let url = format!(
            "{}/20180115/zones?compartmentId={}&name={}",
            self.endpoint,
            urlencode(&self.config.compartment_ocid),
            urlencode(trimmed),
        );
        let (status, body) = self.send_signed(Method::GET, &url, None).await?;
        if !status.is_success() {
            return Err(map_error(status, &body));
        }
        let zones: Vec<Zone> = serde_json::from_str(&body)
            .map_err(|e| Error::Serialize(format!("Failed to parse zones list: {}", e)))?;
        zones
            .into_iter()
            .find(|z| z.name.trim_end_matches('.') == trimmed)
            .map(|z| z.id)
            .ok_or_else(|| Error::Api(format!("Zone not found for {}", origin)))
    }

    fn records_url(&self, zone_id: &str, domain: &str, rtype: &str) -> String {
        format!(
            "{}/20180115/zones/{}/records/{}/{}?compartmentId={}",
            self.endpoint,
            urlencode(zone_id),
            urlencode(domain),
            urlencode(rtype),
            urlencode(&self.config.compartment_ocid),
        )
    }

    async fn get_records(
        &self,
        zone_id: &str,
        domain: &str,
        rtype: &str,
    ) -> Result<Vec<OciRecord>> {
        let url = self.records_url(zone_id, domain, rtype);
        let (status, body) = self.send_signed(Method::GET, &url, None).await?;
        if status.as_u16() == 404 {
            return Ok(Vec::new());
        }
        if !status.is_success() {
            return Err(map_error(status, &body));
        }
        let collection: RecordCollection = serde_json::from_str(&body)
            .map_err(|e| Error::Serialize(format!("Failed to parse records: {}", e)))?;
        Ok(collection.items)
    }

    async fn put_records(
        &self,
        zone_id: &str,
        domain: &str,
        rtype: &str,
        items: Vec<OciRecord>,
    ) -> Result<()> {
        let url = self.records_url(zone_id, domain, rtype);
        let request = UpdateRecordsRequest { items };
        let body = serde_json::to_string(&request)
            .map_err(|e| Error::Serialize(format!("Failed to serialize request: {}", e)))?;
        let (status, response_body) = self.send_signed(Method::PUT, &url, Some(body)).await?;
        if !status.is_success() {
            return Err(map_error(status, &response_body));
        }
        Ok(())
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        let (rtype, rdata) = Self::record_to_rdata(&record)?;
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone_id = self.resolve_zone(&origin).await?;

        let mut existing = self.get_records(&zone_id, &name, &rtype).await?;
        existing.push(OciRecord {
            domain: name.clone(),
            rtype: rtype.clone(),
            rdata,
            ttl,
            is_protected: None,
            record_hash: None,
        });

        let items = existing
            .into_iter()
            .map(|r| OciRecord {
                domain: r.domain,
                rtype: r.rtype,
                rdata: r.rdata,
                ttl: r.ttl,
                is_protected: None,
                record_hash: None,
            })
            .collect();
        self.put_records(&zone_id, &name, &rtype, items).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        let (rtype, rdata) = Self::record_to_rdata(&record)?;
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone_id = self.resolve_zone(&origin).await?;

        let items = vec![OciRecord {
            domain: name.clone(),
            rtype: rtype.clone(),
            rdata,
            ttl,
            is_protected: None,
            record_hash: None,
        }];
        self.put_records(&zone_id, &name, &rtype, items).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> Result<()> {
        if matches!(record_type, DnsRecordType::TLSA) {
            return Err(Error::Api(
                "TLSA records are not supported by Oracle Cloud DNS".into(),
            ));
        }
        let name = name.into_name().to_string();
        let origin = origin.into_name().to_string();
        let zone_id = self.resolve_zone(&origin).await?;
        let rtype = record_type.as_str();

        let url = self.records_url(&zone_id, &name, rtype);
        let (status, body) = self.send_signed(Method::DELETE, &url, None).await?;
        if status.as_u16() == 404 {
            return Err(Error::NotFound);
        }
        if !status.is_success() {
            return Err(map_error(status, &body));
        }
        Ok(())
    }
}

fn format_target(value: &str) -> String {
    format!("{}.", value.trim_end_matches('.'))
}

fn urlencode(value: &str) -> String {
    serde_urlencoded::to_string([("v", value)])
        .ok()
        .and_then(|s| s.strip_prefix("v=").map(str::to_string))
        .unwrap_or_else(|| value.to_string())
}

fn map_error(status: reqwest::StatusCode, body: &str) -> Error {
    match status.as_u16() {
        400 => Error::BadRequest,
        401 | 403 => Error::Unauthorized,
        404 => Error::NotFound,
        _ => Error::Api(format!("Oracle Cloud DNS error {}: {}", status, body)),
    }
}
