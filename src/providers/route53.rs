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

use crate::crypto::{hmac_sha256, sha256_digest};
use crate::{DnsRecord, DnsRecordType, IntoFqdn};

use std::time::SystemTime;

use quick_xml::de::from_str;
use quick_xml::se::to_string;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};

const ROUTE53_API_VERSION: &str = "2013-04-01";
const ROUTE53_SERVICE: &str = "route53";
const ROUTE53_HOST: &str = "route53.amazonaws.com";

/// Route53 provider configuration
#[derive(Debug, Clone)]
pub struct Route53Config {
    /// AWS access key ID (required)
    pub access_key_id: String,
    /// AWS secret access key (required)
    pub secret_access_key: String,
    /// AWS session token (optional, for temporary credentials)
    pub session_token: Option<String>,
    /// AWS region (optional, defaults to us-east-1)
    pub region: Option<String>,
    /// Hosted zone ID to use (optional, will resolve by name if not provided)
    pub hosted_zone_id: Option<String>,
    /// Whether to use private zones only (optional, defaults to false)
    pub private_zone_only: Option<bool>,
}

/// Route53 DNS provider
#[derive(Debug, Clone)]
pub struct Route53Provider {
    client: Client,
    config: Route53Config,
    region: String,
}

impl Route53Provider {
    /// Create a new Route53 provider
    pub fn new(config: Route53Config) -> Self {
        let region = config
            .region
            .clone()
            .unwrap_or_else(|| "us-east-1".to_string());

        Self {
            client: Client::new(),
            config,
            region,
        }
    }

    /// Create a new DNS record
    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_fqdn();
        let hosted_zone_id = if let Some(zone_id) = &self.config.hosted_zone_id {
            zone_id.clone()
        } else {
            self.resolve_hosted_zone(&name)
                .await
                .map_err(|e| crate::Error::Api(e.to_string()))?
        };

        let change_batch = ChangeBatch {
            comment: Some(format!("Create record for {}", name)),
            changes: vec![Change {
                action: ChangeAction::Create,
                resource_record_set: self
                    .record_to_rrset(&name, &record, ttl)
                    .map_err(|e| crate::Error::Api(format!("{}", e)))?,
            }],
        };

        self.send_change_request(&hosted_zone_id, &change_batch)
            .await
            .map_err(|e| crate::Error::Api(e.to_string()))
    }

    /// Update an existing DNS record
    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_fqdn();
        let hosted_zone_id = if let Some(zone_id) = &self.config.hosted_zone_id {
            zone_id.clone()
        } else {
            self.resolve_hosted_zone(&name)
                .await
                .map_err(|e| crate::Error::Api(e.to_string()))?
        };

        let change_batch = ChangeBatch {
            comment: Some(format!("Update record for {}", name)),
            changes: vec![Change {
                action: ChangeAction::Upsert,
                resource_record_set: self
                    .record_to_rrset(&name, &record, ttl)
                    .map_err(|e| crate::Error::Api(format!("{}", e)))?,
            }],
        };

        self.send_change_request(&hosted_zone_id, &change_batch)
            .await
            .map_err(|e| crate::Error::Api(e.to_string()))
    }

    /// Delete an existing DNS record
    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        _origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_fqdn();
        let hosted_zone_id = if let Some(zone_id) = &self.config.hosted_zone_id {
            zone_id.clone()
        } else {
            self.resolve_hosted_zone(&name)
                .await
                .map_err(|e| crate::Error::Api(e.to_string()))?
        };

        // Find existing RRSet(s) for this name and type
        let existing_rrsets = self
            .list_resource_record_sets(&hosted_zone_id, &name, &record_type)
            .await
            .map_err(|e| crate::Error::Api(format!("{}", e)))?;

        let type_str = self.record_type_to_string(&record_type);
        let mut matching_rrsets: Vec<_> = existing_rrsets
            .into_iter()
            .filter(|r| r.name == name && r.type_ == type_str)
            .collect();

        match matching_rrsets.len() {
            0 => {
                // Record doesn't exist, consider this a success (idempotent delete)
                Ok(())
            }
            1 => {
                // Exactly one RRSet found, delete it
                let rrset = matching_rrsets.pop().unwrap();
                let change_batch = ChangeBatch {
                    comment: Some(format!("Delete {} record for {}", record_type, name)),
                    changes: vec![Change {
                        action: ChangeAction::Delete,
                        resource_record_set: rrset,
                    }],
                };
                self.send_change_request(&hosted_zone_id, &change_batch)
                    .await
                    .map_err(|e| crate::Error::Api(format!("{}", e)))
            }
            _ => {
                // Multiple RRSet found, this is ambiguous
                Err(crate::Error::Api(format!(
                    "Found {} RRSet(s) with name '{}' and type '{:?}'. Cannot delete ambiguous records.",
                    matching_rrsets.len(),
                    name,
                    record_type
                )))
            }
        }
    }

    /// Resolve hosted zone ID by name using longest suffix matching
    async fn resolve_hosted_zone(
        &self,
        name: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let zones = self.list_hosted_zones_by_name().await?;

        let private_zone_only = self.config.private_zone_only.unwrap_or(false);

        // Find zones that match the record name (longest suffix match)
        let mut matching_zones = Vec::new();

        for zone in zones {
            if private_zone_only && !zone.config.private_zone {
                continue;
            }

            // Check if the name ends with the zone name (with proper DNS name handling)
            if name == zone.name || name.ends_with(&format!(".{}", zone.name)) {
                matching_zones.push(zone);
            }
        }

        // Sort by name length (longest first) and return the first match
        matching_zones.sort_by(|a, b| b.name.len().cmp(&a.name.len()));

        matching_zones
            .into_iter()
            .next()
            .map(|zone| zone.id)
            .ok_or_else(|| format!("No suitable hosted zone found for name: {}", name).into())
    }

    /// List hosted zones sorted by name
    async fn list_hosted_zones_by_name(
        &self,
    ) -> Result<Vec<HostedZone>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "https://{}/{}/hostedzonebyname",
            ROUTE53_HOST, ROUTE53_API_VERSION
        );
        let response = self.send_signed_request("GET", &url, None).await?;
        let list_response: ListHostedZonesByNameResponse =
            from_str(&response.text().await?).map_err(|e| format!("XML parsing error: {}", e))?;
        Ok(list_response.hosted_zones)
    }

    /// List resource record sets for a specific name and type
    async fn list_resource_record_sets(
        &self,
        hosted_zone_id: &str,
        name: &str,
        record_type: &DnsRecordType,
    ) -> Result<Vec<ResourceRecordSet>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "https://{}/{}/hostedzone/{}/rrset?name={}&type={}",
            ROUTE53_HOST,
            ROUTE53_API_VERSION,
            hosted_zone_id.trim_start_matches("/hostedzone/"),
            name,
            self.record_type_to_string(record_type)
        );

        let response = self.send_signed_request("GET", &url, None).await?;
        let list_response: ListResourceRecordSetsResponse =
            from_str(&response.text().await?).map_err(|e| format!("XML parsing error: {}", e))?;
        Ok(list_response.resource_record_sets)
    }

    /// Send a change request to Route53
    async fn send_change_request(
        &self,
        hosted_zone_id: &str,
        change_batch: &ChangeBatch,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "https://{}/{}/hostedzone/{}/rrset",
            ROUTE53_HOST,
            ROUTE53_API_VERSION,
            hosted_zone_id.trim_start_matches("/hostedzone/")
        );

        let payload =
            to_string(change_batch).map_err(|e| format!("XML serialization error: {}", e))?;

        self.send_signed_request("POST", &url, Some(payload))
            .await?;
        Ok(())
    }

    /// Send a signed HTTP request to Route53
    async fn send_signed_request(
        &self,
        method: &str,
        url: &str,
        body: Option<String>,
    ) -> Result<Response, Box<dyn std::error::Error + Send + Sync>> {
        use chrono::{DateTime, Utc};
        let datetime: DateTime<Utc> = SystemTime::now().into();
        let amz_date = datetime.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = datetime.format("%Y%m%d").to_string();

        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_str(ROUTE53_HOST)?);
        headers.insert("x-amz-date", HeaderValue::from_str(&amz_date)?);

        if let Some(session_token) = &self.config.session_token {
            headers.insert(
                "x-amz-security-token",
                HeaderValue::from_str(session_token)?,
            );
        }

        let body_str = body.as_deref().unwrap_or("");
        let payload_hash = hex::encode(sha256_digest(body_str.as_bytes()));

        // Create canonical request
        let parsed_url = url.parse::<reqwest::Url>()?;
        let canonical_uri = parsed_url.path();
        let canonical_querystring = parsed_url.query().unwrap_or("");
        let canonical_headers = format!("host:{}\nx-amz-date:{}\n", ROUTE53_HOST, amz_date);
        let signed_headers = "host;x-amz-date";

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash
        );

        // Create string to sign
        let algorithm = "AWS4-HMAC-SHA256";
        let credential_scope = format!(
            "{}/{}/{}/aws4_request",
            date_stamp, self.region, ROUTE53_SERVICE
        );
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            algorithm,
            amz_date,
            credential_scope,
            hex::encode(sha256_digest(canonical_request.as_bytes()))
        );

        // Calculate signature
        let signing_key = self.get_signature_key(&date_stamp)?;
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        // Add authorization header
        let authorization_header = format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            algorithm, self.config.access_key_id, credential_scope, signed_headers, signature
        );
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&authorization_header)?,
        );

        // Send request
        let mut request = self.client.request(method.parse()?, url);
        request = request.headers(headers);

        if let Some(body_content) = body {
            request = request.body(body_content);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Route53 API error: {} - {}", status, body).into());
        }

        Ok(response)
    }

    /// Get AWS signature key
    fn get_signature_key(
        &self,
        date_stamp: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let k_date = hmac_sha256(
            format!("AWS4{}", self.config.secret_access_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, ROUTE53_SERVICE.as_bytes());
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        Ok(k_signing)
    }

    /// Convert DNS record to Route53 ResourceRecordSet
    fn record_to_rrset(
        &self,
        name: &str,
        record: &DnsRecord,
        ttl: u32,
    ) -> Result<ResourceRecordSet, Box<dyn std::error::Error + Send + Sync>> {
        let value = match record {
            DnsRecord::A(addr) => addr.to_string(),
            DnsRecord::AAAA(addr) => addr.to_string(),
            DnsRecord::CNAME(name) => name.clone(),
            DnsRecord::NS(name) => name.clone(),
            DnsRecord::MX(mx) => mx.to_string(),
            DnsRecord::TXT(text) => format!("\"{}\"", text.replace('\"', "\\\"")),
            DnsRecord::SRV(srv) => srv.to_string(),
            DnsRecord::TLSA(tlsa) => tlsa.to_string(),
            DnsRecord::CAA(caa) => caa.to_string(),
        };

        let resource_records = vec![ResourceRecord { value }];

        Ok(ResourceRecordSet {
            name: name.to_string(),
            type_: self.record_type_to_string(&record.as_type()),
            ttl: ttl as i64,
            resource_records,
            set_identifier: None,
            weight: None,
            region: None,
            geo_location: None,
            health_check_id: None,
            traffic_policy_instance_id: None,
        })
    }

    /// Convert DNS record type to Route53 string
    fn record_type_to_string(&self, record_type: &DnsRecordType) -> String {
        match record_type {
            DnsRecordType::A => "A".to_string(),
            DnsRecordType::AAAA => "AAAA".to_string(),
            DnsRecordType::CNAME => "CNAME".to_string(),
            DnsRecordType::MX => "MX".to_string(),
            DnsRecordType::TXT => "TXT".to_string(),
            DnsRecordType::SRV => "SRV".to_string(),
            DnsRecordType::NS => "NS".to_string(),
            DnsRecordType::TLSA => "TLSA".to_string(),
            DnsRecordType::CAA => "CAA".to_string(),
        }
    }
}

// XML structures for Route53 API

#[derive(Debug, Serialize, Deserialize)]
struct ChangeBatch {
    #[serde(rename = "@comment", skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "Change")]
    changes: Vec<Change>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Change {
    #[serde(rename = "Action")]
    action: ChangeAction,
    #[serde(rename = "ResourceRecordSet")]
    resource_record_set: ResourceRecordSet,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum ChangeAction {
    Create,
    Delete,
    Upsert,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResourceRecordSet {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Type")]
    type_: String,
    #[serde(rename = "TTL")]
    ttl: i64,
    #[serde(rename = "ResourceRecords")]
    resource_records: Vec<ResourceRecord>,
    #[serde(rename = "SetIdentifier", skip_serializing_if = "Option::is_none")]
    set_identifier: Option<String>,
    #[serde(rename = "Weight", skip_serializing_if = "Option::is_none")]
    weight: Option<i64>,
    #[serde(rename = "Region", skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(rename = "GeoLocation", skip_serializing_if = "Option::is_none")]
    geo_location: Option<GeoLocation>,
    #[serde(rename = "HealthCheckId", skip_serializing_if = "Option::is_none")]
    health_check_id: Option<String>,
    #[serde(
        rename = "TrafficPolicyInstanceId",
        skip_serializing_if = "Option::is_none"
    )]
    traffic_policy_instance_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResourceRecord {
    #[serde(rename = "Value")]
    value: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GeoLocation {
    #[serde(rename = "ContinentCode", skip_serializing_if = "Option::is_none")]
    continent_code: Option<String>,
    #[serde(rename = "CountryCode", skip_serializing_if = "Option::is_none")]
    country_code: Option<String>,
    #[serde(rename = "SubdivisionCode", skip_serializing_if = "Option::is_none")]
    subdivision_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListHostedZonesByNameResponse {
    #[serde(rename = "HostedZones")]
    hosted_zones: Vec<HostedZone>,
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,
    #[serde(rename = "NextRecordName", skip_serializing_if = "Option::is_none")]
    next_record_name: Option<String>,
    #[serde(rename = "NextRecordType", skip_serializing_if = "Option::is_none")]
    next_record_type: Option<String>,
    #[serde(rename = "MaxItems")]
    max_items: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct HostedZone {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "CallerReference")]
    caller_reference: String,
    #[serde(rename = "Config")]
    config: HostedZoneConfig,
}

#[derive(Debug, Serialize, Deserialize)]
struct HostedZoneConfig {
    #[serde(rename = "PrivateZone")]
    private_zone: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListResourceRecordSetsResponse {
    #[serde(rename = "ResourceRecordSets")]
    resource_record_sets: Vec<ResourceRecordSet>,
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,
    #[serde(rename = "MaxItems")]
    max_items: String,
    #[serde(rename = "NextRecordName", skip_serializing_if = "Option::is_none")]
    next_record_name: Option<String>,
    #[serde(rename = "NextRecordType", skip_serializing_if = "Option::is_none")]
    next_record_type: Option<String>,
    #[serde(
        rename = "NextRecordIdentifier",
        skip_serializing_if = "Option::is_none"
    )]
    next_record_identifier: Option<String>,
}
