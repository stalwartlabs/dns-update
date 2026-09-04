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
use crate::utils::split_caa_value;
use crate::utils::strip_trailing_dot;
use crate::utils::txt_chunks_to_text;
use crate::utils::{parse_mx, parse_srv, parse_tlsa};
use crate::{CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn};
use quick_xml::de::from_str;
use quick_xml::se::to_string;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::net::AddrParseError;
use std::time::{Duration, SystemTime};

const ROUTE53_API_VERSION: &str = "2013-04-01";
const ROUTE53_SERVICE: &str = "route53";
const ROUTE53_DEFAULT_ENDPOINT: &str = "https://route53.amazonaws.com";
const ROUTE53_XMLNS: &str = "https://route53.amazonaws.com/doc/2013-04-01/";
const MAX_RETRIES: u32 = 3;

#[derive(Debug, Clone)]
pub struct Route53Config {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub region: Option<String>,
    pub hosted_zone_id: Option<String>,
    pub private_zone_only: Option<bool>,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Route53Provider {
    client: Client,
    config: Route53Config,
    region: String,
    endpoint: Cow<'static, str>,
}

impl Route53Provider {
    pub fn new(config: Route53Config) -> Self {
        let region = config
            .region
            .clone()
            .unwrap_or_else(|| "us-east-1".to_string());

        let endpoint = match config.endpoint.clone() {
            Some(ep) => Cow::Owned(ep),
            None => Cow::Borrowed(ROUTE53_DEFAULT_ENDPOINT),
        };

        Self {
            client: Client::new(),
            config,
            region,
            endpoint,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl Into<Cow<'static, str>>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..self
        }
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        let name = name.into_fqdn().into_owned();
        let hosted_zone_id = self.resolve_zone_id(&name).await?;

        if records.is_empty() {
            let existing = self
                .find_existing_rrset(&hosted_zone_id, &name, record_type)
                .await?;
            match existing {
                None => Ok(()),
                Some(rrset) => {
                    let change_batch = ChangeBatch {
                        comment: Some(format!("Delete {} RRSet for {}", record_type, name)),
                        changes: Changes {
                            changes: vec![Change {
                                action: ChangeAction::Delete,
                                resource_record_set: rrset,
                            }],
                        },
                    };
                    self.send_change_request(&hosted_zone_id, change_batch)
                        .await
                }
            }
        } else {
            let resource_records = ResourceRecords {
                resource_records: build_resource_records(&records)?,
            };
            let rrset = ResourceRecordSet::new(
                name.to_string(),
                record_type.as_str().to_string(),
                ttl as i64,
                resource_records,
            );
            let change_batch = ChangeBatch {
                comment: Some(format!("Set {} RRSet for {}", record_type, name)),
                changes: Changes {
                    changes: vec![Change {
                        action: ChangeAction::Upsert,
                        resource_record_set: rrset,
                    }],
                },
            };
            self.send_change_request(&hosted_zone_id, change_batch)
                .await
        }
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_fqdn().into_owned();
        let hosted_zone_id = self.resolve_zone_id(&name).await?;

        let mut desired = build_resource_records(&records)?;
        let existing_rrset = self
            .find_existing_rrset(&hosted_zone_id, &name, record_type)
            .await?;

        let (mut union, effective_ttl): (Vec<ResourceRecord>, i64) =
            if let Some(existing) = existing_rrset {
                let existing_ttl = existing.ttl;
                (existing.resource_records.resource_records, existing_ttl)
            } else {
                (Vec::new(), ttl as i64)
            };

        for record in desired.drain(..) {
            if !union.iter().any(|r| r.value == record.value) {
                union.push(record);
            }
        }

        let rrset = ResourceRecordSet::new(
            name.to_string(),
            record_type.as_str().to_string(),
            effective_ttl,
            ResourceRecords {
                resource_records: union,
            },
        );
        let change_batch = ChangeBatch {
            comment: Some(format!("Add to {} RRSet for {}", record_type, name)),
            changes: Changes {
                changes: vec![Change {
                    action: ChangeAction::Upsert,
                    resource_record_set: rrset,
                }],
            },
        };
        self.send_change_request(&hosted_zone_id, change_batch)
            .await
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_fqdn().into_owned();
        let hosted_zone_id = self.resolve_zone_id(&name).await?;

        let existing_rrset = match self
            .find_existing_rrset(&hosted_zone_id, &name, record_type)
            .await?
        {
            Some(r) => r,
            None => return Ok(()),
        };

        let to_remove = build_resource_records(&records)?;
        let existing_ttl = existing_rrset.ttl;
        let existing_records = existing_rrset.resource_records.resource_records.clone();
        let filtered: Vec<ResourceRecord> = existing_records
            .iter()
            .filter(|r| !to_remove.iter().any(|x| x.value == r.value))
            .cloned()
            .collect();

        if filtered.len() == existing_records.len() {
            return Ok(());
        }

        if filtered.is_empty() {
            let rrset = ResourceRecordSet::new(
                name.to_string(),
                record_type.as_str().to_string(),
                existing_ttl,
                ResourceRecords {
                    resource_records: existing_records,
                },
            );
            let change_batch = ChangeBatch {
                comment: Some(format!(
                    "Remove all from {} RRSet for {}",
                    record_type, name
                )),
                changes: Changes {
                    changes: vec![Change {
                        action: ChangeAction::Delete,
                        resource_record_set: rrset,
                    }],
                },
            };
            self.send_change_request(&hosted_zone_id, change_batch)
                .await
        } else {
            let rrset = ResourceRecordSet::new(
                name.to_string(),
                record_type.as_str().to_string(),
                existing_ttl,
                ResourceRecords {
                    resource_records: filtered,
                },
            );
            let change_batch = ChangeBatch {
                comment: Some(format!("Remove from {} RRSet for {}", record_type, name)),
                changes: Changes {
                    changes: vec![Change {
                        action: ChangeAction::Upsert,
                        resource_record_set: rrset,
                    }],
                },
            };
            self.send_change_request(&hosted_zone_id, change_batch)
                .await
        }
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let name = name.into_fqdn().into_owned();
        let hosted_zone_id = self.resolve_zone_id(&name).await?;
        let existing = self
            .find_existing_rrset(&hosted_zone_id, &name, record_type)
            .await?;
        let Some(rrset) = existing else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(rrset.resource_records.resource_records.len());
        for r in rrset.resource_records.resource_records {
            out.push(parse_value(record_type, &r.value)?);
        }
        Ok(out)
    }

    async fn resolve_zone_id(&self, name: &str) -> crate::Result<String> {
        if let Some(zone_id) = &self.config.hosted_zone_id {
            return Ok(zone_id.trim_start_matches("/hostedzone/").to_string());
        }

        let zones = self.list_hosted_zones_by_name().await?;
        let private_zone_only = self.config.private_zone_only.unwrap_or(false);
        let mut matching: Vec<HostedZone> = zones
            .into_iter()
            .filter(|z| !private_zone_only || z.config.private_zone)
            .filter(|z| {
                let zone_name = z.name.trim_end_matches('.');
                let candidate = name.trim_end_matches('.');
                candidate == zone_name || candidate.ends_with(&format!(".{}", zone_name))
            })
            .collect();
        matching.sort_by_key(|z| std::cmp::Reverse(z.name.len()));
        matching
            .into_iter()
            .next()
            .map(|z| z.id.trim_start_matches("/hostedzone/").to_string())
            .ok_or_else(|| Error::Api(format!("No suitable hosted zone found for name: {}", name)))
    }

    async fn list_hosted_zones_by_name(&self) -> crate::Result<Vec<HostedZone>> {
        let mut zones: Vec<HostedZone> = Vec::new();
        let mut next_dns_name: Option<String> = None;
        let mut next_hosted_zone_id: Option<String> = None;
        loop {
            let mut url = format!(
                "{}/{}/hostedzonesbyname",
                self.endpoint.as_ref(),
                ROUTE53_API_VERSION
            );
            let mut query_parts: Vec<(&str, String)> = Vec::new();
            if let Some(n) = &next_dns_name {
                query_parts.push(("dnsname", n.clone()));
            }
            if let Some(z) = &next_hosted_zone_id {
                query_parts.push(("hostedzoneid", z.clone()));
            }
            if !query_parts.is_empty() {
                let q = serde_urlencoded::to_string(&query_parts)
                    .map_err(|e| Error::Serialize(e.to_string()))?;
                url.push('?');
                url.push_str(&q);
            }

            let response = self.send_signed_request("GET", &url, None).await?;
            let body = response
                .text()
                .await
                .map_err(|e| Error::Api(format!("Failed to read response: {}", e)))?;
            let list_response: ListHostedZonesByNameResponse =
                from_str(&body).map_err(|e| Error::Api(format!("XML parsing error: {}", e)))?;
            zones.extend(list_response.hosted_zones.hosted_zones);
            if !list_response.is_truncated {
                break;
            }
            next_dns_name = list_response.next_dns_name;
            next_hosted_zone_id = list_response.next_hosted_zone_id;
            if next_dns_name.is_none() && next_hosted_zone_id.is_none() {
                break;
            }
        }
        Ok(zones)
    }

    async fn find_existing_rrset(
        &self,
        hosted_zone_id: &str,
        name: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Option<ResourceRecordSet>> {
        let type_str = record_type.as_str();
        let normalized_name = name.into_fqdn().into_owned();
        let rrsets = self
            .list_resource_record_sets(hosted_zone_id, &normalized_name, type_str)
            .await?;
        Ok(rrsets.into_iter().find(|r| {
            r.type_ == type_str
                && r.set_identifier.is_none()
                && names_match(&r.name, &normalized_name)
        }))
    }

    async fn list_resource_record_sets(
        &self,
        hosted_zone_id: &str,
        start_name: &str,
        start_type: &str,
    ) -> crate::Result<Vec<ResourceRecordSet>> {
        let mut out: Vec<ResourceRecordSet> = Vec::new();
        let mut next_name = Some(start_name.to_string());
        let mut next_type = Some(start_type.to_string());
        let mut next_identifier: Option<String> = None;
        let mut first = true;
        loop {
            let mut query: Vec<(&str, String)> = Vec::new();
            if let Some(n) = &next_name {
                query.push(("name", n.clone()));
            }
            if let Some(t) = &next_type {
                query.push(("type", t.clone()));
            }
            if let Some(i) = &next_identifier {
                query.push(("identifier", i.clone()));
            }
            let query_string =
                serde_urlencoded::to_string(&query).map_err(|e| Error::Serialize(e.to_string()))?;
            let url = format!(
                "{}/{}/hostedzone/{}/rrset?{}",
                self.endpoint.as_ref(),
                ROUTE53_API_VERSION,
                hosted_zone_id.trim_start_matches("/hostedzone/"),
                query_string,
            );
            let response = self.send_signed_request("GET", &url, None).await?;
            let body = response
                .text()
                .await
                .map_err(|e| Error::Api(format!("Failed to read response: {}", e)))?;
            let list_response: ListResourceRecordSetsResponse =
                from_str(&body).map_err(|e| Error::Api(format!("XML parsing error: {}", e)))?;

            let mut stop = false;
            for rrset in list_response.resource_record_sets.resource_record_sets {
                if !names_match(&rrset.name, start_name) {
                    stop = true;
                    break;
                }
                if rrset.type_ != start_type {
                    if first && rrset.type_.as_str() < start_type {
                        continue;
                    }
                    stop = true;
                    break;
                }
                out.push(rrset);
            }
            first = false;
            if stop || !list_response.is_truncated {
                break;
            }
            next_name = list_response.next_record_name;
            next_type = list_response.next_record_type;
            next_identifier = list_response.next_record_identifier;
            if next_name.is_none() && next_type.is_none() {
                break;
            }
        }
        Ok(out)
    }

    async fn send_change_request(
        &self,
        hosted_zone_id: &str,
        change_batch: ChangeBatch,
    ) -> crate::Result<()> {
        let url = format!(
            "{}/{}/hostedzone/{}/rrset",
            self.endpoint.as_ref(),
            ROUTE53_API_VERSION,
            hosted_zone_id.trim_start_matches("/hostedzone/")
        );

        let request = ChangeResourceRecordSetsRequest {
            xmlns: ROUTE53_XMLNS,
            change_batch,
        };

        let xml_body = to_string(&request).map_err(|e| Error::Serialize(format!("{}", e)))?;
        let payload = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", xml_body);

        self.send_signed_request("POST", &url, Some(payload))
            .await?;
        Ok(())
    }

    async fn send_signed_request(
        &self,
        method: &str,
        url: &str,
        body: Option<String>,
    ) -> crate::Result<Response> {
        let mut attempts: u32 = 0;
        loop {
            let result = self
                .send_signed_request_once(method, url, body.as_deref())
                .await;
            match result {
                Ok(response) => return Ok(response),
                Err(SignedRequestError::Retryable(_)) if attempts < MAX_RETRIES => {
                    let delay = Duration::from_millis(250 * (1u64 << attempts));
                    tokio::time::sleep(delay).await;
                    attempts += 1;
                    continue;
                }
                Err(SignedRequestError::Retryable(e)) => return Err(e),
                Err(SignedRequestError::Permanent(e)) => return Err(e),
            }
        }
    }

    async fn send_signed_request_once(
        &self,
        method: &str,
        url: &str,
        body: Option<&str>,
    ) -> Result<Response, SignedRequestError> {
        use chrono::{DateTime, Utc};
        let datetime: DateTime<Utc> = SystemTime::now().into();
        let amz_date = datetime.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = datetime.format("%Y%m%d").to_string();

        let parsed_url: reqwest::Url = url
            .parse()
            .map_err(|e| SignedRequestError::Permanent(Error::Parse(format!("{e}"))))?;
        let host_for_header = parsed_url
            .host_str()
            .ok_or_else(|| {
                SignedRequestError::Permanent(Error::Parse(format!("invalid URL: {url}")))
            })?
            .to_string();
        let host_header_value = match parsed_url.port() {
            Some(port) => format!("{host_for_header}:{port}"),
            None => host_for_header.clone(),
        };
        let canonical_uri = parsed_url.path();
        let canonical_querystring = canonical_query_string(parsed_url.query().unwrap_or(""));

        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_str(&host_header_value).map_err(|e| {
                SignedRequestError::Permanent(Error::Api(format!("invalid host header: {e}")))
            })?,
        );
        headers.insert(
            "x-amz-date",
            HeaderValue::from_str(&amz_date).map_err(|e| {
                SignedRequestError::Permanent(Error::Api(format!("invalid date header: {e}")))
            })?,
        );
        headers.insert("content-type", HeaderValue::from_static("application/xml"));

        let mut signed_header_names: Vec<&'static str> = vec!["content-type", "host", "x-amz-date"];
        let mut canonical_header_lines: Vec<String> = vec![
            "content-type:application/xml".to_string(),
            format!("host:{host_header_value}"),
            format!("x-amz-date:{amz_date}"),
        ];

        if let Some(session_token) = &self.config.session_token {
            headers.insert(
                "x-amz-security-token",
                HeaderValue::from_str(session_token).map_err(|e| {
                    SignedRequestError::Permanent(Error::Api(format!(
                        "invalid session token header: {e}"
                    )))
                })?,
            );
            signed_header_names.push("x-amz-security-token");
            canonical_header_lines.push(format!("x-amz-security-token:{session_token}"));
        }

        let signed_headers = signed_header_names.join(";");
        let canonical_headers = format!("{}\n", canonical_header_lines.join("\n"));

        let body_str = body.unwrap_or("");
        let payload_hash = hex::encode(sha256_digest(body_str.as_bytes()));

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash
        );

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

        let signing_key = self.get_signature_key(&date_stamp);
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let authorization_header = format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            algorithm, self.config.access_key_id, credential_scope, signed_headers, signature
        );
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&authorization_header).map_err(|e| {
                SignedRequestError::Permanent(Error::Api(format!(
                    "invalid authorization header: {e}"
                )))
            })?,
        );

        let parsed_method = method
            .parse::<reqwest::Method>()
            .map_err(|e| SignedRequestError::Permanent(Error::Parse(e.to_string())))?;
        let mut request = self.client.request(parsed_method, url).headers(headers);
        if let Some(body_content) = body {
            request = request.body(body_content.to_string());
        }

        let response = request
            .send()
            .await
            .map_err(|e| SignedRequestError::Permanent(Error::Api(e.to_string())))?;

        let status = response.status();
        let code = status.as_u16();
        if status.is_success() {
            return Ok(response);
        }

        let body_text = response.text().await.unwrap_or_default();
        let retryable = code == 429
            || code == 503
            || body_text.contains("Throttling")
            || body_text.contains("PriorRequestNotComplete");
        let err = match code {
            401 => Error::Unauthorized,
            404 => Error::NotFound,
            400 if !retryable => Error::Api(format!("Route53 BadRequest: {}", body_text)),
            _ => Error::Api(format!("Route53 API error: {} - {}", status, body_text)),
        };
        if retryable {
            Err(SignedRequestError::Retryable(err))
        } else {
            Err(SignedRequestError::Permanent(err))
        }
    }

    fn get_signature_key(&self, date_stamp: &str) -> Vec<u8> {
        let k_date = hmac_sha256(
            format!("AWS4{}", self.config.secret_access_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, ROUTE53_SERVICE.as_bytes());
        hmac_sha256(&k_service, b"aws4_request")
    }
}

enum SignedRequestError {
    Retryable(Error),
    Permanent(Error),
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> crate::Result<()> {
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

fn build_resource_records(records: &[DnsRecord]) -> crate::Result<Vec<ResourceRecord>> {
    let mut out = Vec::with_capacity(records.len());
    let mut seen: Vec<String> = Vec::with_capacity(records.len());
    for record in records {
        let value = render_record_value(record);
        if seen.iter().any(|s| s == &value) {
            continue;
        }
        seen.push(value.clone());
        out.push(ResourceRecord { value });
    }
    Ok(out)
}

fn render_record_value(record: &DnsRecord) -> String {
    match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(name) => name.clone(),
        DnsRecord::NS(name) => name.clone(),
        DnsRecord::MX(mx) => mx.to_string(),
        DnsRecord::TXT(text) => {
            let mut value = String::new();
            txt_chunks_to_text(&mut value, text, " ");
            value
        }
        DnsRecord::SRV(srv) => srv.to_string(),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    }
}

fn parse_value(record_type: DnsRecordType, value: &str) -> crate::Result<DnsRecord> {
    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(value.parse().map_err(|e: AddrParseError| {
            Error::Parse(format!("invalid A value '{value}': {e}"))
        })?),
        DnsRecordType::AAAA => DnsRecord::AAAA(value.parse().map_err(|e: AddrParseError| {
            Error::Parse(format!("invalid AAAA value '{value}': {e}"))
        })?),
        DnsRecordType::CNAME => DnsRecord::CNAME(strip_trailing_dot(value).to_string()),
        DnsRecordType::NS => DnsRecord::NS(strip_trailing_dot(value).to_string()),
        DnsRecordType::MX => parse_mx(value)?,
        DnsRecordType::TXT => DnsRecord::TXT(parse_txt(value)),
        DnsRecordType::SRV => parse_srv(value)?,
        DnsRecordType::TLSA => parse_tlsa(value)?,
        DnsRecordType::CAA => parse_caa(value)?,
    })
}

fn parse_caa(value: &str) -> crate::Result<DnsRecord> {
    let mut parts = value.splitn(3, char::is_whitespace);
    let flags: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags in '{value}': {e}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value '{value}'")))?
        .to_ascii_lowercase();
    let raw_value = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value '{value}'")))?
        .trim();
    let unquoted = raw_value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .map(|s| s.replace("\\\"", "\""))
        .unwrap_or_else(|| raw_value.to_string());

    let issuer_critical = flags & 0x80 != 0;
    match tag.as_str() {
        "issue" => {
            let (name, options) = split_caa_value(&unquoted);
            Ok(DnsRecord::CAA(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }))
        }
        "issuewild" => {
            let (name, options) = split_caa_value(&unquoted);
            Ok(DnsRecord::CAA(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            }))
        }
        "iodef" => Ok(DnsRecord::CAA(CAARecord::Iodef {
            issuer_critical,
            url: unquoted,
        })),
        other => Err(Error::Parse(format!("unknown CAA tag: {other}"))),
    }
}

fn parse_txt(value: &str) -> String {
    let trimmed = value.trim();
    let mut out = String::with_capacity(trimmed.len());
    let mut bytes = trimmed.bytes().peekable();
    let mut saw_quote = false;
    while let Some(&b) = bytes.peek() {
        if b != b'"' {
            bytes.next();
            continue;
        }
        saw_quote = true;
        bytes.next();
        loop {
            match bytes.next() {
                Some(b'"') => break,
                Some(b'\\') => {
                    if let Some(next) = bytes.next() {
                        out.push(next as char);
                    }
                }
                Some(other) => out.push(other as char),
                None => break,
            }
        }
    }
    if !saw_quote {
        return trimmed.to_string();
    }
    out
}

fn names_match(a: &str, b: &str) -> bool {
    a.trim_end_matches('.') == b.trim_end_matches('.')
}

fn canonical_query_string(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (pair.to_string(), String::new()),
        };
        pairs.push((k, v));
    }
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

#[derive(Debug, Serialize)]
#[serde(rename = "ChangeResourceRecordSetsRequest")]
struct ChangeResourceRecordSetsRequest {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
    #[serde(rename = "ChangeBatch")]
    change_batch: ChangeBatch,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChangeBatch {
    #[serde(rename = "Comment", skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(rename = "Changes")]
    changes: Changes,
}

#[derive(Debug, Serialize, Deserialize)]
struct Changes {
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
    resource_records: ResourceRecords,
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

impl ResourceRecordSet {
    fn new(name: String, type_: String, ttl: i64, resource_records: ResourceRecords) -> Self {
        Self {
            name,
            type_,
            ttl,
            resource_records,
            set_identifier: None,
            weight: None,
            region: None,
            geo_location: None,
            health_check_id: None,
            traffic_policy_instance_id: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ResourceRecords {
    #[serde(rename = "ResourceRecord", default)]
    resource_records: Vec<ResourceRecord>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
    hosted_zones: HostedZones,
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,
    #[serde(rename = "NextDNSName", skip_serializing_if = "Option::is_none")]
    next_dns_name: Option<String>,
    #[serde(rename = "NextHostedZoneId", skip_serializing_if = "Option::is_none")]
    next_hosted_zone_id: Option<String>,
    #[serde(rename = "MaxItems")]
    max_items: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct HostedZones {
    #[serde(rename = "HostedZone", default)]
    hosted_zones: Vec<HostedZone>,
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
    resource_record_sets: ResourceRecordSets,
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

#[derive(Debug, Serialize, Deserialize)]
struct ResourceRecordSets {
    #[serde(rename = "ResourceRecordSet", default)]
    resource_record_sets: Vec<ResourceRecordSet>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MXRecord, TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector};
    use quick_xml::se::to_string;

    #[test]
    fn test_serialization() {
        let req = ChangeResourceRecordSetsRequest {
            xmlns: ROUTE53_XMLNS,
            change_batch: ChangeBatch {
                comment: Some("Test".to_string()),
                changes: Changes {
                    changes: vec![Change {
                        action: ChangeAction::Create,
                        resource_record_set: ResourceRecordSet::new(
                            "example.com".to_string(),
                            "A".to_string(),
                            300,
                            ResourceRecords {
                                resource_records: vec![ResourceRecord {
                                    value: "127.0.0.1".to_string(),
                                }],
                            },
                        ),
                    }],
                },
            },
        };
        let out = to_string(&req).unwrap();
        assert!(out.starts_with("<ChangeResourceRecordSetsRequest"));
    }

    #[test]
    fn test_parse_txt_roundtrip() {
        let original = "hello \"world\"";
        let rendered = render_record_value(&DnsRecord::TXT(original.to_string()));
        let parsed = parse_txt(&rendered);
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_parse_mx_roundtrip() {
        let original = DnsRecord::MX(MXRecord {
            priority: 10,
            exchange: "mail.example.com".to_string(),
        });
        let rendered = render_record_value(&original);
        let parsed = parse_value(DnsRecordType::MX, &rendered).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_parse_tlsa_roundtrip() {
        let original = DnsRecord::TLSA(TLSARecord {
            cert_usage: TlsaCertUsage::DaneEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            cert_data: vec![0xab, 0xcd, 0xef],
        });
        let rendered = render_record_value(&original);
        let parsed = parse_value(DnsRecordType::TLSA, &rendered).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_canonical_query_string_sorts_pairs() {
        let q = canonical_query_string("type=A&name=example.com.");
        assert_eq!(q, "name=example.com.&type=A");
    }
}
