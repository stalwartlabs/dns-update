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
    DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord,
    crypto::hmac_sha256,
    http::{HttpClient, HttpClientBuilder},
    utils::txt_chunks_to_text,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use quick_xml::se::to_string as xml_to_string;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://dns.api.nifcloud.com";
const API_VERSION: &str = "2012-12-12N2013-12-16";
const XMLNS: &str = "https://route53.amazonaws.com/doc/2012-12-12/";

#[derive(Clone)]
pub struct NifcloudProvider {
    client: HttpClient,
    access_key: String,
    secret_key: String,
    endpoint: String,
}

#[derive(Serialize, Debug)]
#[serde(rename = "ChangeResourceRecordSetsRequest")]
struct ChangeRequest {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
    #[serde(rename = "ChangeBatch")]
    change_batch: ChangeBatch,
}

#[derive(Serialize, Debug)]
struct ChangeBatch {
    #[serde(rename = "Comment")]
    comment: String,
    #[serde(rename = "Changes")]
    changes: Changes,
}

#[derive(Serialize, Debug)]
struct Changes {
    #[serde(rename = "Change")]
    change: Vec<Change>,
}

#[derive(Serialize, Debug)]
struct Change {
    #[serde(rename = "Action")]
    action: &'static str,
    #[serde(rename = "ResourceRecordSet")]
    resource_record_set: ResourceRecordSet,
}

#[derive(Serialize, Debug)]
struct ResourceRecordSet {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Type")]
    record_type: &'static str,
    #[serde(rename = "TTL")]
    ttl: u32,
    #[serde(rename = "ResourceRecords")]
    resource_records: ResourceRecords,
}

#[derive(Serialize, Debug)]
struct ResourceRecords {
    #[serde(rename = "ResourceRecord")]
    resource_record: Vec<ResourceRecord>,
}

#[derive(Serialize, Debug)]
struct ResourceRecord {
    #[serde(rename = "Value")]
    value: String,
}

#[derive(Deserialize, Debug)]
struct ChangeResponse {
    #[serde(rename = "ChangeInfo")]
    #[allow(dead_code)]
    change_info: ChangeInfo,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ChangeInfo {
    #[serde(rename = "Id")]
    id: String,
}

#[derive(Deserialize, Debug)]
struct ErrorResponse {
    #[serde(rename = "Error", default)]
    error: NifcloudError,
}

#[derive(Deserialize, Debug, Default)]
struct NifcloudError {
    #[serde(rename = "Code", default)]
    code: String,
    #[serde(rename = "Message", default)]
    message: String,
}

#[derive(Deserialize, Debug, Default)]
struct ListResponse {
    #[serde(rename = "ResourceRecordSets", default)]
    resource_record_sets: ListedRecordSets,
    #[serde(rename = "IsTruncated", default)]
    is_truncated: String,
    #[serde(rename = "NextRecordName", default)]
    next_record_name: Option<String>,
    #[serde(rename = "NextRecordType", default)]
    next_record_type: Option<String>,
    #[serde(rename = "NextRecordIdentifier", default)]
    next_record_identifier: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
struct ListedRecordSets {
    #[serde(rename = "ResourceRecordSet", default)]
    resource_record_set: Vec<ListedRecordSet>,
}

#[derive(Deserialize, Debug, Clone)]
struct ListedRecordSet {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Type", default)]
    record_type: String,
    #[serde(rename = "TTL", default)]
    ttl: u32,
    #[serde(rename = "SetIdentifier", default)]
    set_identifier: Option<String>,
    #[serde(rename = "ResourceRecords", default)]
    resource_records: ListedResourceRecords,
}

#[derive(Deserialize, Debug, Default, Clone)]
struct ListedResourceRecords {
    #[serde(rename = "ResourceRecord", default)]
    resource_record: Vec<ListedResourceRecord>,
}

#[derive(Deserialize, Debug, Clone)]
struct ListedResourceRecord {
    #[serde(rename = "Value", default)]
    value: String,
}

impl NifcloudProvider {
    pub(crate) fn new(
        access_key: impl AsRef<str>,
        secret_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let access_key = access_key.as_ref();
        let secret_key = secret_key.as_ref();
        if access_key.is_empty() || secret_key.is_empty() {
            return Err(Error::Api("Nifcloud credentials missing".into()));
        }
        let client = HttpClientBuilder::default()
            .with_header("Accept", "application/xml")
            .with_timeout(timeout)
            .build();
        Ok(Self {
            client,
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            endpoint: DEFAULT_ENDPOINT.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    fn signed(&self, request: crate::http::HttpRequest) -> crate::http::HttpRequest {
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let mac = hmac_sha256(self.secret_key.as_bytes(), date.as_bytes());
        let signature = BASE64_STANDARD.encode(&mac);
        let auth = format!(
            "NIFTY3-HTTPS NiftyAccessKeyId={},Algorithm=HmacSHA256,Signature={}",
            self.access_key, signature
        );
        request
            .set_header("Content-Type", "text/xml; charset=utf-8")
            .with_header("Date", date)
            .with_header("X-Nifty-Authorization", auth)
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let type_str = dns_type_str(record_type)?;
        check_record_types(record_type, &records)?;
        let name_str = name.into_name().to_string();
        let domain = origin.into_name().to_string();
        let subdomain_name = normalized_record_name(&name_str, &domain);

        let desired = build_values(record_type, &records)?;
        let existing = self
            .list_existing(&domain, &subdomain_name, type_str)
            .await?;

        let mut changes: Vec<Change> = Vec::new();
        if let Some(prev) = existing.first() {
            let current_values: Vec<String> = prev
                .resource_records
                .resource_record
                .iter()
                .map(|r| r.value.clone())
                .collect();
            if prev.ttl == ttl && values_equal(&current_values, &desired) {
                return Ok(());
            }
            changes.push(Change {
                action: "DELETE",
                resource_record_set: ResourceRecordSet {
                    name: subdomain_name.clone(),
                    record_type: type_str,
                    ttl: prev.ttl,
                    resource_records: ResourceRecords {
                        resource_record: current_values
                            .into_iter()
                            .map(|value| ResourceRecord { value })
                            .collect(),
                    },
                },
            });
        }

        if !desired.is_empty() {
            changes.push(Change {
                action: "CREATE",
                resource_record_set: ResourceRecordSet {
                    name: subdomain_name,
                    record_type: type_str,
                    ttl,
                    resource_records: ResourceRecords {
                        resource_record: desired
                            .into_iter()
                            .map(|value| ResourceRecord { value })
                            .collect(),
                    },
                },
            });
        }

        if changes.is_empty() {
            return Ok(());
        }

        self.send_change(
            &domain,
            ChangeRequest {
                xmlns: XMLNS,
                change_batch: ChangeBatch {
                    comment: "Managed by dns-update".into(),
                    changes: Changes { change: changes },
                },
            },
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let type_str = dns_type_str(record_type)?;
        check_record_types(record_type, &records)?;
        let name_str = name.into_name().to_string();
        let domain = origin.into_name().to_string();
        let subdomain_name = normalized_record_name(&name_str, &domain);

        let new_values = build_values(record_type, &records)?;
        let existing = self
            .list_existing(&domain, &subdomain_name, type_str)
            .await?;

        let mut changes: Vec<Change> = Vec::new();
        let merged: Vec<String>;
        let merged_ttl: u32;

        if let Some(prev) = existing.first() {
            let current_values: Vec<String> = prev
                .resource_records
                .resource_record
                .iter()
                .map(|r| r.value.clone())
                .collect();
            let mut combined = current_values.clone();
            for value in &new_values {
                if !combined.iter().any(|v| v == value) {
                    combined.push(value.clone());
                }
            }
            if values_equal(&current_values, &combined) {
                return Ok(());
            }
            changes.push(Change {
                action: "DELETE",
                resource_record_set: ResourceRecordSet {
                    name: subdomain_name.clone(),
                    record_type: type_str,
                    ttl: prev.ttl,
                    resource_records: ResourceRecords {
                        resource_record: current_values
                            .into_iter()
                            .map(|value| ResourceRecord { value })
                            .collect(),
                    },
                },
            });
            merged = combined;
            merged_ttl = prev.ttl;
        } else {
            merged = new_values;
            merged_ttl = ttl;
        }

        changes.push(Change {
            action: "CREATE",
            resource_record_set: ResourceRecordSet {
                name: subdomain_name,
                record_type: type_str,
                ttl: merged_ttl,
                resource_records: ResourceRecords {
                    resource_record: merged
                        .into_iter()
                        .map(|value| ResourceRecord { value })
                        .collect(),
                },
            },
        });

        self.send_change(
            &domain,
            ChangeRequest {
                xmlns: XMLNS,
                change_batch: ChangeBatch {
                    comment: "Managed by dns-update".into(),
                    changes: Changes { change: changes },
                },
            },
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let type_str = dns_type_str(record_type)?;
        check_record_types(record_type, &records)?;
        let name_str = name.into_name().to_string();
        let domain = origin.into_name().to_string();
        let subdomain_name = normalized_record_name(&name_str, &domain);

        let to_remove = build_values(record_type, &records)?;
        let existing = self
            .list_existing(&domain, &subdomain_name, type_str)
            .await?;

        let Some(prev) = existing.first() else {
            return Ok(());
        };
        let current_values: Vec<String> = prev
            .resource_records
            .resource_record
            .iter()
            .map(|r| r.value.clone())
            .collect();
        let remaining: Vec<String> = current_values
            .iter()
            .filter(|v| !to_remove.iter().any(|r| r == *v))
            .cloned()
            .collect();
        if remaining.len() == current_values.len() {
            return Ok(());
        }

        let mut changes: Vec<Change> = Vec::new();
        changes.push(Change {
            action: "DELETE",
            resource_record_set: ResourceRecordSet {
                name: subdomain_name.clone(),
                record_type: type_str,
                ttl: prev.ttl,
                resource_records: ResourceRecords {
                    resource_record: current_values
                        .into_iter()
                        .map(|value| ResourceRecord { value })
                        .collect(),
                },
            },
        });
        if !remaining.is_empty() {
            changes.push(Change {
                action: "CREATE",
                resource_record_set: ResourceRecordSet {
                    name: subdomain_name,
                    record_type: type_str,
                    ttl: prev.ttl,
                    resource_records: ResourceRecords {
                        resource_record: remaining
                            .into_iter()
                            .map(|value| ResourceRecord { value })
                            .collect(),
                    },
                },
            });
        }

        self.send_change(
            &domain,
            ChangeRequest {
                xmlns: XMLNS,
                change_batch: ChangeBatch {
                    comment: "Managed by dns-update".into(),
                    changes: Changes { change: changes },
                },
            },
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let type_str = dns_type_str(record_type)?;
        let name_str = name.into_name().to_string();
        let domain = origin.into_name().to_string();
        let subdomain_name = normalized_record_name(&name_str, &domain);

        let existing = self
            .list_existing(&domain, &subdomain_name, type_str)
            .await?;
        let mut out = Vec::new();
        for rrset in existing {
            for record in rrset.resource_records.resource_record {
                out.push(parse_value(record_type, &record.value)?);
            }
        }
        Ok(out)
    }

    async fn list_existing(
        &self,
        domain: &str,
        subdomain_name: &str,
        type_str: &str,
    ) -> crate::Result<Vec<ListedRecordSet>> {
        let target_name_a = subdomain_name.to_string();
        let target_name_b = if subdomain_name == "@" {
            domain.trim_end_matches('.').to_string()
        } else {
            format!("{}.{}", subdomain_name, domain.trim_end_matches('.'))
        };

        let mut out: Vec<ListedRecordSet> = Vec::new();
        let mut next_name: Option<String> = Some(target_name_b.clone());
        let mut next_type: Option<String> = Some(type_str.to_string());
        let mut next_identifier: Option<String> = None;

        loop {
            let mut query = String::new();
            if let Some(n) = next_name.as_ref() {
                query.push_str(&format!("name={}", urlencode(n)));
            }
            if let Some(t) = next_type.as_ref() {
                if !query.is_empty() {
                    query.push('&');
                }
                query.push_str(&format!("type={t}"));
            }
            if let Some(i) = next_identifier.as_ref() {
                if !query.is_empty() {
                    query.push('&');
                }
                query.push_str(&format!("identifier={}", urlencode(i)));
            }
            let url = if query.is_empty() {
                format!(
                    "{}/{}/hostedzone/{}/rrset",
                    self.endpoint, API_VERSION, domain
                )
            } else {
                format!(
                    "{}/{}/hostedzone/{}/rrset?{}",
                    self.endpoint, API_VERSION, domain, query
                )
            };
            let response = self.signed(self.client.get(url)).send_raw().await?;
            if response.contains("<Error>") {
                let parsed: Result<ErrorResponse, _> = quick_xml::de::from_str(&response);
                if let Ok(err) = parsed {
                    return Err(Error::Api(format!(
                        "Nifcloud error {}: {}",
                        err.error.code, err.error.message
                    )));
                }
                return Err(Error::Api(format!("Nifcloud error response: {response}")));
            }
            let list: ListResponse = quick_xml::de::from_str(&response)
                .map_err(|e| Error::Serialize(format!("XML deserialization failed: {e}")))?;
            for rrset in list.resource_record_sets.resource_record_set {
                if rrset.set_identifier.is_some() {
                    continue;
                }
                if rrset.record_type != type_str {
                    continue;
                }
                let candidate = rrset.name.trim_end_matches('.');
                if candidate == target_name_a.trim_end_matches('.')
                    || candidate == target_name_b.trim_end_matches('.')
                {
                    out.push(rrset);
                }
            }
            if list.is_truncated.eq_ignore_ascii_case("true")
                && (list.next_record_name.is_some() || list.next_record_identifier.is_some())
            {
                next_name = list.next_record_name;
                next_type = list.next_record_type;
                next_identifier = list.next_record_identifier;
                continue;
            }
            break;
        }
        Ok(out)
    }

    async fn send_change(&self, domain: &str, body: ChangeRequest) -> crate::Result<String> {
        let xml_body = xml_to_string(&body)
            .map_err(|e| Error::Serialize(format!("XML serialization failed: {e}")))?;
        let payload = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", xml_body);
        let url = format!(
            "{}/{}/hostedzone/{}/rrset",
            self.endpoint, API_VERSION, domain
        );
        let response = self
            .signed(self.client.post(url).with_raw_body(payload))
            .send_raw()
            .await?;
        if response.contains("<Error>") {
            let parsed: Result<ErrorResponse, _> = quick_xml::de::from_str(&response);
            if let Ok(err) = parsed {
                return Err(Error::Api(format!(
                    "Nifcloud error {}: {}",
                    err.error.code, err.error.message
                )));
            }
            return Err(Error::Api(format!("Nifcloud error response: {response}")));
        }
        let _info: ChangeResponse = quick_xml::de::from_str(&response)
            .map_err(|e| Error::Serialize(format!("XML deserialization failed: {e}")))?;
        Ok(response)
    }
}

fn urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    out
}

fn normalized_record_name(name: &str, domain: &str) -> String {
    let unfqdn = name.trim_end_matches('.');
    let domain = domain.trim_end_matches('.');
    if unfqdn == domain {
        "@".to_string()
    } else if let Some(prefix) = unfqdn.strip_suffix(&format!(".{}", domain)) {
        prefix.to_string()
    } else {
        unfqdn.to_string()
    }
}

fn values_equal(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut a_sorted: Vec<&String> = a.iter().collect();
    let mut b_sorted: Vec<&String> = b.iter().collect();
    a_sorted.sort();
    b_sorted.sort();
    a_sorted == b_sorted
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> crate::Result<()> {
    for record in records {
        if record.as_type() != expected {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected.as_str(),
                record.as_type().as_str(),
            )));
        }
    }
    Ok(())
}

fn dns_type_str(record_type: DnsRecordType) -> crate::Result<&'static str> {
    match record_type {
        DnsRecordType::A => Ok("A"),
        DnsRecordType::AAAA => Ok("AAAA"),
        DnsRecordType::CNAME => Ok("CNAME"),
        DnsRecordType::NS => Ok("NS"),
        DnsRecordType::MX => Ok("MX"),
        DnsRecordType::TXT => Ok("TXT"),
        DnsRecordType::SRV => Err(Error::Api(
            "SRV records are not supported by Nifcloud".into(),
        )),
        DnsRecordType::CAA => Err(Error::Api(
            "CAA records are not supported by Nifcloud".into(),
        )),
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by Nifcloud".into(),
        )),
    }
}

fn build_values(record_type: DnsRecordType, records: &[DnsRecord]) -> crate::Result<Vec<String>> {
    dns_type_str(record_type)?;
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        out.push(build_value(record)?);
    }
    Ok(out)
}

fn build_value(record: &DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(target) => target.clone(),
        DnsRecord::NS(target) => target.clone(),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, mx.exchange),
        DnsRecord::TXT(text) => {
            let mut out = String::new();
            txt_chunks_to_text(&mut out, text, " ");
            out
        }
        DnsRecord::SRV(_) => {
            return Err(Error::Api(
                "SRV records are not supported by Nifcloud".into(),
            ));
        }
        DnsRecord::CAA(_) => {
            return Err(Error::Api(
                "CAA records are not supported by Nifcloud".into(),
            ));
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Nifcloud".into(),
            ));
        }
    })
}

fn parse_value(record_type: DnsRecordType, value: &str) -> crate::Result<DnsRecord> {
    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(
            value
                .parse()
                .map_err(|e| Error::Parse(format!("invalid A value: {e}")))?,
        ),
        DnsRecordType::AAAA => DnsRecord::AAAA(
            value
                .parse()
                .map_err(|e| Error::Parse(format!("invalid AAAA value: {e}")))?,
        ),
        DnsRecordType::CNAME => DnsRecord::CNAME(value.trim_end_matches('.').to_string()),
        DnsRecordType::NS => DnsRecord::NS(value.trim_end_matches('.').to_string()),
        DnsRecordType::MX => {
            let (prio, exchange) = value
                .split_once(' ')
                .ok_or_else(|| Error::Parse(format!("invalid MX value: {value}")))?;
            DnsRecord::MX(MXRecord {
                priority: prio
                    .trim()
                    .parse()
                    .map_err(|e| Error::Parse(format!("invalid MX priority: {e}")))?,
                exchange: exchange.trim().trim_end_matches('.').to_string(),
            })
        }
        DnsRecordType::TXT => DnsRecord::TXT(unquote_txt(value)),
        DnsRecordType::SRV => {
            return Err(Error::Api(
                "SRV records are not supported by Nifcloud".into(),
            ));
        }
        DnsRecordType::CAA => {
            return Err(Error::Api(
                "CAA records are not supported by Nifcloud".into(),
            ));
        }
        DnsRecordType::TLSA => {
            return Err(Error::Api(
                "TLSA records are not supported by Nifcloud".into(),
            ));
        }
    })
}

fn unquote_txt(content: &str) -> String {
    let trimmed = content.trim();
    let mut out = String::new();
    let mut chars = trimmed.chars().peekable();
    let mut in_quotes = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            '\\' => {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            c if !in_quotes && c.is_whitespace() => {}
            c => out.push(c),
        }
    }
    out
}
