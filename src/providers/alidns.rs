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

use std::time::Duration;

use chrono::Utc;
use serde::Deserialize;

use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, KeyValue, MXRecord, SRVRecord,
    crypto::{hmac_sha256, sha256_digest},
    http::{HttpClient, HttpClientBuilder},
    utils::strip_origin_from_name,
};

const DEFAULT_HOST: &str = "alidns.aliyuncs.com";
const API_VERSION: &str = "2015-01-09";
const ALGORITHM: &str = "ACS3-HMAC-SHA256";

#[derive(Clone)]
pub struct AlidnsProvider {
    client: HttpClient,
    access_key: String,
    secret_key: String,
    security_token: Option<String>,
    line: Option<String>,
    endpoint: String,
    host: String,
}

#[derive(Deserialize, Debug)]
struct ApiError {
    #[serde(rename = "Code", default)]
    code: String,
    #[serde(rename = "Message", default)]
    message: String,
}

#[derive(Deserialize, Debug)]
struct DescribeDomainsResponse {
    #[serde(rename = "Domains", default)]
    domains: Option<DomainsField>,
    #[serde(rename = "TotalCount", default)]
    total_count: u64,
    #[serde(rename = "PageSize", default)]
    page_size: u64,
}

#[derive(Deserialize, Debug, Clone)]
struct DomainsField {
    #[serde(rename = "Domain", default)]
    domain: Vec<Domain>,
}

#[derive(Deserialize, Debug, Clone)]
struct Domain {
    #[serde(rename = "DomainName")]
    domain_name: String,
    #[serde(rename = "PunyCode", default)]
    puny_code: String,
}

#[derive(Deserialize, Debug)]
struct DescribeDomainRecordsResponse {
    #[serde(rename = "DomainRecords", default)]
    domain_records: Option<DomainRecordsField>,
}

#[derive(Deserialize, Debug, Clone)]
struct DomainRecordsField {
    #[serde(rename = "Record", default)]
    record: Vec<Record>,
}

#[derive(Deserialize, Debug, Clone)]
struct Record {
    #[serde(rename = "RecordId")]
    record_id: String,
    #[serde(rename = "RR")]
    rr: String,
    #[serde(rename = "Type")]
    record_type: String,
    #[serde(rename = "Value", default)]
    value: String,
    #[serde(rename = "TTL", default)]
    ttl: u32,
    #[serde(rename = "Priority", default)]
    priority: Option<u16>,
}

impl AlidnsProvider {
    pub(crate) fn new(
        access_key: impl AsRef<str>,
        secret_key: impl AsRef<str>,
        region: Option<impl AsRef<str>>,
        security_token: Option<impl AsRef<str>>,
        line: Option<impl AsRef<str>>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let client = HttpClientBuilder::default().with_timeout(timeout).build();
        let host = region
            .map(|r| {
                let region = r.as_ref();
                if region.is_empty() {
                    DEFAULT_HOST.to_string()
                } else {
                    format!("alidns.{}.aliyuncs.com", region)
                }
            })
            .unwrap_or_else(|| DEFAULT_HOST.to_string());
        Ok(Self {
            client,
            access_key: access_key.as_ref().to_string(),
            secret_key: secret_key.as_ref().to_string(),
            security_token: security_token.map(|s| s.as_ref().to_string()),
            line: line
                .map(|l| l.as_ref().to_string())
                .filter(|s| !s.is_empty()),
            endpoint: format!("https://{}", host),
            host,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        let url = endpoint.as_ref().to_string();
        let host = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .map(|s| s.split('/').next().unwrap_or(s).to_string())
            .unwrap_or_else(|| DEFAULT_HOST.to_string());
        Self {
            endpoint: url,
            host,
            ..self
        }
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        let name = name.into_name();
        let origin = origin.into_name();
        let zone = self.find_zone(&origin).await?;
        let rr = strip_origin_from_name(&name, &zone, Some("@"));
        let type_str = record_type.as_str();

        if records.is_empty() {
            return self.delete_sub_domain_records(&zone, &rr, type_str).await;
        }

        let desired = build_alidns_records(records)?;
        let mut existing = self.list_rrset_records(&zone, &rr, type_str).await?;

        let mut to_add: Vec<&AlidnsRecord> = Vec::new();
        for d in &desired {
            if let Some(idx) = existing
                .iter()
                .position(|c| c.value == d.value && c.priority == d.priority)
            {
                existing.swap_remove(idx);
            } else {
                to_add.push(d);
            }
        }

        for stale in &existing {
            self.delete_domain_record(&stale.record_id).await?;
        }
        for d in to_add {
            self.add_domain_record(&zone, &rr, ttl, d).await?;
        }
        Ok(())
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name();
        let origin = origin.into_name();
        let zone = self.find_zone(&origin).await?;
        let rr = strip_origin_from_name(&name, &zone, Some("@"));
        let type_str = record_type.as_str();

        let desired = build_alidns_records(records)?;
        let existing = self.list_rrset_records(&zone, &rr, type_str).await?;

        for d in &desired {
            if existing
                .iter()
                .any(|c| c.value == d.value && c.priority == d.priority)
            {
                continue;
            }
            self.add_domain_record(&zone, &rr, ttl, d).await?;
        }
        Ok(())
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name();
        let origin = origin.into_name();
        let zone = self.find_zone(&origin).await?;
        let rr = strip_origin_from_name(&name, &zone, Some("@"));
        let type_str = record_type.as_str();

        let to_remove = build_alidns_records(records)?;
        let existing = self.list_rrset_records(&zone, &rr, type_str).await?;

        for d in &to_remove {
            if let Some(entry) = existing
                .iter()
                .find(|c| c.value == d.value && c.priority == d.priority)
            {
                self.delete_domain_record(&entry.record_id).await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let name = name.into_name();
        let origin = origin.into_name();
        let zone = self.find_zone(&origin).await?;
        let rr = strip_origin_from_name(&name, &zone, Some("@"));
        let type_str = record_type.as_str();
        let listed = self.list_rrset_records(&zone, &rr, type_str).await?;
        let mut out = Vec::with_capacity(listed.len());
        for r in listed {
            out.push(record_from_listed(record_type, &r)?);
        }
        Ok(out)
    }

    async fn list_rrset_records(
        &self,
        zone: &str,
        rr: &str,
        record_type: &str,
    ) -> crate::Result<Vec<ListedRrsetRecord>> {
        let params = vec![
            ("Action".to_string(), "DescribeDomainRecords".to_string()),
            ("DomainName".to_string(), zone.to_string()),
            ("RRKeyWord".to_string(), rr.to_string()),
            ("TypeKeyWord".to_string(), record_type.to_string()),
            ("SearchMode".to_string(), "EXACT".to_string()),
            ("PageSize".to_string(), "500".to_string()),
        ];
        let raw = self.send(params).await?;
        let resp: DescribeDomainRecordsResponse = serde_json::from_str(&raw).map_err(|err| {
            Error::Serialize(format!(
                "Failed to parse Alidns DescribeDomainRecords: {err}"
            ))
        })?;
        let records = resp
            .domain_records
            .map(|f| f.record)
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.rr == rr && r.record_type == record_type)
            .map(|r| ListedRrsetRecord {
                record_id: r.record_id,
                value: r.value,
                ttl: r.ttl,
                priority: r.priority,
            })
            .collect();
        Ok(records)
    }

    async fn add_domain_record(
        &self,
        zone: &str,
        rr: &str,
        ttl: u32,
        record: &AlidnsRecord,
    ) -> crate::Result<()> {
        let mut params = vec![
            ("Action".to_string(), "AddDomainRecord".to_string()),
            ("DomainName".to_string(), zone.to_string()),
            ("RR".to_string(), rr.to_string()),
            ("Type".to_string(), record.record_type.clone()),
            ("Value".to_string(), record.value.clone()),
            ("TTL".to_string(), ttl.to_string()),
        ];
        if let Some(line) = &self.line {
            params.push(("Line".to_string(), line.clone()));
        }
        if let Some(priority) = record.priority {
            params.push(("Priority".to_string(), priority.to_string()));
        }
        self.send(params).await.map(|_| ())
    }

    async fn delete_domain_record(&self, record_id: &str) -> crate::Result<()> {
        let params = vec![
            ("Action".to_string(), "DeleteDomainRecord".to_string()),
            ("RecordId".to_string(), record_id.to_string()),
        ];
        self.send(params).await.map(|_| ())
    }

    async fn delete_sub_domain_records(
        &self,
        zone: &str,
        rr: &str,
        record_type: &str,
    ) -> crate::Result<()> {
        let params = vec![
            ("Action".to_string(), "DeleteSubDomainRecords".to_string()),
            ("DomainName".to_string(), zone.to_string()),
            ("RR".to_string(), rr.to_string()),
            ("Type".to_string(), record_type.to_string()),
        ];
        self.send(params).await.map(|_| ())
    }

    async fn find_zone(&self, origin: &str) -> crate::Result<String> {
        let zone_name = origin.trim_end_matches('.').to_string();
        let mut page: u64 = 1;
        let mut collected: Vec<Domain> = Vec::new();
        loop {
            let params = vec![
                ("Action".to_string(), "DescribeDomains".to_string()),
                ("PageNumber".to_string(), page.to_string()),
                ("PageSize".to_string(), "100".to_string()),
            ];
            let raw = self.send(params).await?;
            let resp: DescribeDomainsResponse = serde_json::from_str(&raw).map_err(|err| {
                Error::Serialize(format!("Failed to parse Alidns DescribeDomains: {err}"))
            })?;
            if let Some(field) = &resp.domains {
                collected.extend(field.domain.iter().cloned());
            }
            let fetched = page * resp.page_size.max(1);
            if fetched >= resp.total_count
                || resp
                    .domains
                    .as_ref()
                    .map(|f| f.domain.is_empty())
                    .unwrap_or(true)
            {
                break;
            }
            page += 1;
        }

        collected
            .into_iter()
            .find(|d| d.domain_name == zone_name || d.puny_code == zone_name)
            .map(|d| d.domain_name)
            .ok_or_else(|| Error::Api(format!("Alidns zone not found for {}", zone_name)))
    }

    async fn send(&self, mut params: Vec<(String, String)>) -> crate::Result<String> {
        params.push(("Version".to_string(), API_VERSION.to_string()));
        params.sort_by(|a, b| a.0.cmp(&b.0));
        let canonical_querystring = params
            .iter()
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let url = format!("{}/?{}", self.endpoint, canonical_querystring);

        let now = Utc::now();
        let amz_date = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let nonce = format!(
            "{}{}",
            now.timestamp_nanos_opt().unwrap_or(0),
            now.timestamp_subsec_nanos()
        );

        let payload_hash = hex::encode(sha256_digest(b""));

        let mut canonical_headers_pairs: Vec<(String, String)> = vec![
            ("host".to_string(), self.host.clone()),
            ("x-acs-action".to_string(), action_from_params(&params)),
            ("x-acs-content-sha256".to_string(), payload_hash.clone()),
            ("x-acs-date".to_string(), amz_date.clone()),
            ("x-acs-signature-nonce".to_string(), nonce.clone()),
            ("x-acs-version".to_string(), API_VERSION.to_string()),
        ];
        if let Some(token) = &self.security_token {
            canonical_headers_pairs.push(("x-acs-security-token".to_string(), token.clone()));
        }
        canonical_headers_pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let canonical_headers = canonical_headers_pairs
            .iter()
            .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
            .collect::<String>();
        let signed_headers = canonical_headers_pairs
            .iter()
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>()
            .join(";");

        let canonical_request = format!(
            "GET\n/\n{}\n{}\n{}\n{}",
            canonical_querystring, canonical_headers, signed_headers, payload_hash
        );
        let canonical_request_hash = hex::encode(sha256_digest(canonical_request.as_bytes()));

        let string_to_sign = format!("{}\n{}", ALGORITHM, canonical_request_hash);
        let signature = hex::encode(hmac_sha256(
            self.secret_key.as_bytes(),
            string_to_sign.as_bytes(),
        ));

        let authorization = format!(
            "{} Credential={},SignedHeaders={},Signature={}",
            ALGORITHM, self.access_key, signed_headers, signature
        );

        let mut request = self
            .client
            .get(url)
            .with_header("Authorization", authorization)
            .with_header("Host", self.host.clone())
            .with_header("x-acs-action", action_from_params(&params))
            .with_header("x-acs-content-sha256", payload_hash)
            .with_header("x-acs-date", amz_date)
            .with_header("x-acs-signature-nonce", nonce)
            .with_header("x-acs-version", API_VERSION);
        if let Some(token) = &self.security_token {
            request = request.with_header("x-acs-security-token", token.clone());
        }

        let raw = request.send_raw().await?;
        if let Ok(error) = serde_json::from_str::<ApiError>(&raw)
            && !error.code.is_empty()
        {
            return Err(Error::Api(format!(
                "Alidns error {}: {}",
                error.code, error.message
            )));
        }
        Ok(raw)
    }
}

fn action_from_params(params: &[(String, String)]) -> String {
    params
        .iter()
        .find(|(k, _)| k == "Action")
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            other => {
                out.push('%');
                out.push_str(&format!("{:02X}", other));
            }
        }
    }
    out
}

#[derive(Debug, Clone)]
struct ListedRrsetRecord {
    record_id: String,
    value: String,
    #[allow(dead_code)]
    ttl: u32,
    priority: Option<u16>,
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

fn build_alidns_records(records: Vec<DnsRecord>) -> crate::Result<Vec<AlidnsRecord>> {
    let mut out = Vec::with_capacity(records.len());
    for r in records {
        out.push(AlidnsRecord::try_from(r)?);
    }
    Ok(out)
}

fn record_from_listed(
    record_type: DnsRecordType,
    listed: &ListedRrsetRecord,
) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => {
            listed.value.parse().map(DnsRecord::A).map_err(|e| {
                Error::Parse(format!("Invalid A record value '{}': {}", listed.value, e))
            })
        }
        DnsRecordType::AAAA => listed.value.parse().map(DnsRecord::AAAA).map_err(|e| {
            Error::Parse(format!(
                "Invalid AAAA record value '{}': {}",
                listed.value, e
            ))
        }),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(listed.value.clone())),
        DnsRecordType::NS => Ok(DnsRecord::NS(listed.value.clone())),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(listed.value.clone())),
        DnsRecordType::MX => Ok(DnsRecord::MX(MXRecord {
            exchange: listed.value.clone(),
            priority: listed.priority.unwrap_or(0),
        })),
        DnsRecordType::SRV => parse_srv_value(&listed.value).map(DnsRecord::SRV),
        DnsRecordType::CAA => parse_caa_value(&listed.value).map(DnsRecord::CAA),
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by Alibaba Cloud DNS".to_string(),
        )),
    }
}

fn parse_srv_value(value: &str) -> crate::Result<SRVRecord> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 4 {
        return Err(Error::Parse(format!(
            "Invalid SRV record value '{}': expected 4 fields",
            value
        )));
    }
    let priority = parts[0]
        .parse::<u16>()
        .map_err(|e| Error::Parse(format!("Invalid SRV priority '{}': {}", parts[0], e)))?;
    let weight = parts[1]
        .parse::<u16>()
        .map_err(|e| Error::Parse(format!("Invalid SRV weight '{}': {}", parts[1], e)))?;
    let port = parts[2]
        .parse::<u16>()
        .map_err(|e| Error::Parse(format!("Invalid SRV port '{}': {}", parts[2], e)))?;
    Ok(SRVRecord {
        priority,
        weight,
        port,
        target: parts[3].to_string(),
    })
}

fn parse_caa_value(value: &str) -> crate::Result<CAARecord> {
    let trimmed = value.trim();
    let (flags_str, rest) = trimmed.split_once(char::is_whitespace).ok_or_else(|| {
        Error::Parse(format!("Invalid CAA record value '{}': missing tag", value))
    })?;
    let flags: u8 = flags_str
        .parse()
        .map_err(|e| Error::Parse(format!("Invalid CAA flags '{}': {}", flags_str, e)))?;
    let rest = rest.trim_start();
    let (tag, raw_value) = rest.split_once(char::is_whitespace).ok_or_else(|| {
        Error::Parse(format!(
            "Invalid CAA record value '{}': missing value",
            value
        ))
    })?;
    let raw_value = raw_value.trim();
    let unquoted = raw_value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(raw_value);
    let issuer_critical = flags & 0x80 != 0;
    match tag.to_ascii_lowercase().as_str() {
        "issue" => Ok(CAARecord::Issue {
            issuer_critical,
            name: parse_caa_name_and_options(unquoted).0,
            options: parse_caa_name_and_options(unquoted).1,
        }),
        "issuewild" => Ok(CAARecord::IssueWild {
            issuer_critical,
            name: parse_caa_name_and_options(unquoted).0,
            options: parse_caa_name_and_options(unquoted).1,
        }),
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: unquoted.to_string(),
        }),
        other => Err(Error::Parse(format!("Unknown CAA tag '{}'", other))),
    }
}

fn parse_caa_name_and_options(unquoted: &str) -> (Option<String>, Vec<KeyValue>) {
    let mut parts = unquoted.split(';');
    let name_part = parts.next().unwrap_or("").trim();
    let name = if name_part.is_empty() {
        None
    } else {
        Some(name_part.to_string())
    };
    let options = parts
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => KeyValue {
                key: k.trim().to_string(),
                value: v.trim().to_string(),
            },
            None => KeyValue {
                key: p.to_string(),
                value: String::new(),
            },
        })
        .collect();
    (name, options)
}

#[derive(Debug)]
pub(crate) struct AlidnsRecord {
    pub record_type: String,
    pub value: String,
    pub priority: Option<u16>,
}

impl TryFrom<DnsRecord> for AlidnsRecord {
    type Error = Error;

    fn try_from(record: DnsRecord) -> Result<Self, Self::Error> {
        match record {
            DnsRecord::A(addr) => Ok(AlidnsRecord {
                record_type: "A".to_string(),
                value: addr.to_string(),
                priority: None,
            }),
            DnsRecord::AAAA(addr) => Ok(AlidnsRecord {
                record_type: "AAAA".to_string(),
                value: addr.to_string(),
                priority: None,
            }),
            DnsRecord::CNAME(target) => Ok(AlidnsRecord {
                record_type: "CNAME".to_string(),
                value: target.trim_end_matches('.').to_string(),
                priority: None,
            }),
            DnsRecord::NS(target) => Ok(AlidnsRecord {
                record_type: "NS".to_string(),
                value: target.trim_end_matches('.').to_string(),
                priority: None,
            }),
            DnsRecord::MX(mx) => Ok(AlidnsRecord {
                record_type: "MX".to_string(),
                value: mx.exchange.trim_end_matches('.').to_string(),
                priority: Some(mx.priority),
            }),
            DnsRecord::TXT(text) => Ok(AlidnsRecord {
                record_type: "TXT".to_string(),
                value: text,
                priority: None,
            }),
            DnsRecord::SRV(srv) => Ok(AlidnsRecord {
                record_type: "SRV".to_string(),
                value: format!(
                    "{} {} {} {}",
                    srv.priority,
                    srv.weight,
                    srv.port,
                    srv.target.trim_end_matches('.')
                ),
                priority: None,
            }),
            DnsRecord::CAA(caa) => Ok(AlidnsRecord {
                record_type: "CAA".to_string(),
                value: caa.to_string(),
                priority: None,
            }),
            DnsRecord::TLSA(_) => Err(Error::Api(
                "TLSA records are not supported by Alibaba Cloud DNS".to_string(),
            )),
        }
    }
}
