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
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, KeyValue, MXRecord, SRVRecord,
    TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector, crypto, utils::strip_origin_from_name,
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct OvhProvider {
    application_key: String,
    application_secret: String,
    consumer_key: String,
    pub(crate) endpoint: String,
    timeout: Duration,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OvhRecordFormat {
    pub field_type: String,
    pub target: String,
}

#[derive(Deserialize, Debug)]
struct OvhRecordBody {
    id: u64,
    #[serde(rename = "fieldType")]
    field_type: String,
    target: String,
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
        match record {
            DnsRecord::A(content) => OvhRecordFormat {
                field_type: "A".to_string(),
                target: content.to_string(),
            },
            DnsRecord::AAAA(content) => OvhRecordFormat {
                field_type: "AAAA".to_string(),
                target: content.to_string(),
            },
            DnsRecord::CNAME(content) => OvhRecordFormat {
                field_type: "CNAME".to_string(),
                target: format!("{}.", content.trim_end_matches('.')),
            },
            DnsRecord::NS(content) => OvhRecordFormat {
                field_type: "NS".to_string(),
                target: format!("{}.", content.trim_end_matches('.')),
            },
            DnsRecord::MX(mx) => OvhRecordFormat {
                field_type: "MX".to_string(),
                target: format!("{} {}.", mx.priority, mx.exchange.trim_end_matches('.')),
            },
            DnsRecord::TXT(content) => OvhRecordFormat {
                field_type: "TXT".to_string(),
                target: content.clone(),
            },
            DnsRecord::SRV(srv) => OvhRecordFormat {
                field_type: "SRV".to_string(),
                target: format!(
                    "{} {} {} {}.",
                    srv.priority,
                    srv.weight,
                    srv.port,
                    srv.target.trim_end_matches('.')
                ),
            },
            DnsRecord::TLSA(tlsa) => OvhRecordFormat {
                field_type: "TLSA".to_string(),
                target: tlsa.to_string(),
            },
            DnsRecord::CAA(caa) => OvhRecordFormat {
                field_type: "CAA".to_string(),
                target: caa.to_string(),
            },
        }
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
        Ok(Self {
            application_key: application_key.as_ref().to_string(),
            application_secret: application_secret.as_ref().to_string(),
            consumer_key: consumer_key.as_ref().to_string(),
            endpoint: endpoint.api_url().to_string(),
            timeout: timeout.unwrap_or(Duration::from_secs(30)),
        })
    }

    fn generate_signature(&self, method: &str, url: &str, body: &str, timestamp: u64) -> String {
        let data = format!(
            "{}+{}+{}+{}+{}+{}",
            self.application_secret, self.consumer_key, method, url, body, timestamp
        );

        let hash = crypto::sha1_digest(data.as_bytes());
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

    async fn list_record_ids(
        &self,
        zone: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<u64>> {
        let url = format!(
            "{}/domain/zone/{}/record?fieldType={}&subDomain={}",
            self.endpoint,
            zone,
            record_type.as_str(),
            subdomain
        );
        let response = self
            .send_authenticated_request(Method::GET, &url, "")
            .await?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "Failed to list records: HTTP {}",
                response.status()
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Api(format!("Failed to fetch record list: {}", e)))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Error::Api(format!("Failed to parse record list: {}", e)))
    }

    async fn fetch_record(&self, zone: &str, id: u64) -> crate::Result<OvhRecordBody> {
        let url = format!("{}/domain/zone/{}/record/{}", self.endpoint, zone, id);
        let response = self
            .send_authenticated_request(Method::GET, &url, "")
            .await?;

        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "Failed to fetch record {}: HTTP {}",
                id,
                response.status()
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Api(format!("Failed to read record {}: {}", id, e)))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Error::Api(format!("Failed to parse record {}: {}", id, e)))
    }

    async fn list_at(
        &self,
        zone: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<OvhRecordBody>> {
        let ids = self.list_record_ids(zone, subdomain, record_type).await?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let body = self.fetch_record(zone, id).await?;
            if body.field_type == record_type.as_str() {
                out.push(body);
            }
        }
        Ok(out)
    }

    async fn refresh_zone(&self, zone: &str) -> crate::Result<()> {
        let url = format!("{}/domain/zone/{}/refresh", self.endpoint, zone);
        let response = self
            .send_authenticated_request(Method::POST, &url, "")
            .await?;
        if !response.status().is_success() {
            return Err(Error::Api(format!(
                "Failed to refresh zone: HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }

    async fn post_record(
        &self,
        zone: &str,
        subdomain: &str,
        ttl: u32,
        wire: &OvhRecordFormat,
    ) -> crate::Result<()> {
        let params = CreateDnsRecordParams {
            field_type: wire.field_type.clone(),
            sub_domain: subdomain.to_string(),
            target: wire.target.clone(),
            ttl,
        };
        let body = serde_json::to_string(&params)
            .map_err(|e| Error::Serialize(format!("Failed to serialize record: {}", e)))?;

        let url = format!("{}/domain/zone/{}/record", self.endpoint, zone);
        let response = self
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
        Ok(())
    }

    async fn delete_record_id(&self, zone: &str, id: u64) -> crate::Result<()> {
        let url = format!("{}/domain/zone/{}/record/{}", self.endpoint, zone, id);
        let response = self
            .send_authenticated_request(Method::DELETE, &url, "")
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Api(format!(
                "Failed to delete record {}: HTTP {} - {}",
                id, status, error_text
            )));
        }
        Ok(())
    }

    fn subdomain_for<'a>(&self, zone: &str, name: impl IntoFqdn<'a>) -> String {
        let name = name.into_name();
        let subdomain = strip_origin_from_name(&name, zone, Some(""));
        if subdomain == "@" {
            String::new()
        } else {
            subdomain
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
        let desired = build_wire(record_type, &records)?;
        let zone = self.get_zone_name(origin).await?;
        let subdomain = self.subdomain_for(&zone, name);

        let existing = self.list_at(&zone, &subdomain, record_type).await?;

        let mut to_add: Vec<OvhRecordFormat> = Vec::new();
        let mut leftovers: Vec<&OvhRecordBody> = existing.iter().collect();

        for wanted in &desired {
            if let Some(pos) = leftovers
                .iter()
                .position(|e| e.field_type == wanted.field_type && e.target == wanted.target)
            {
                leftovers.swap_remove(pos);
            } else {
                to_add.push(wanted.clone());
            }
        }

        let mut mutated = false;
        for stale in leftovers {
            self.delete_record_id(&zone, stale.id).await?;
            mutated = true;
        }
        for wire in to_add {
            self.post_record(&zone, &subdomain, ttl, &wire).await?;
            mutated = true;
        }

        if mutated {
            self.refresh_zone(&zone).await?;
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
        if records.is_empty() {
            return Ok(());
        }
        let desired = build_wire(record_type, &records)?;
        let zone = self.get_zone_name(origin).await?;
        let subdomain = self.subdomain_for(&zone, name);

        let existing = self.list_at(&zone, &subdomain, record_type).await?;

        let mut mutated = false;
        for wire in desired {
            if existing
                .iter()
                .any(|e| e.field_type == wire.field_type && e.target == wire.target)
            {
                continue;
            }
            self.post_record(&zone, &subdomain, ttl, &wire).await?;
            mutated = true;
        }

        if mutated {
            self.refresh_zone(&zone).await?;
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
        if records.is_empty() {
            return Ok(());
        }
        let to_remove = build_wire(record_type, &records)?;
        let zone = self.get_zone_name(origin).await?;
        let subdomain = self.subdomain_for(&zone, name);

        let existing = self.list_at(&zone, &subdomain, record_type).await?;

        let mut mutated = false;
        for wire in to_remove {
            if let Some(entry) = existing
                .iter()
                .find(|e| e.field_type == wire.field_type && e.target == wire.target)
            {
                self.delete_record_id(&zone, entry.id).await?;
                mutated = true;
            }
        }

        if mutated {
            self.refresh_zone(&zone).await?;
        }
        Ok(())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let zone = self.get_zone_name(origin).await?;
        let subdomain = self.subdomain_for(&zone, name);
        let existing = self.list_at(&zone, &subdomain, record_type).await?;
        existing
            .into_iter()
            .map(|e| parse_ovh_target(record_type, &e.target))
            .collect()
    }
}

fn build_wire(
    expected_type: DnsRecordType,
    records: &[DnsRecord],
) -> crate::Result<Vec<OvhRecordFormat>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(record.into());
    }
    Ok(out)
}

fn parse_ovh_target(record_type: DnsRecordType, target: &str) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => target
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A target {}: {}", target, e))),
        DnsRecordType::AAAA => target
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA target {}: {}", target, e))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(target.to_string())),
        DnsRecordType::NS => Ok(DnsRecord::NS(target.to_string())),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(target.to_string())),
        DnsRecordType::MX => {
            let mut parts = target.splitn(2, char::is_whitespace);
            let priority = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid MX target: {}", target)))?
                .parse::<u16>()
                .map_err(|e| Error::Parse(format!("invalid MX priority in {}: {}", target, e)))?;
            let exchange = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("MX target missing exchange: {}", target)))?
                .trim()
                .to_string();
            Ok(DnsRecord::MX(MXRecord { exchange, priority }))
        }
        DnsRecordType::SRV => {
            let mut parts = target.split_whitespace();
            let priority = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid SRV target: {}", target)))?
                .parse::<u16>()
                .map_err(|e| Error::Parse(format!("invalid SRV priority in {}: {}", target, e)))?;
            let weight = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid SRV target: {}", target)))?
                .parse::<u16>()
                .map_err(|e| Error::Parse(format!("invalid SRV weight in {}: {}", target, e)))?;
            let port = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid SRV target: {}", target)))?
                .parse::<u16>()
                .map_err(|e| Error::Parse(format!("invalid SRV port in {}: {}", target, e)))?;
            let srv_target = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("SRV target missing host: {}", target)))?
                .to_string();
            Ok(DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target: srv_target,
            }))
        }
        DnsRecordType::TLSA => {
            let mut parts = target.split_whitespace();
            let usage = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid TLSA target: {}", target)))?
                .parse::<u8>()
                .map_err(|e| Error::Parse(format!("invalid TLSA usage in {}: {}", target, e)))?;
            let selector = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid TLSA target: {}", target)))?
                .parse::<u8>()
                .map_err(|e| Error::Parse(format!("invalid TLSA selector in {}: {}", target, e)))?;
            let matching = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid TLSA target: {}", target)))?
                .parse::<u8>()
                .map_err(|e| Error::Parse(format!("invalid TLSA matching in {}: {}", target, e)))?;
            let cert_hex = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("TLSA target missing data: {}", target)))?;
            Ok(DnsRecord::TLSA(TLSARecord {
                cert_usage: tlsa_cert_usage_from_u8(usage)?,
                selector: tlsa_selector_from_u8(selector)?,
                matching: tlsa_matching_from_u8(matching)?,
                cert_data: decode_hex(cert_hex)?,
            }))
        }
        DnsRecordType::CAA => parse_caa(target),
    }
}

fn tlsa_cert_usage_from_u8(value: u8) -> crate::Result<TlsaCertUsage> {
    Ok(match value {
        0 => TlsaCertUsage::PkixTa,
        1 => TlsaCertUsage::PkixEe,
        2 => TlsaCertUsage::DaneTa,
        3 => TlsaCertUsage::DaneEe,
        255 => TlsaCertUsage::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA cert usage: {}", value))),
    })
}

fn tlsa_selector_from_u8(value: u8) -> crate::Result<TlsaSelector> {
    Ok(match value {
        0 => TlsaSelector::Full,
        1 => TlsaSelector::Spki,
        255 => TlsaSelector::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA selector: {}", value))),
    })
}

fn tlsa_matching_from_u8(value: u8) -> crate::Result<TlsaMatching> {
    Ok(match value {
        0 => TlsaMatching::Raw,
        1 => TlsaMatching::Sha256,
        2 => TlsaMatching::Sha512,
        255 => TlsaMatching::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA matching: {}", value))),
    })
}

fn decode_hex(hex: &str) -> crate::Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::Parse(format!("invalid hex string: {}", hex)));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| Error::Parse(format!("invalid hex byte: {}", e)))
        })
        .collect()
}

fn parse_caa(target: &str) -> crate::Result<DnsRecord> {
    let mut parts = target.splitn(3, char::is_whitespace);
    let flags = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA target: {}", target)))?
        .parse::<u8>()
        .map_err(|e| Error::Parse(format!("invalid CAA flags in {}: {}", target, e)))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("CAA target missing tag: {}", target)))?
        .to_string();
    let raw_value = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("CAA target missing value: {}", target)))?
        .trim();
    let unquoted_full = strip_caa_quotes(raw_value);

    let issuer_critical = flags & 0x80 != 0;
    match tag.as_str() {
        "issue" => {
            let (name, options) = parse_caa_value(&unquoted_full);
            Ok(DnsRecord::CAA(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }))
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(&unquoted_full);
            Ok(DnsRecord::CAA(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            }))
        }
        "iodef" => Ok(DnsRecord::CAA(CAARecord::Iodef {
            issuer_critical,
            url: unquoted_full,
        })),
        other => Err(Error::Parse(format!("unknown CAA tag: {}", other))),
    }
}

fn strip_caa_quotes(s: &str) -> String {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        inner.to_string()
    } else {
        s.to_string()
    }
}

fn parse_caa_value(value: &str) -> (Option<String>, Vec<KeyValue>) {
    let mut parts = value.split(';').map(str::trim);
    let name_part = parts.next().unwrap_or("").trim().to_string();
    let name = if name_part.is_empty() {
        None
    } else {
        Some(name_part)
    };
    let options = parts
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => KeyValue {
                key: k.trim().to_string(),
                value: v.trim().to_string(),
            },
            None => KeyValue {
                key: p.trim().to_string(),
                value: String::new(),
            },
        })
        .collect();
    (name, options)
}
