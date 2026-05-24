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

use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, KeyValue, MXRecord, SRVRecord,
    TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector,
    http::{HttpClient, HttpClientBuilder, HttpRequest},
    jwt::rsa_sha512_sign,
    utils::strip_origin_from_name,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_API_ENDPOINT: &str = "https://api.transip.nl/v6";

#[derive(Clone)]
pub struct TransipProvider {
    auth: Arc<Mutex<AuthState>>,
    login: String,
    private_key_pem: String,
    endpoint: String,
    client: HttpClient,
}

struct AuthState {
    token: Option<(String, Instant)>,
}

#[derive(Serialize, Debug)]
struct AuthRequest<'a> {
    login: &'a str,
    nonce: String,
    read_only: bool,
    expiration_time: &'a str,
    label: String,
    global_key: bool,
}

#[derive(Deserialize, Debug)]
struct AuthResponse {
    token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DnsEntry {
    name: String,
    expire: u32,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
}

#[derive(Deserialize, Debug)]
struct DnsEntriesResponse {
    #[serde(rename = "dnsEntries", default)]
    dns_entries: Vec<DnsEntry>,
}

#[derive(Serialize, Debug)]
struct DnsEntryRequest<'a> {
    #[serde(rename = "dnsEntry")]
    dns_entry: &'a DnsEntry,
}

impl TransipProvider {
    pub(crate) fn new(
        login: impl AsRef<str>,
        private_key_pem: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let login = login.as_ref().to_string();
        let private_key_pem = private_key_pem.as_ref().to_string();
        if login.is_empty() || private_key_pem.is_empty() {
            return Err(Error::Api(
                "TransIP login and private key must not be empty".to_string(),
            ));
        }
        let client = HttpClientBuilder::default()
            .with_header("Accept", "application/json")
            .with_timeout(timeout)
            .build();
        Ok(Self {
            auth: Arc::new(Mutex::new(AuthState { token: None })),
            login,
            private_key_pem,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            client,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().trim_end_matches('/').to_string(),
            ..self
        }
    }

    #[cfg(test)]
    pub(crate) fn with_cached_token(self, token: impl Into<String>) -> Self {
        if let Ok(mut guard) = self.auth.lock() {
            guard.token = Some((token.into(), Instant::now() + Duration::from_secs(30 * 60)));
        }
        self
    }

    async fn ensure_token(&self) -> crate::Result<String> {
        {
            let guard = self
                .auth
                .lock()
                .map_err(|_| Error::Client("TransIP token lock poisoned".to_string()))?;
            if let Some((token, expiry)) = &guard.token
                && Instant::now() < *expiry
            {
                return Ok(token.clone());
            }
        }

        let nonce = generate_nonce();
        let body = AuthRequest {
            login: &self.login,
            nonce: nonce.clone(),
            read_only: false,
            expiration_time: "30 minutes",
            label: format!("dns-update-{nonce}"),
            global_key: false,
        };

        let payload = serde_json::to_string(&body)
            .map_err(|e| Error::Serialize(format!("Failed to encode TransIP auth body: {e}")))?;
        let signature = rsa_sha512_sign(&self.private_key_pem, payload.as_bytes())
            .map_err(|e| Error::Api(format!("Failed to sign TransIP request: {e}")))?;
        let signature_b64 = STANDARD.encode(&signature);

        let response: AuthResponse = self
            .client
            .post(format!("{}/auth", self.endpoint))
            .with_header("Signature", signature_b64)
            .with_raw_body(payload)
            .send()
            .await?;

        let expiry = Instant::now() + Duration::from_secs(25 * 60);
        let mut guard = self
            .auth
            .lock()
            .map_err(|_| Error::Client("TransIP token lock poisoned".to_string()))?;
        guard.token = Some((response.token.clone(), expiry));
        Ok(response.token)
    }

    fn authed(&self, request: HttpRequest, token: &str) -> HttpRequest {
        request.with_header("Authorization", format!("Bearer {token}"))
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
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let token = self.ensure_token().await?;

        let target_type = record_type.as_str();
        let existing_at_target: Vec<DnsEntry> = self
            .list_zone(&token, &domain)
            .await?
            .into_iter()
            .filter(|e| e.name == subdomain && e.record_type == target_type)
            .collect();

        let desired: Vec<DnsEntry> = records
            .into_iter()
            .map(|record| {
                Ok(DnsEntry {
                    name: subdomain.clone(),
                    expire: ttl,
                    record_type: target_type.to_string(),
                    content: render_value(record)?,
                })
            })
            .collect::<crate::Result<_>>()?;

        let mut existing_pool = existing_at_target;
        let mut to_add: Vec<DnsEntry> = Vec::new();
        for entry in desired {
            if let Some(idx) = existing_pool
                .iter()
                .position(|e| e.content == entry.content && e.expire == entry.expire)
            {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(entry);
            }
        }

        for entry in existing_pool {
            self.delete_entry(&token, &domain, &entry).await?;
        }
        for entry in to_add {
            self.post_entry(&token, &domain, &entry).await?;
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
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let token = self.ensure_token().await?;
        let target_type = record_type.as_str();

        let existing: Vec<DnsEntry> = self
            .list_zone(&token, &domain)
            .await?
            .into_iter()
            .filter(|e| e.name == subdomain && e.record_type == target_type)
            .collect();

        for record in records {
            let content = render_value(record)?;
            if existing.iter().any(|e| e.content == content) {
                continue;
            }
            let entry = DnsEntry {
                name: subdomain.clone(),
                expire: ttl,
                record_type: target_type.to_string(),
                content,
            };
            self.post_entry(&token, &domain, &entry).await?;
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
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let token = self.ensure_token().await?;
        let target_type = record_type.as_str();

        let existing: Vec<DnsEntry> = self
            .list_zone(&token, &domain)
            .await?
            .into_iter()
            .filter(|e| e.name == subdomain && e.record_type == target_type)
            .collect();

        let mut targets: Vec<String> = Vec::with_capacity(records.len());
        for record in records {
            targets.push(render_value(record)?);
        }

        for entry in existing {
            if targets.iter().any(|t| t == &entry.content) {
                self.delete_entry(&token, &domain, &entry).await?;
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
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let token = self.ensure_token().await?;
        let target_type = record_type.as_str();

        let entries = self.list_zone(&token, &domain).await?;
        let mut out = Vec::new();
        for entry in entries {
            if entry.name == subdomain && entry.record_type == target_type {
                out.push(parse_dns_entry(&entry, record_type)?);
            }
        }
        Ok(out)
    }

    async fn list_zone(&self, token: &str, domain: &str) -> crate::Result<Vec<DnsEntry>> {
        let url = format!("{}/domains/{}/dns", self.endpoint, domain);
        let entries: DnsEntriesResponse = self.authed(self.client.get(url), token).send().await?;
        Ok(entries.dns_entries)
    }

    async fn post_entry(&self, token: &str, domain: &str, entry: &DnsEntry) -> crate::Result<()> {
        let url = format!("{}/domains/{}/dns", self.endpoint, domain);
        self.authed(self.client.post(url), token)
            .with_body(DnsEntryRequest { dns_entry: entry })?
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn delete_entry(&self, token: &str, domain: &str, entry: &DnsEntry) -> crate::Result<()> {
        let url = format!("{}/domains/{}/dns", self.endpoint, domain);
        self.authed(self.client.delete(url), token)
            .with_body(DnsEntryRequest { dns_entry: entry })?
            .send_raw()
            .await
            .map(|_| ())
    }
}

pub(crate) fn generate_nonce() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0) as u64;
    format!("dnsu{now:016x}")
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

fn render_value(record: DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content,
        DnsRecord::NS(content) => content,
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, mx.exchange),
        DnsRecord::TXT(content) => content,
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority, srv.weight, srv.port, srv.target
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.decompose();
            format!("{flags} {tag} \"{value}\"")
        }
    })
}

fn parse_dns_entry(entry: &DnsEntry, record_type: DnsRecordType) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => {
            let addr = entry
                .content
                .parse()
                .map_err(|e| Error::Parse(format!("invalid A address {}: {e}", entry.content)))?;
            Ok(DnsRecord::A(addr))
        }
        DnsRecordType::AAAA => {
            let addr = entry.content.parse().map_err(|e| {
                Error::Parse(format!("invalid AAAA address {}: {e}", entry.content))
            })?;
            Ok(DnsRecord::AAAA(addr))
        }
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(entry.content.clone())),
        DnsRecordType::NS => Ok(DnsRecord::NS(entry.content.clone())),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(entry.content.clone())),
        DnsRecordType::MX => {
            let mut parts = entry.content.splitn(2, char::is_whitespace);
            let priority_token = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid MX content: {}", entry.content)))?;
            let exchange = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid MX content: {}", entry.content)))?
                .trim()
                .to_string();
            let priority: u16 = priority_token
                .parse()
                .map_err(|e| Error::Parse(format!("invalid MX priority: {e}")))?;
            Ok(DnsRecord::MX(MXRecord { priority, exchange }))
        }
        DnsRecordType::SRV => {
            let mut parts = entry.content.split_whitespace();
            let priority: u16 = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid SRV content: {}", entry.content)))?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid SRV priority: {e}")))?;
            let weight: u16 = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid SRV content: {}", entry.content)))?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid SRV weight: {e}")))?;
            let port: u16 = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid SRV content: {}", entry.content)))?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid SRV port: {e}")))?;
            let target = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid SRV content: {}", entry.content)))?
                .to_string();
            Ok(DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target,
            }))
        }
        DnsRecordType::TLSA => {
            let mut parts = entry.content.split_whitespace();
            let usage: u8 = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid TLSA content: {}", entry.content)))?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid TLSA usage: {e}")))?;
            let selector: u8 = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid TLSA content: {}", entry.content)))?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid TLSA selector: {e}")))?;
            let matching: u8 = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid TLSA content: {}", entry.content)))?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid TLSA matching: {e}")))?;
            let hex = parts
                .next()
                .ok_or_else(|| Error::Parse(format!("invalid TLSA content: {}", entry.content)))?;
            Ok(DnsRecord::TLSA(TLSARecord {
                cert_usage: tlsa_cert_usage_from_u8(usage)?,
                selector: tlsa_selector_from_u8(selector)?,
                matching: tlsa_matching_from_u8(matching)?,
                cert_data: decode_hex(hex)?,
            }))
        }
        DnsRecordType::CAA => Ok(DnsRecord::CAA(parse_caa_content(&entry.content)?)),
    }
}

fn parse_caa_content(content: &str) -> crate::Result<CAARecord> {
    let trimmed = content.trim();
    let mut parts = trimmed.splitn(3, char::is_whitespace);
    let flags_token = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value: {trimmed}")))?;
    let tag_token = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value: {trimmed}")))?;
    let raw_value = parts.next().unwrap_or("").trim();
    let flags: u8 = flags_token
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags: {e}")))?;
    let issuer_critical = flags & 0x80 != 0;
    let value = raw_value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(raw_value)
        .to_string();

    match tag_token {
        "issue" => {
            let (name, options) = split_caa_value(&value);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = split_caa_value(&value);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: value,
        }),
        other => Err(Error::Parse(format!("unknown CAA tag: {other}"))),
    }
}

fn split_caa_value(value: &str) -> (Option<String>, Vec<KeyValue>) {
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

fn decode_hex(hex: &str) -> crate::Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::Parse(format!("invalid hex string: {hex}")));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| Error::Parse(format!("invalid hex byte: {e}")))
        })
        .collect()
}

fn tlsa_cert_usage_from_u8(value: u8) -> crate::Result<TlsaCertUsage> {
    Ok(match value {
        0 => TlsaCertUsage::PkixTa,
        1 => TlsaCertUsage::PkixEe,
        2 => TlsaCertUsage::DaneTa,
        3 => TlsaCertUsage::DaneEe,
        255 => TlsaCertUsage::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA cert usage: {value}"))),
    })
}

fn tlsa_selector_from_u8(value: u8) -> crate::Result<TlsaSelector> {
    Ok(match value {
        0 => TlsaSelector::Full,
        1 => TlsaSelector::Spki,
        255 => TlsaSelector::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA selector: {value}"))),
    })
}

fn tlsa_matching_from_u8(value: u8) -> crate::Result<TlsaMatching> {
    Ok(match value {
        0 => TlsaMatching::Raw,
        1 => TlsaMatching::Sha256,
        2 => TlsaMatching::Sha512,
        255 => TlsaMatching::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA matching: {value}"))),
    })
}
