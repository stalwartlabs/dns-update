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
    TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector, http::HttpClientBuilder,
    utils::strip_origin_from_name,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_API_ENDPOINT: &str = "https://api.mythic-beasts.com/dns/v2";
const DEFAULT_AUTH_ENDPOINT: &str = "https://auth.mythic-beasts.com/login";

#[derive(Clone)]
pub struct MythicBeastsProvider {
    auth: Arc<Mutex<AuthState>>,
    username: String,
    password: String,
    api_endpoint: String,
    auth_endpoint: String,
    timeout: Option<Duration>,
}

struct AuthState {
    token: Option<(String, Instant)>,
}

#[derive(Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    #[serde(default)]
    token_type: String,
}

#[derive(Serialize, Debug)]
struct RecordsBody {
    records: Vec<RecordPayload>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct RecordPayload {
    host: String,
    ttl: u32,
    #[serde(rename = "type")]
    record_type: String,
    data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mx_priority: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    srv_priority: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    srv_weight: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    srv_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    caa_flags: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    caa_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tlsa_usage: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tlsa_selector: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tlsa_matching: Option<u8>,
}

#[derive(Deserialize, Debug)]
struct ListResponse {
    #[serde(default)]
    records: Vec<RecordPayload>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct MutationResponse {
    #[serde(default)]
    records_added: i64,
    #[serde(default)]
    records_removed: i64,
    #[serde(default)]
    message: String,
}

impl MythicBeastsProvider {
    pub(crate) fn new(
        username: impl AsRef<str>,
        password: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let username = username.as_ref().to_string();
        let password = password.as_ref().to_string();
        if username.is_empty() || password.is_empty() {
            return Err(Error::Api(
                "Mythic Beasts username and password must not be empty".to_string(),
            ));
        }

        Ok(Self {
            auth: Arc::new(Mutex::new(AuthState { token: None })),
            username,
            password,
            api_endpoint: DEFAULT_API_ENDPOINT.to_string(),
            auth_endpoint: DEFAULT_AUTH_ENDPOINT.to_string(),
            timeout,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        let base = endpoint.as_ref().trim_end_matches('/').to_string();
        Self {
            api_endpoint: format!("{base}/dns/v2"),
            auth_endpoint: format!("{base}/auth/login"),
            ..self
        }
    }

    fn api_client(&self, token: &str) -> HttpClientBuilder {
        HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {token}"))
            .with_header("Accept", "application/json")
            .with_timeout(self.timeout)
    }

    async fn ensure_token(&self) -> crate::Result<String> {
        {
            let guard = self
                .auth
                .lock()
                .map_err(|_| Error::Client("Mythic Beasts token lock poisoned".to_string()))?;
            if let Some((token, expiry)) = &guard.token
                && Instant::now() < *expiry
            {
                return Ok(token.clone());
            }
        }

        let credentials = STANDARD.encode(format!("{}:{}", self.username, self.password));
        let auth_client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {credentials}"))
            .with_header("Accept", "application/json")
            .with_timeout(self.timeout);

        let body: TokenResponse = auth_client
            .post(self.auth_endpoint.clone())
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_raw_body("grant_type=client_credentials".to_string())
            .send()
            .await?;

        if !body.token_type.eq_ignore_ascii_case("bearer") && !body.token_type.is_empty() {
            return Err(Error::Api(format!(
                "Unexpected token type: {}",
                body.token_type
            )));
        }

        let expiry = Instant::now() + Duration::from_secs(body.expires_in.saturating_sub(60));
        let mut guard = self
            .auth
            .lock()
            .map_err(|_| Error::Client("Mythic Beasts token lock poisoned".to_string()))?;
        guard.token = Some((body.access_token.clone(), expiry));
        Ok(body.access_token)
    }

    fn rrset_url(&self, zone: &str, host: &str, record_type: DnsRecordType) -> String {
        format!(
            "{}/zones/{}/records/{}/{}",
            self.api_endpoint,
            zone,
            host,
            record_type.as_str(),
        )
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let payloads = build_payloads(&subdomain, record_type, ttl, records)?;
        let token = self.ensure_token().await?;
        let url = self.rrset_url(&domain, &subdomain, record_type);

        if payloads.is_empty() {
            return match self.api_client(&token).delete(url).send_raw().await {
                Ok(_) => Ok(()),
                Err(Error::NotFound) => Ok(()),
                Err(e) => Err(e),
            };
        }

        let body = RecordsBody { records: payloads };
        let _: MutationResponse = self
            .api_client(&token)
            .put(url)
            .with_body(body)?
            .send()
            .await?;
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let payloads = build_payloads(&subdomain, record_type, ttl, records)?;
        if payloads.is_empty() {
            return Ok(());
        }
        let token = self.ensure_token().await?;

        let body = RecordsBody { records: payloads };
        let _: MutationResponse = self
            .api_client(&token)
            .post(self.rrset_url(&domain, &subdomain, record_type))
            .with_body(body)?
            .send()
            .await?;
        Ok(())
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let to_remove = build_payloads(&subdomain, record_type, 0, records)?;
        if to_remove.is_empty() {
            return Ok(());
        }
        let token = self.ensure_token().await?;
        let url = self.rrset_url(&domain, &subdomain, record_type);

        let current = match self
            .api_client(&token)
            .get(url.clone())
            .send::<ListResponse>()
            .await
        {
            Ok(r) => r.records,
            Err(Error::NotFound) => return Ok(()),
            Err(e) => return Err(e),
        };

        let remaining: Vec<RecordPayload> = current
            .into_iter()
            .filter(|existing| {
                !to_remove
                    .iter()
                    .any(|target| rdata_matches(existing, target))
            })
            .collect();

        if remaining.is_empty() {
            return match self.api_client(&token).delete(url).send_raw().await {
                Ok(_) => Ok(()),
                Err(Error::NotFound) => Ok(()),
                Err(e) => Err(e),
            };
        }

        let body = RecordsBody { records: remaining };
        let _: MutationResponse = self
            .api_client(&token)
            .put(url)
            .with_body(body)?
            .send()
            .await?;
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
        let url = self.rrset_url(&domain, &subdomain, record_type);

        let response = match self
            .api_client(&token)
            .get(url)
            .send::<ListResponse>()
            .await
        {
            Ok(r) => r,
            Err(Error::NotFound) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };

        let expected = record_type.as_str();
        response
            .records
            .into_iter()
            .filter(|r| r.record_type.eq_ignore_ascii_case(expected))
            .map(payload_to_record)
            .collect()
    }
}

fn rdata_matches(a: &RecordPayload, b: &RecordPayload) -> bool {
    a.record_type.eq_ignore_ascii_case(&b.record_type)
        && a.host == b.host
        && a.data == b.data
        && a.mx_priority == b.mx_priority
        && a.srv_priority == b.srv_priority
        && a.srv_weight == b.srv_weight
        && a.srv_port == b.srv_port
        && a.caa_flags == b.caa_flags
        && a.caa_tag == b.caa_tag
        && a.tlsa_usage == b.tlsa_usage
        && a.tlsa_selector == b.tlsa_selector
        && a.tlsa_matching == b.tlsa_matching
}

fn build_payloads(
    host: &str,
    expected_type: DnsRecordType,
    ttl: u32,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<RecordPayload>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(build_payload(host, record, ttl)?);
    }
    Ok(out)
}

fn build_payload(host: &str, record: DnsRecord, ttl: u32) -> crate::Result<RecordPayload> {
    let record_type = record.as_type().as_str().to_string();
    let mut payload = RecordPayload {
        host: host.to_string(),
        ttl,
        record_type,
        data: String::new(),
        mx_priority: None,
        srv_priority: None,
        srv_weight: None,
        srv_port: None,
        caa_flags: None,
        caa_tag: None,
        tlsa_usage: None,
        tlsa_selector: None,
        tlsa_matching: None,
    };

    match record {
        DnsRecord::A(addr) => {
            payload.data = addr.to_string();
        }
        DnsRecord::AAAA(addr) => {
            payload.data = addr.to_string();
        }
        DnsRecord::CNAME(content) => {
            payload.data = ensure_trailing_dot(content);
        }
        DnsRecord::NS(content) => {
            payload.data = ensure_trailing_dot(content);
        }
        DnsRecord::MX(mx) => {
            payload.mx_priority = Some(mx.priority);
            payload.data = ensure_trailing_dot(mx.exchange);
        }
        DnsRecord::TXT(content) => {
            payload.data = content;
        }
        DnsRecord::SRV(srv) => {
            payload.srv_priority = Some(srv.priority);
            payload.srv_weight = Some(srv.weight);
            payload.srv_port = Some(srv.port);
            payload.data = ensure_trailing_dot(srv.target);
        }
        DnsRecord::TLSA(tlsa) => {
            payload.tlsa_usage = Some(u8::from(tlsa.cert_usage));
            payload.tlsa_selector = Some(u8::from(tlsa.selector));
            payload.tlsa_matching = Some(u8::from(tlsa.matching));
            payload.data = tlsa.cert_data.iter().map(|b| format!("{b:02x}")).collect();
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.decompose();
            payload.caa_flags = Some(flags);
            payload.caa_tag = Some(tag);
            payload.data = value;
        }
    }

    Ok(payload)
}

fn ensure_trailing_dot(mut value: String) -> String {
    if !value.ends_with('.') {
        value.push('.');
    }
    value
}

fn strip_trailing_dot(value: &str) -> String {
    value.strip_suffix('.').unwrap_or(value).to_string()
}

fn payload_to_record(payload: RecordPayload) -> crate::Result<DnsRecord> {
    let upper = payload.record_type.to_ascii_uppercase();
    Ok(match upper.as_str() {
        "A" => DnsRecord::A(
            payload
                .data
                .parse::<Ipv4Addr>()
                .map_err(|e| Error::Parse(format!("Invalid A record: {e}")))?,
        ),
        "AAAA" => DnsRecord::AAAA(
            payload
                .data
                .parse::<Ipv6Addr>()
                .map_err(|e| Error::Parse(format!("Invalid AAAA record: {e}")))?,
        ),
        "CNAME" => DnsRecord::CNAME(strip_trailing_dot(&payload.data)),
        "NS" => DnsRecord::NS(strip_trailing_dot(&payload.data)),
        "MX" => DnsRecord::MX(MXRecord {
            priority: payload.mx_priority.unwrap_or(0),
            exchange: strip_trailing_dot(&payload.data),
        }),
        "TXT" => DnsRecord::TXT(payload.data),
        "SRV" => DnsRecord::SRV(SRVRecord {
            priority: payload.srv_priority.unwrap_or(0),
            weight: payload.srv_weight.unwrap_or(0),
            port: payload.srv_port.unwrap_or(0),
            target: strip_trailing_dot(&payload.data),
        }),
        "TLSA" => DnsRecord::TLSA(TLSARecord {
            cert_usage: tlsa_cert_usage_from_u8(payload.tlsa_usage.unwrap_or(0))?,
            selector: tlsa_selector_from_u8(payload.tlsa_selector.unwrap_or(0))?,
            matching: tlsa_matching_from_u8(payload.tlsa_matching.unwrap_or(0))?,
            cert_data: decode_hex(&payload.data)?,
        }),
        "CAA" => DnsRecord::CAA(build_caa(
            payload.caa_flags.unwrap_or(0),
            payload.caa_tag.unwrap_or_default(),
            payload.data,
        )?),
        other => {
            return Err(Error::Api(format!(
                "Unsupported record type from Mythic Beasts: {other}"
            )));
        }
    })
}

fn decode_hex(hex: &str) -> crate::Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::Parse(format!("Invalid hex string: {hex}")));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| Error::Parse(format!("Invalid hex byte: {e}")))
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
        _ => return Err(Error::Parse(format!("Unknown TLSA cert usage: {value}"))),
    })
}

fn tlsa_selector_from_u8(value: u8) -> crate::Result<TlsaSelector> {
    Ok(match value {
        0 => TlsaSelector::Full,
        1 => TlsaSelector::Spki,
        255 => TlsaSelector::Private,
        _ => return Err(Error::Parse(format!("Unknown TLSA selector: {value}"))),
    })
}

fn tlsa_matching_from_u8(value: u8) -> crate::Result<TlsaMatching> {
    Ok(match value {
        0 => TlsaMatching::Raw,
        1 => TlsaMatching::Sha256,
        2 => TlsaMatching::Sha512,
        255 => TlsaMatching::Private,
        _ => return Err(Error::Parse(format!("Unknown TLSA matching: {value}"))),
    })
}

fn build_caa(flags: u8, tag: String, value: String) -> crate::Result<CAARecord> {
    let issuer_critical = flags & 0x80 != 0;
    match tag.as_str() {
        "issue" => {
            let (name, options) = parse_caa_value(&value);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(&value);
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
        other => Err(Error::Parse(format!("Unknown CAA tag: {other}"))),
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
