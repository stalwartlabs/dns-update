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
    TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector, utils::strip_origin_from_name,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_ENDPOINT: &str = "https://api.domrobot.com/jsonrpc/";
const SANDBOX_ENDPOINT: &str = "https://api.ote.domrobot.com/jsonrpc/";

const SESSION_TTL: Duration = Duration::from_secs(50 * 60);

#[derive(Clone)]
pub struct InwxProvider {
    client: Client,
    username: String,
    password: String,
    shared_secret: Option<String>,
    endpoint: String,
    session: Arc<Mutex<Option<SessionState>>>,
}

#[derive(Clone)]
struct SessionState {
    cookie: String,
    expires: Instant,
}

#[derive(Deserialize, Debug)]
struct RpcResponse {
    code: i64,
    #[serde(default)]
    msg: Option<String>,
    #[serde(rename = "resData", default)]
    res_data: Option<Value>,
}

#[derive(Serialize, Debug)]
struct RpcRequest<'a> {
    method: &'a str,
    params: Value,
}

#[derive(Deserialize, Debug)]
struct LoginResData {
    #[serde(default)]
    tfa: Option<String>,
}

#[derive(Deserialize, Debug)]
struct NameserverInfoResData {
    #[serde(default)]
    record: Vec<NameserverRecord>,
}

#[derive(Deserialize, Debug, Clone)]
struct NameserverRecord {
    id: i64,
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    record_type: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    prio: Option<u16>,
}

impl InwxProvider {
    pub(crate) fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        shared_secret: Option<String>,
        sandbox: bool,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let mut builder = Client::builder();
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        let client = builder
            .build()
            .map_err(|err| Error::Client(format!("Failed to build INWX HTTP client: {err}")))?;
        let endpoint = if sandbox {
            SANDBOX_ENDPOINT.to_string()
        } else {
            DEFAULT_ENDPOINT.to_string()
        };
        Ok(Self {
            client,
            username: username.into(),
            password: password.into(),
            shared_secret,
            endpoint,
            session: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        self.endpoint = endpoint.as_ref().to_string();
        self
    }

    #[cfg(test)]
    pub(crate) fn with_cached_session(self, cookie: impl Into<String>) -> Self {
        *self.session.lock().expect("INWX test session lock") = Some(SessionState {
            cookie: cookie.into(),
            expires: Instant::now() + SESSION_TTL,
        });
        self
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
        let name = name.into_name().to_string();
        let domain = origin.into_name().to_string();
        let rtype = inwx_record_type(record_type);
        let desired = build_payloads(&records);

        self.ensure_logged_in().await?;
        let existing = self.list_records_at(&domain, &name, rtype).await?;

        let mut existing_pool = existing;
        let mut to_add: Vec<(String, Option<u16>)> = Vec::new();

        for payload in desired {
            if let Some(idx) = existing_pool.iter().position(|r| {
                r.content == payload.0 && r.prio.unwrap_or(0) == payload.1.unwrap_or(0)
            }) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(payload);
            }
        }

        for stale in existing_pool {
            self.call("nameserver.deleteRecord", json!({ "id": stale.id }))
                .await
                .map(|_| ())?;
        }

        for (content, prio) in to_add {
            self.create_record(&domain, &name, rtype, ttl, content, prio)
                .await?;
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
        check_record_types(record_type, &records)?;
        let name = name.into_name().to_string();
        let domain = origin.into_name().to_string();
        let rtype = inwx_record_type(record_type);
        let desired = build_payloads(&records);

        self.ensure_logged_in().await?;
        let existing = self.list_records_at(&domain, &name, rtype).await?;

        for (content, prio) in desired {
            let already_present = existing
                .iter()
                .any(|r| r.content == content && r.prio.unwrap_or(0) == prio.unwrap_or(0));
            if already_present {
                continue;
            }
            self.create_record(&domain, &name, rtype, ttl, content, prio)
                .await?;
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
        check_record_types(record_type, &records)?;
        let name = name.into_name().to_string();
        let domain = origin.into_name().to_string();
        let rtype = inwx_record_type(record_type);
        let to_remove = build_payloads(&records);

        self.ensure_logged_in().await?;
        let existing = self.list_records_at(&domain, &name, rtype).await?;

        for (content, prio) in to_remove {
            if let Some(entry) = existing
                .iter()
                .find(|r| r.content == content && r.prio.unwrap_or(0) == prio.unwrap_or(0))
            {
                self.call("nameserver.deleteRecord", json!({ "id": entry.id }))
                    .await
                    .map(|_| ())?;
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
        let name = name.into_name().to_string();
        let domain = origin.into_name().to_string();
        let rtype = inwx_record_type(record_type);

        self.ensure_logged_in().await?;
        let existing = self.list_records_at(&domain, &name, rtype).await?;
        existing
            .into_iter()
            .map(|r| parse_record(record_type, &r.content, r.prio))
            .collect()
    }

    async fn list_records_at(
        &self,
        domain: &str,
        name: &str,
        record_type: &str,
    ) -> crate::Result<Vec<NameserverRecord>> {
        let params = json!({
            "domain": domain,
            "name": name,
            "type": record_type,
        });
        let resp = self.call("nameserver.info", params).await?;
        let Some(res_data) = resp.res_data else {
            return Ok(Vec::new());
        };
        let info: NameserverInfoResData = serde_json::from_value(res_data)
            .map_err(|err| Error::Api(format!("Failed to parse INWX nameserver.info: {err}")))?;

        let apex = strip_origin_from_name(name, domain, Some("@"));
        let bare_name = name.trim_end_matches('.');
        Ok(info
            .record
            .into_iter()
            .filter(|record| {
                if !record.record_type.eq_ignore_ascii_case(record_type) {
                    return false;
                }
                let echoed = record.name.trim_end_matches('.');
                echoed == bare_name || echoed == apex
            })
            .collect())
    }

    async fn create_record(
        &self,
        domain: &str,
        name: &str,
        record_type: &str,
        ttl: u32,
        content: String,
        prio: Option<u16>,
    ) -> crate::Result<()> {
        let mut params = json!({
            "domain": domain,
            "name": name,
            "type": record_type,
            "content": content,
            "ttl": ttl,
        });
        if let Some(prio) = prio {
            params["prio"] = json!(prio);
        }
        self.call("nameserver.createRecord", params)
            .await
            .map(|_| ())
    }

    async fn ensure_logged_in(&self) -> crate::Result<()> {
        if let Some(state) = self.session.lock().ok().and_then(|guard| guard.clone())
            && Instant::now() < state.expires
        {
            return Ok(());
        }
        self.login().await
    }

    async fn login(&self) -> crate::Result<()> {
        let params = json!({
            "user": &self.username,
            "pass": &self.password,
        });
        let response = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .json(&RpcRequest {
                method: "account.login",
                params,
            })
            .send()
            .await
            .map_err(|err| Error::Api(format!("INWX login request failed: {err}")))?;

        let cookie = response
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|value| value.split(';').next().map(|part| part.trim().to_string()))
            .unwrap_or_default();

        let rpc: RpcResponse = response
            .json()
            .await
            .map_err(|err| Error::Api(format!("Failed to parse INWX login response: {err}")))?;
        if rpc.code / 1000 != 1 {
            return Err(Error::Api(format!(
                "INWX login failed: code={} message={}",
                rpc.code,
                rpc.msg.unwrap_or_default()
            )));
        }

        let login: LoginResData = rpc
            .res_data
            .map(serde_json::from_value)
            .transpose()
            .map_err(|err| Error::Api(format!("Failed to parse INWX login resData: {err}")))?
            .unwrap_or(LoginResData { tfa: None });

        if let Some(tfa) = login.tfa.as_deref()
            && !tfa.is_empty()
            && tfa != "0"
        {
            if self.shared_secret.is_some() {
                return Err(Error::Api(
                    "INWX 2FA TOTP is not supported by this port".into(),
                ));
            }
            return Err(Error::Api(format!(
                "INWX account requires 2FA ({tfa}); not supported by this port"
            )));
        }

        if let Ok(mut guard) = self.session.lock() {
            *guard = Some(SessionState {
                cookie,
                expires: Instant::now() + SESSION_TTL,
            });
        }
        Ok(())
    }

    async fn call(&self, method: &str, params: Value) -> crate::Result<RpcResponse> {
        let cookie = self
            .session
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|state| state.cookie.clone()))
            .unwrap_or_default();

        let mut request = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .json(&RpcRequest { method, params });
        if !cookie.is_empty() {
            request = request.header(reqwest::header::COOKIE, &cookie);
        }

        let response = request
            .send()
            .await
            .map_err(|err| Error::Api(format!("INWX request to {method} failed: {err}")))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| Error::Api(format!("Failed to read INWX response body: {err}")))?;

        if !status.is_success() {
            return match status.as_u16() {
                401 => Err(Error::Unauthorized),
                404 => Err(Error::NotFound),
                400 => Err(Error::BadRequest),
                _ => Err(Error::Api(format!(
                    "INWX returned HTTP {status} for {method}: {body}"
                ))),
            };
        }

        let rpc: RpcResponse = serde_json::from_str(&body).map_err(|err| {
            Error::Api(format!(
                "Failed to parse INWX response from {method}: {err}"
            ))
        })?;
        if rpc.code / 1000 != 1 {
            return Err(Error::Api(format!(
                "INWX {method} failed: code={} message={}",
                rpc.code,
                rpc.msg.clone().unwrap_or_default()
            )));
        }
        Ok(rpc)
    }
}

fn inwx_record_type(record_type: DnsRecordType) -> &'static str {
    match record_type {
        DnsRecordType::A => "A",
        DnsRecordType::AAAA => "AAAA",
        DnsRecordType::CNAME => "CNAME",
        DnsRecordType::NS => "NS",
        DnsRecordType::MX => "MX",
        DnsRecordType::TXT => "TXT",
        DnsRecordType::SRV => "SRV",
        DnsRecordType::TLSA => "TLSA",
        DnsRecordType::CAA => "CAA",
    }
}

fn inwx_record_payload(record: &DnsRecord) -> (&'static str, String, Option<u16>) {
    match record {
        DnsRecord::A(ip) => ("A", ip.to_string(), None),
        DnsRecord::AAAA(ip) => ("AAAA", ip.to_string(), None),
        DnsRecord::CNAME(name) => ("CNAME", name.as_str().into_fqdn().into_owned(), None),
        DnsRecord::NS(name) => ("NS", name.as_str().into_fqdn().into_owned(), None),
        DnsRecord::MX(mx) => (
            "MX",
            mx.exchange.as_str().into_fqdn().into_owned(),
            Some(mx.priority),
        ),
        DnsRecord::TXT(value) => ("TXT", value.clone(), None),
        DnsRecord::SRV(srv) => (
            "SRV",
            format!(
                "{} {} {}",
                srv.weight,
                srv.port,
                srv.target.as_str().into_fqdn()
            ),
            Some(srv.priority),
        ),
        DnsRecord::TLSA(tlsa) => ("TLSA", format!("{tlsa}"), None),
        DnsRecord::CAA(caa) => ("CAA", format!("{caa}"), None),
    }
}

fn build_payloads(records: &[DnsRecord]) -> Vec<(String, Option<u16>)> {
    records
        .iter()
        .map(|r| {
            let (_, content, prio) = inwx_record_payload(r);
            (content, prio)
        })
        .collect()
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

fn parse_record(
    record_type: DnsRecordType,
    content: &str,
    prio: Option<u16>,
) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => content
            .parse()
            .map(DnsRecord::A)
            .map_err(|err| Error::Parse(format!("invalid INWX A content {content}: {err}"))),
        DnsRecordType::AAAA => content
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|err| Error::Parse(format!("invalid INWX AAAA content {content}: {err}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(content.to_string())),
        DnsRecordType::NS => Ok(DnsRecord::NS(content.to_string())),
        DnsRecordType::MX => Ok(DnsRecord::MX(MXRecord {
            exchange: content.to_string(),
            priority: prio.unwrap_or(0),
        })),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(content.to_string())),
        DnsRecordType::SRV => parse_srv(content, prio.unwrap_or(0)),
        DnsRecordType::TLSA => parse_tlsa(content),
        DnsRecordType::CAA => parse_caa(content),
    }
}

fn parse_srv(content: &str, priority: u16) -> crate::Result<DnsRecord> {
    let mut parts = content.split_ascii_whitespace();
    let weight: u16 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid INWX SRV content: {content}")))?
        .parse()
        .map_err(|err| Error::Parse(format!("invalid SRV weight: {err}")))?;
    let port: u16 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid INWX SRV content: {content}")))?
        .parse()
        .map_err(|err| Error::Parse(format!("invalid SRV port: {err}")))?;
    let target = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid INWX SRV content: {content}")))?
        .to_string();
    Ok(DnsRecord::SRV(SRVRecord {
        priority,
        weight,
        port,
        target,
    }))
}

fn parse_tlsa(content: &str) -> crate::Result<DnsRecord> {
    let mut parts = content.split_ascii_whitespace();
    let usage: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid INWX TLSA content: {content}")))?
        .parse()
        .map_err(|err| Error::Parse(format!("invalid TLSA usage: {err}")))?;
    let selector: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid INWX TLSA content: {content}")))?
        .parse()
        .map_err(|err| Error::Parse(format!("invalid TLSA selector: {err}")))?;
    let matching: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid INWX TLSA content: {content}")))?
        .parse()
        .map_err(|err| Error::Parse(format!("invalid TLSA matching: {err}")))?;
    let hex = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid INWX TLSA content: {content}")))?;
    Ok(DnsRecord::TLSA(TLSARecord {
        cert_usage: tlsa_cert_usage_from_u8(usage)?,
        selector: tlsa_selector_from_u8(selector)?,
        matching: tlsa_matching_from_u8(matching)?,
        cert_data: decode_hex(hex)?,
    }))
}

fn parse_caa(content: &str) -> crate::Result<DnsRecord> {
    let (flags_str, rest) = content
        .split_once(' ')
        .ok_or_else(|| Error::Parse(format!("invalid INWX CAA content: {content}")))?;
    let flags: u8 = flags_str
        .parse()
        .map_err(|err| Error::Parse(format!("invalid CAA flags: {err}")))?;
    let (tag, raw_value) = rest
        .split_once(' ')
        .ok_or_else(|| Error::Parse(format!("invalid INWX CAA content: {content}")))?;
    let value = raw_value.trim().trim_matches('"').to_string();
    let issuer_critical = flags & 0x80 != 0;

    match tag {
        "issue" => {
            let (name, options) = split_caa_value(&value);
            Ok(DnsRecord::CAA(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }))
        }
        "issuewild" => {
            let (name, options) = split_caa_value(&value);
            Ok(DnsRecord::CAA(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            }))
        }
        "iodef" => Ok(DnsRecord::CAA(CAARecord::Iodef {
            issuer_critical,
            url: value,
        })),
        other => Err(Error::Parse(format!("unknown CAA tag: {other}"))),
    }
}

fn split_caa_value(value: &str) -> (Option<String>, Vec<KeyValue>) {
    let mut parts = value.split(';').map(str::trim);
    let name_part = parts.next().unwrap_or("").to_string();
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
