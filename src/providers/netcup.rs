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
use serde::{Deserialize, Serialize};
use std::{
    net::AddrParseError,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const DEFAULT_ENDPOINT: &str = "https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON";
const SESSION_TTL_SECS: u64 = 10 * 60;

#[derive(Clone)]
pub struct NetcupProvider {
    client: HttpClientBuilder,
    endpoint: String,
    customer_number: String,
    api_key: String,
    api_password: String,
    session: Arc<Mutex<Option<(String, Instant)>>>,
}

#[derive(Serialize, Debug)]
struct Request<P: Serialize> {
    action: &'static str,
    param: P,
}

#[derive(Serialize, Debug)]
struct LoginParam<'a> {
    customernumber: &'a str,
    apikey: &'a str,
    apipassword: &'a str,
}

#[derive(Serialize, Debug)]
struct LogoutParam<'a> {
    customernumber: &'a str,
    apikey: &'a str,
    apisessionid: &'a str,
}

#[derive(Serialize, Debug)]
struct InfoDnsRecordsParam<'a> {
    domainname: &'a str,
    customernumber: &'a str,
    apikey: &'a str,
    apisessionid: &'a str,
}

#[derive(Serialize, Debug)]
struct UpdateDnsRecordsParam<'a> {
    domainname: &'a str,
    customernumber: &'a str,
    apikey: &'a str,
    apisessionid: &'a str,
    dnsrecordset: DnsRecordSet,
}

#[derive(Serialize, Debug)]
struct DnsRecordSet {
    dnsrecords: Vec<NetcupRecord>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct NetcupRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    hostname: String,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    priority: String,
    destination: String,
    #[serde(default, skip_serializing_if = "is_false")]
    deleterecord: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    state: String,
}

fn is_false(v: &bool) -> bool {
    !*v
}

fn ensure_trailing_dot(value: &str) -> String {
    if value.ends_with('.') {
        value.to_string()
    } else {
        format!("{value}.")
    }
}

fn strip_trailing_dot(value: &str) -> String {
    value.strip_suffix('.').unwrap_or(value).to_string()
}

#[derive(Deserialize, Debug)]
struct ResponseMsg {
    #[serde(default)]
    status: String,
    #[serde(default, rename = "statuscode")]
    status_code: i64,
    #[serde(default, rename = "shortmessage")]
    short_message: String,
    #[serde(default, rename = "longmessage")]
    long_message: String,
    #[serde(default, rename = "responsedata")]
    response_data: serde_json::Value,
}

#[derive(Deserialize, Debug)]
struct LoginResponse {
    #[serde(default, rename = "apisessionid")]
    api_session_id: String,
}

#[derive(Deserialize, Debug)]
struct InfoDnsRecordsResponse {
    #[serde(default)]
    dnsrecords: Vec<NetcupRecord>,
}

impl NetcupProvider {
    pub(crate) fn new(
        customer_number: impl AsRef<str>,
        api_key: impl AsRef<str>,
        api_password: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default().with_timeout(timeout);
        Self {
            client,
            endpoint: DEFAULT_ENDPOINT.to_string(),
            customer_number: customer_number.as_ref().to_string(),
            api_key: api_key.as_ref().to_string(),
            api_password: api_password.as_ref().to_string(),
            session: Arc::new(Mutex::new(None)),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let hostname = strip_origin_from_name(&name, &origin, Some("@"));
        let session = self.ensure_session().await?;
        let listed = self.list_all_records(&origin, &session).await?;

        let type_str = record_type.as_str();
        let existing: Vec<NetcupRecord> = listed
            .into_iter()
            .filter(|r| r.hostname == hostname && r.record_type.eq_ignore_ascii_case(type_str))
            .collect();

        let desired: Vec<NetcupRecord> = records
            .iter()
            .map(|r| encode_record(r, &hostname))
            .collect::<crate::Result<Vec<_>>>()?;

        let mut batch: Vec<NetcupRecord> = Vec::new();
        let mut remaining: Vec<NetcupRecord> = existing.clone();

        for want in &desired {
            if let Some(idx) = remaining.iter().position(|r| same_payload(r, want)) {
                remaining.swap_remove(idx);
            } else {
                batch.push(want.clone());
            }
        }
        for stale in remaining {
            batch.push(NetcupRecord {
                id: stale.id,
                hostname: stale.hostname,
                record_type: stale.record_type,
                priority: stale.priority,
                destination: stale.destination,
                deleterecord: true,
                state: String::new(),
            });
        }

        if batch.is_empty() {
            return Ok(());
        }
        self.update_dns_records(&origin, &session, batch).await
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let hostname = strip_origin_from_name(&name, &origin, Some("@"));
        let session = self.ensure_session().await?;
        let listed = self.list_all_records(&origin, &session).await?;

        let type_str = record_type.as_str();
        let existing: Vec<NetcupRecord> = listed
            .into_iter()
            .filter(|r| r.hostname == hostname && r.record_type.eq_ignore_ascii_case(type_str))
            .collect();

        let desired: Vec<NetcupRecord> = records
            .iter()
            .map(|r| encode_record(r, &hostname))
            .collect::<crate::Result<Vec<_>>>()?;

        let mut batch: Vec<NetcupRecord> = Vec::new();
        for want in desired {
            if !existing.iter().any(|r| same_payload(r, &want)) {
                batch.push(want);
            }
        }

        if batch.is_empty() {
            return Ok(());
        }
        self.update_dns_records(&origin, &session, batch).await
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
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let hostname = strip_origin_from_name(&name, &origin, Some("@"));
        let session = self.ensure_session().await?;
        let listed = self.list_all_records(&origin, &session).await?;

        let type_str = record_type.as_str();
        let existing: Vec<NetcupRecord> = listed
            .into_iter()
            .filter(|r| r.hostname == hostname && r.record_type.eq_ignore_ascii_case(type_str))
            .collect();

        let targets: Vec<NetcupRecord> = records
            .iter()
            .map(|r| encode_record(r, &hostname))
            .collect::<crate::Result<Vec<_>>>()?;

        let mut batch: Vec<NetcupRecord> = Vec::new();
        for target in &targets {
            if let Some(found) = existing.iter().find(|r| same_payload(r, target)) {
                batch.push(NetcupRecord {
                    id: found.id.clone(),
                    hostname: found.hostname.clone(),
                    record_type: found.record_type.clone(),
                    priority: found.priority.clone(),
                    destination: found.destination.clone(),
                    deleterecord: true,
                    state: String::new(),
                });
            }
        }

        if batch.is_empty() {
            return Ok(());
        }
        self.update_dns_records(&origin, &session, batch).await
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let hostname = strip_origin_from_name(&name, &origin, Some("@"));
        let session = self.ensure_session().await?;
        let listed = self.list_all_records(&origin, &session).await?;

        let type_str = record_type.as_str();
        let mut out = Vec::new();
        for r in listed {
            if r.hostname == hostname && r.record_type.eq_ignore_ascii_case(type_str) {
                out.push(decode_record(record_type, &r)?);
            }
        }
        Ok(out)
    }

    async fn ensure_session(&self) -> crate::Result<String> {
        if let Some((ref id, expiry)) = *self.session_lock()?
            && Instant::now() < expiry
        {
            return Ok(id.clone());
        }
        let id = self.login().await?;
        let expiry = Instant::now() + Duration::from_secs(SESSION_TTL_SECS);
        *self.session_lock()? = Some((id.clone(), expiry));
        Ok(id)
    }

    fn session_lock(&self) -> crate::Result<std::sync::MutexGuard<'_, Option<(String, Instant)>>> {
        self.session
            .lock()
            .map_err(|_| Error::Client("Netcup session lock poisoned".into()))
    }

    async fn login(&self) -> crate::Result<String> {
        let payload = Request {
            action: "login",
            param: LoginParam {
                customernumber: &self.customer_number,
                apikey: &self.api_key,
                apipassword: &self.api_password,
            },
        };
        let response: ResponseMsg = self
            .client
            .post(&self.endpoint)
            .with_body(payload)?
            .send()
            .await?;
        check_status(&response)?;
        let parsed: LoginResponse = serde_json::from_value(response.response_data)
            .map_err(|e| Error::Serialize(format!("Failed to parse Netcup login: {e}")))?;
        Ok(parsed.api_session_id)
    }

    async fn update_dns_records(
        &self,
        domain: &str,
        session: &str,
        records: Vec<NetcupRecord>,
    ) -> crate::Result<()> {
        let payload = Request {
            action: "updateDnsRecords",
            param: UpdateDnsRecordsParam {
                domainname: domain,
                customernumber: &self.customer_number,
                apikey: &self.api_key,
                apisessionid: session,
                dnsrecordset: DnsRecordSet {
                    dnsrecords: records,
                },
            },
        };

        let response: ResponseMsg = self
            .client
            .post(&self.endpoint)
            .with_body(payload)?
            .send()
            .await?;
        check_status(&response)?;
        Ok(())
    }

    async fn list_all_records(
        &self,
        domain: &str,
        session: &str,
    ) -> crate::Result<Vec<NetcupRecord>> {
        let payload = Request {
            action: "infoDnsRecords",
            param: InfoDnsRecordsParam {
                domainname: domain,
                customernumber: &self.customer_number,
                apikey: &self.api_key,
                apisessionid: session,
            },
        };
        let response: ResponseMsg = self
            .client
            .post(&self.endpoint)
            .with_body(payload)?
            .send()
            .await?;
        check_status(&response)?;
        let parsed: InfoDnsRecordsResponse = serde_json::from_value(response.response_data)
            .map_err(|e| Error::Serialize(format!("Failed to parse Netcup record list: {e}")))?;
        Ok(parsed.dnsrecords)
    }

    #[allow(dead_code)]
    async fn logout(&self, session: &str) -> crate::Result<()> {
        let payload = Request {
            action: "logout",
            param: LogoutParam {
                customernumber: &self.customer_number,
                apikey: &self.api_key,
                apisessionid: session,
            },
        };
        let response: ResponseMsg = self
            .client
            .post(&self.endpoint)
            .with_body(payload)?
            .send()
            .await?;
        check_status(&response)
    }
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

fn check_status(response: &ResponseMsg) -> crate::Result<()> {
    if response.status == "success" {
        Ok(())
    } else {
        Err(Error::Api(format!(
            "Netcup API error: status={} code={} short={} long={}",
            response.status, response.status_code, response.short_message, response.long_message
        )))
    }
}

fn same_payload(a: &NetcupRecord, b: &NetcupRecord) -> bool {
    a.hostname == b.hostname
        && a.record_type.eq_ignore_ascii_case(&b.record_type)
        && a.destination == b.destination
        && a.priority == b.priority
}

fn encode_record(record: &DnsRecord, hostname: &str) -> crate::Result<NetcupRecord> {
    let (record_type, destination, priority) = match record {
        DnsRecord::A(addr) => ("A", addr.to_string(), String::new()),
        DnsRecord::AAAA(addr) => ("AAAA", addr.to_string(), String::new()),
        DnsRecord::CNAME(value) => ("CNAME", ensure_trailing_dot(value), String::new()),
        DnsRecord::NS(value) => ("NS", ensure_trailing_dot(value), String::new()),
        DnsRecord::MX(mx) => (
            "MX",
            ensure_trailing_dot(&mx.exchange),
            mx.priority.to_string(),
        ),
        DnsRecord::TXT(value) => ("TXT", value.clone(), String::new()),
        DnsRecord::SRV(srv) => (
            "SRV",
            format!(
                "{} {} {} {}",
                srv.priority,
                srv.weight,
                srv.port,
                ensure_trailing_dot(&srv.target),
            ),
            String::new(),
        ),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            (
                "CAA",
                format!("{} {} \"{}\"", flags, tag, value.replace('"', "\\\"")),
                String::new(),
            )
        }
        DnsRecord::TLSA(tlsa) => (
            "TLSA",
            format!(
                "{} {} {} {}",
                u8::from(tlsa.cert_usage),
                u8::from(tlsa.selector),
                u8::from(tlsa.matching),
                tlsa.cert_data
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            ),
            String::new(),
        ),
    };

    Ok(NetcupRecord {
        id: None,
        hostname: hostname.to_string(),
        record_type: record_type.to_string(),
        priority,
        destination,
        deleterecord: false,
        state: String::new(),
    })
}

fn decode_record(record_type: DnsRecordType, record: &NetcupRecord) -> crate::Result<DnsRecord> {
    Ok(match record_type {
        DnsRecordType::A => {
            DnsRecord::A(record.destination.parse().map_err(|e: AddrParseError| {
                Error::Parse(format!(
                    "invalid Netcup A value '{}': {e}",
                    record.destination
                ))
            })?)
        }
        DnsRecordType::AAAA => {
            DnsRecord::AAAA(record.destination.parse().map_err(|e: AddrParseError| {
                Error::Parse(format!(
                    "invalid Netcup AAAA value '{}': {e}",
                    record.destination
                ))
            })?)
        }
        DnsRecordType::CNAME => DnsRecord::CNAME(strip_trailing_dot(&record.destination)),
        DnsRecordType::NS => DnsRecord::NS(strip_trailing_dot(&record.destination)),
        DnsRecordType::MX => {
            let priority: u16 = record.priority.parse().map_err(|e| {
                Error::Parse(format!(
                    "invalid Netcup MX priority '{}': {e}",
                    record.priority
                ))
            })?;
            DnsRecord::MX(MXRecord {
                priority,
                exchange: strip_trailing_dot(&record.destination),
            })
        }
        DnsRecordType::TXT => DnsRecord::TXT(record.destination.clone()),
        DnsRecordType::SRV => parse_srv(&record.destination)?,
        DnsRecordType::TLSA => parse_tlsa(&record.destination)?,
        DnsRecordType::CAA => parse_caa(&record.destination)?,
    })
}

fn parse_srv(value: &str) -> crate::Result<DnsRecord> {
    let mut parts = value.split_whitespace();
    let priority = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV priority in '{value}': {e}")))?;
    let weight = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV weight in '{value}': {e}")))?;
    let port = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV port in '{value}': {e}")))?;
    let target = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV value '{value}'")))?;
    Ok(DnsRecord::SRV(SRVRecord {
        priority,
        weight,
        port,
        target: strip_trailing_dot(target),
    }))
}

fn parse_tlsa(value: &str) -> crate::Result<DnsRecord> {
    let mut parts = value.split_whitespace();
    let usage_raw: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA usage in '{value}': {e}")))?;
    let selector_raw: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA selector in '{value}': {e}")))?;
    let matching_raw: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA matching in '{value}': {e}")))?;
    let hex = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA value '{value}'")))?;
    Ok(DnsRecord::TLSA(TLSARecord {
        cert_usage: tlsa_cert_usage_from_u8(usage_raw)?,
        selector: tlsa_selector_from_u8(selector_raw)?,
        matching: tlsa_matching_from_u8(matching_raw)?,
        cert_data: decode_hex(hex)?,
    }))
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
            let (name, options) = parse_caa_kv(&unquoted);
            Ok(DnsRecord::CAA(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }))
        }
        "issuewild" => {
            let (name, options) = parse_caa_kv(&unquoted);
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

fn parse_caa_kv(value: &str) -> (Option<String>, Vec<KeyValue>) {
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
