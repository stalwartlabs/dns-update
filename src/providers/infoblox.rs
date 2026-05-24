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
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, KeyValue, MXRecord, Result, SRVRecord,
    TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector,
    http::{HttpClient, HttpClientBuilder},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

const DEFAULT_WAPI_VERSION: &str = "2.11";
const DEFAULT_PORT: &str = "443";
const DEFAULT_VIEW: &str = "External";

#[derive(Debug, Clone)]
pub struct InfobloxConfig {
    pub host: String,
    pub port: Option<String>,
    pub username: String,
    pub password: String,
    pub wapi_version: Option<String>,
    pub dns_view: Option<String>,
    pub request_timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct InfobloxProvider {
    client: HttpClient,
    base_url: String,
    dns_view: String,
}

#[derive(Deserialize, Debug)]
struct InfobloxError {
    #[serde(default, rename = "Error")]
    error: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

impl InfobloxProvider {
    pub(crate) fn new(config: InfobloxConfig) -> Result<Self> {
        if config.host.is_empty() {
            return Err(Error::Client("Infoblox host is required".into()));
        }
        if config.username.is_empty() || config.password.is_empty() {
            return Err(Error::Client("Infoblox credentials are required".into()));
        }

        let port = config.port.unwrap_or_else(|| DEFAULT_PORT.to_string());
        let version = config
            .wapi_version
            .unwrap_or_else(|| DEFAULT_WAPI_VERSION.to_string());
        let scheme = if config.host.starts_with("http://") || config.host.starts_with("https://") {
            ""
        } else {
            "https://"
        };
        let host = config.host.trim_end_matches('/');
        let base_url = if scheme.is_empty() {
            format!("{host}/wapi/v{version}")
        } else if port == "443" {
            format!("{scheme}{host}/wapi/v{version}")
        } else {
            format!("{scheme}{host}:{port}/wapi/v{version}")
        };

        let credentials = format!("{}:{}", config.username, config.password);
        let auth_header = format!("Basic {}", BASE64_STANDARD.encode(credentials.as_bytes()));

        let client = HttpClientBuilder::default()
            .with_header("Authorization", auth_header)
            .with_timeout(config.request_timeout)
            .build();

        Ok(Self {
            client,
            base_url,
            dns_view: config.dns_view.unwrap_or_else(|| DEFAULT_VIEW.to_string()),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        self.base_url = endpoint.as_ref().trim_end_matches('/').to_string();
        self
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        check_record_types(record_type, &records)?;
        let object = wapi_object_for_type(record_type)?;
        let name = name.into_name().into_owned();

        let existing = self.list_records(object, &name).await?;

        if records.is_empty() {
            for entry in existing {
                self.delete_record(&entry._ref).await?;
            }
            return Ok(());
        }

        let mut to_add: Vec<DnsRecord> = Vec::new();
        let mut existing_pool: Vec<ListedRecord> = existing;

        for record in records {
            if let Some(idx) = existing_pool
                .iter()
                .position(|entry| infoblox_value_matches(&entry.fields, &record))
            {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(record);
            }
        }

        for entry in existing_pool {
            self.delete_record(&entry._ref).await?;
        }
        for record in to_add {
            let body = build_create_body(&name, &record, ttl, &self.dns_view)?;
            self.post_record(object, &body).await?;
        }
        Ok(())
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        check_record_types(record_type, &records)?;
        let object = wapi_object_for_type(record_type)?;
        let name = name.into_name().into_owned();

        let existing = self.list_records(object, &name).await?;

        for record in records {
            if existing
                .iter()
                .any(|entry| infoblox_value_matches(&entry.fields, &record))
            {
                continue;
            }
            let body = build_create_body(&name, &record, ttl, &self.dns_view)?;
            self.post_record(object, &body).await?;
        }
        Ok(())
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        check_record_types(record_type, &records)?;
        let object = wapi_object_for_type(record_type)?;
        let name = name.into_name().into_owned();

        let existing = self.list_records(object, &name).await?;

        for record in records {
            if let Some(entry) = existing
                .iter()
                .find(|entry| infoblox_value_matches(&entry.fields, &record))
            {
                self.delete_record(&entry._ref).await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _origin: impl IntoFqdn<'_>,
    ) -> Result<Vec<DnsRecord>> {
        let object = wapi_object_for_type(record_type)?;
        let name = name.into_name().into_owned();
        let listed = self.list_records(object, &name).await?;
        listed
            .into_iter()
            .map(|entry| infoblox_value_to_record(&entry.fields, record_type))
            .collect()
    }

    async fn list_records(&self, object: &str, name: &str) -> Result<Vec<ListedRecord>> {
        let url = format!(
            "{base}/{object}?name={name}&view={view}",
            base = self.base_url,
            view = self.dns_view
        );
        let raw = self
            .client
            .get(url)
            .send_raw()
            .await
            .map_err(map_list_error)?;
        let values: Vec<Value> = if raw.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(&raw).map_err(|err| {
                Error::Api(format!("Failed to parse Infoblox lookup response: {err}"))
            })?
        };
        values
            .into_iter()
            .map(|value| {
                let reference = value
                    .get("_ref")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::Api("Infoblox response missing _ref".into()))?
                    .to_string();
                Ok(ListedRecord {
                    _ref: reference,
                    fields: value,
                })
            })
            .collect()
    }

    async fn post_record(&self, object: &str, body: &Value) -> Result<()> {
        self.client
            .post(format!("{}/{object}", self.base_url))
            .with_body(body)?
            .send_with_retry::<Value>(3)
            .await
            .map(|_| ())
            .map_err(|err| map_action_error(err, "create"))
    }

    async fn delete_record(&self, reference: &str) -> Result<()> {
        self.client
            .delete(format!("{}/{reference}", self.base_url))
            .send_with_retry::<Value>(3)
            .await
            .map(|_| ())
            .map_err(|err| map_action_error(err, "delete"))
    }
}

struct ListedRecord {
    _ref: String,
    fields: Value,
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> Result<()> {
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

fn wapi_object_for_type(record_type: DnsRecordType) -> Result<&'static str> {
    Ok(match record_type {
        DnsRecordType::A => "record:a",
        DnsRecordType::AAAA => "record:aaaa",
        DnsRecordType::CNAME => "record:cname",
        DnsRecordType::NS => {
            return Err(Error::Api(
                "NS records are not supported by Infoblox (requires non-empty glue addresses)"
                    .to_string(),
            ));
        }
        DnsRecordType::MX => "record:mx",
        DnsRecordType::TXT => "record:txt",
        DnsRecordType::SRV => "record:srv",
        DnsRecordType::CAA => "record:caa",
        DnsRecordType::TLSA => "record:tlsa",
    })
}

fn build_create_body(name: &str, record: &DnsRecord, ttl: u32, view: &str) -> Result<Value> {
    let mut body = build_update_body(record, ttl)?;
    if let Value::Object(ref mut map) = body {
        map.insert("name".to_string(), Value::String(name.to_string()));
        map.insert("view".to_string(), Value::String(view.to_string()));
    }
    Ok(body)
}

fn build_update_body(record: &DnsRecord, ttl: u32) -> Result<Value> {
    let mut body = match record {
        DnsRecord::A(ip) => json!({ "ipv4addr": ip.to_string() }),
        DnsRecord::AAAA(ip) => json!({ "ipv6addr": ip.to_string() }),
        DnsRecord::CNAME(target) => json!({ "canonical": target }),
        DnsRecord::NS(_) => {
            return Err(Error::Api(
                "NS records are not supported by Infoblox (requires non-empty glue addresses)"
                    .to_string(),
            ));
        }
        DnsRecord::MX(mx) => json!({
            "mail_exchanger": mx.exchange,
            "preference": mx.priority,
        }),
        DnsRecord::TXT(value) => json!({ "text": value }),
        DnsRecord::SRV(srv) => json!({
            "priority": srv.priority,
            "weight": srv.weight,
            "port": srv.port,
            "target": srv.target,
        }),
        DnsRecord::TLSA(tlsa) => json!({
            "certificate_usage": u8::from(tlsa.cert_usage),
            "selector": u8::from(tlsa.selector),
            "matched_type": u8::from(tlsa.matching),
            "certificate_data": tlsa.cert_data.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        }),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            json!({
                "ca_flag": flags,
                "ca_tag": tag,
                "ca_value": value,
            })
        }
    };
    if let Value::Object(ref mut map) = body
        && ttl > 0
    {
        map.insert("ttl".to_string(), Value::Number(ttl.into()));
        map.insert("use_ttl".to_string(), Value::Bool(true));
    }
    Ok(body)
}

fn infoblox_value_matches(value: &Value, record: &DnsRecord) -> bool {
    match record {
        DnsRecord::A(ip) => value
            .get("ipv4addr")
            .and_then(Value::as_str)
            .is_some_and(|content| content == ip.to_string()),
        DnsRecord::AAAA(ip) => value
            .get("ipv6addr")
            .and_then(Value::as_str)
            .is_some_and(|content| content == ip.to_string()),
        DnsRecord::CNAME(target) => value
            .get("canonical")
            .and_then(Value::as_str)
            .is_some_and(|content| content.trim_end_matches('.') == target.trim_end_matches('.')),
        DnsRecord::NS(target) => value
            .get("nameserver")
            .and_then(Value::as_str)
            .is_some_and(|content| content.trim_end_matches('.') == target.trim_end_matches('.')),
        DnsRecord::MX(mx) => {
            let exchange_matches = value
                .get("mail_exchanger")
                .and_then(Value::as_str)
                .map(|value| value.trim_end_matches('.') == mx.exchange.trim_end_matches('.'))
                .unwrap_or(false);
            let preference_matches = value
                .get("preference")
                .and_then(Value::as_u64)
                .map(|value| value as u16 == mx.priority)
                .unwrap_or(false);
            exchange_matches && preference_matches
        }
        DnsRecord::TXT(text) => value
            .get("text")
            .and_then(Value::as_str)
            .is_some_and(|content| content == text),
        DnsRecord::SRV(srv) => {
            let target_matches = value
                .get("target")
                .and_then(Value::as_str)
                .map(|target| target.trim_end_matches('.') == srv.target.trim_end_matches('.'))
                .unwrap_or(false);
            let port_matches = value
                .get("port")
                .and_then(Value::as_u64)
                .map(|port| port as u16 == srv.port)
                .unwrap_or(false);
            let priority_matches = value
                .get("priority")
                .and_then(Value::as_u64)
                .map(|priority| priority as u16 == srv.priority)
                .unwrap_or(false);
            let weight_matches = value
                .get("weight")
                .and_then(Value::as_u64)
                .map(|weight| weight as u16 == srv.weight)
                .unwrap_or(false);
            target_matches && port_matches && priority_matches && weight_matches
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value_str) = caa.clone().decompose();
            let flag_matches = value
                .get("ca_flag")
                .and_then(Value::as_u64)
                .map(|content| content as u8 == flags)
                .unwrap_or(false);
            let tag_matches = value
                .get("ca_tag")
                .and_then(Value::as_str)
                .map(|content| content == tag)
                .unwrap_or(false);
            let value_matches = value
                .get("ca_value")
                .and_then(Value::as_str)
                .map(|content| content == value_str)
                .unwrap_or(false);
            flag_matches && tag_matches && value_matches
        }
        DnsRecord::TLSA(tlsa) => {
            let usage_matches = value
                .get("certificate_usage")
                .and_then(Value::as_u64)
                .map(|content| content as u8 == u8::from(tlsa.cert_usage))
                .unwrap_or(false);
            let selector_matches = value
                .get("selector")
                .and_then(Value::as_u64)
                .map(|content| content as u8 == u8::from(tlsa.selector))
                .unwrap_or(false);
            let matched_matches = value
                .get("matched_type")
                .and_then(Value::as_u64)
                .map(|content| content as u8 == u8::from(tlsa.matching))
                .unwrap_or(false);
            let cert_hex: String = tlsa.cert_data.iter().map(|b| format!("{b:02x}")).collect();
            let cert_matches = value
                .get("certificate_data")
                .and_then(Value::as_str)
                .map(|content| content.eq_ignore_ascii_case(&cert_hex))
                .unwrap_or(false);
            usage_matches && selector_matches && matched_matches && cert_matches
        }
    }
}

fn infoblox_value_to_record(value: &Value, record_type: DnsRecordType) -> Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => {
            let raw = value
                .get("ipv4addr")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Parse("Infoblox A response missing ipv4addr".into()))?;
            let addr = raw
                .parse()
                .map_err(|err| Error::Parse(format!("Invalid Infoblox A address {raw}: {err}")))?;
            Ok(DnsRecord::A(addr))
        }
        DnsRecordType::AAAA => {
            let raw = value
                .get("ipv6addr")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Parse("Infoblox AAAA response missing ipv6addr".into()))?;
            let addr = raw.parse().map_err(|err| {
                Error::Parse(format!("Invalid Infoblox AAAA address {raw}: {err}"))
            })?;
            Ok(DnsRecord::AAAA(addr))
        }
        DnsRecordType::CNAME => {
            let target = value
                .get("canonical")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Parse("Infoblox CNAME response missing canonical".into()))?;
            Ok(DnsRecord::CNAME(target.to_string()))
        }
        DnsRecordType::NS => {
            let target = value
                .get("nameserver")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Parse("Infoblox NS response missing nameserver".into()))?;
            Ok(DnsRecord::NS(target.to_string()))
        }
        DnsRecordType::MX => {
            let exchange = value
                .get("mail_exchanger")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Parse("Infoblox MX response missing mail_exchanger".into()))?
                .to_string();
            let priority = value
                .get("preference")
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::Parse("Infoblox MX response missing preference".into()))?
                as u16;
            Ok(DnsRecord::MX(MXRecord { exchange, priority }))
        }
        DnsRecordType::TXT => {
            let text = value
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Parse("Infoblox TXT response missing text".into()))?;
            Ok(DnsRecord::TXT(text.to_string()))
        }
        DnsRecordType::SRV => {
            let target = value
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Parse("Infoblox SRV response missing target".into()))?
                .to_string();
            let port = value
                .get("port")
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::Parse("Infoblox SRV response missing port".into()))?
                as u16;
            let priority = value
                .get("priority")
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::Parse("Infoblox SRV response missing priority".into()))?
                as u16;
            let weight = value
                .get("weight")
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::Parse("Infoblox SRV response missing weight".into()))?
                as u16;
            Ok(DnsRecord::SRV(SRVRecord {
                target,
                priority,
                weight,
                port,
            }))
        }
        DnsRecordType::CAA => {
            let flags = value
                .get("ca_flag")
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::Parse("Infoblox CAA response missing ca_flag".into()))?
                as u8;
            let tag = value
                .get("ca_tag")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Parse("Infoblox CAA response missing ca_tag".into()))?
                .to_string();
            let raw_value = value
                .get("ca_value")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Parse("Infoblox CAA response missing ca_value".into()))?
                .to_string();
            Ok(DnsRecord::CAA(build_caa(flags, &tag, raw_value)?))
        }
        DnsRecordType::TLSA => {
            let usage = value
                .get("certificate_usage")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    Error::Parse("Infoblox TLSA response missing certificate_usage".into())
                })? as u8;
            let selector = value
                .get("selector")
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::Parse("Infoblox TLSA response missing selector".into()))?
                as u8;
            let matched = value
                .get("matched_type")
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::Parse("Infoblox TLSA response missing matched_type".into()))?
                as u8;
            let cert_hex = value
                .get("certificate_data")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    Error::Parse("Infoblox TLSA response missing certificate_data".into())
                })?;
            Ok(DnsRecord::TLSA(TLSARecord {
                cert_usage: tlsa_cert_usage_from_u8(usage)?,
                selector: tlsa_selector_from_u8(selector)?,
                matching: tlsa_matching_from_u8(matched)?,
                cert_data: decode_hex(cert_hex)?,
            }))
        }
    }
}

fn build_caa(flags: u8, tag: &str, value: String) -> Result<CAARecord> {
    let issuer_critical = flags & 0x80 != 0;
    match tag {
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
        other => Err(Error::Parse(format!("unknown CAA tag: {other}"))),
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

fn decode_hex(hex: &str) -> Result<Vec<u8>> {
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

fn tlsa_cert_usage_from_u8(value: u8) -> Result<TlsaCertUsage> {
    Ok(match value {
        0 => TlsaCertUsage::PkixTa,
        1 => TlsaCertUsage::PkixEe,
        2 => TlsaCertUsage::DaneTa,
        3 => TlsaCertUsage::DaneEe,
        255 => TlsaCertUsage::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA cert usage: {value}"))),
    })
}

fn tlsa_selector_from_u8(value: u8) -> Result<TlsaSelector> {
    Ok(match value {
        0 => TlsaSelector::Full,
        1 => TlsaSelector::Spki,
        255 => TlsaSelector::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA selector: {value}"))),
    })
}

fn tlsa_matching_from_u8(value: u8) -> Result<TlsaMatching> {
    Ok(match value {
        0 => TlsaMatching::Raw,
        1 => TlsaMatching::Sha256,
        2 => TlsaMatching::Sha512,
        255 => TlsaMatching::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA matching: {value}"))),
    })
}

fn map_list_error(err: Error) -> Error {
    match err {
        Error::Api(message) => Error::Api(format!(
            "Infoblox lookup failed: {}",
            extract_infoblox_message(&message)
        )),
        other => other,
    }
}

fn map_action_error(err: Error, action: &str) -> Error {
    match err {
        Error::Api(message) => Error::Api(format!(
            "Infoblox {action} failed: {}",
            extract_infoblox_message(&message)
        )),
        other => other,
    }
}

fn extract_infoblox_message(text: &str) -> String {
    if let Some(start) = text.find('{')
        && let Some(end) = text.rfind('}')
        && start <= end
    {
        let candidate = &text[start..=end];
        if let Ok(value) = serde_json::from_str::<InfobloxError>(candidate)
            && let Some(message) = value.error.or(value.text)
            && !message.is_empty()
        {
            return message;
        }
    }
    text.to_string()
}
