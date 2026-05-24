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
    crypto::hmac_sha1,
    http::HttpClientBuilder,
    utils::{strip_origin_from_name, txt_chunks_to_text},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

const DEFAULT_ENDPOINT: &str = "https://api.dns.constellix.com";
const API_VERSION: &str = "v1";

#[derive(Clone)]
pub struct ConstellixProvider {
    client: HttpClientBuilder,
    api_key: String,
    secret_key: String,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecordRequest<'a> {
    name: &'a str,
    ttl: u32,
    #[serde(rename = "roundRobin")]
    round_robin: Vec<RoundRobinValue>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
struct RoundRobinValue {
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(rename = "priority", skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(rename = "level", skip_serializing_if = "Option::is_none")]
    level: Option<u16>,
    #[serde(rename = "weight", skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(rename = "port", skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(rename = "host", skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(rename = "caaType", skip_serializing_if = "Option::is_none")]
    caa_type: Option<String>,
    #[serde(rename = "flags", skip_serializing_if = "Option::is_none")]
    flags: Option<u8>,
    #[serde(rename = "tag", skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ConstellixDomain {
    id: i64,
}

#[derive(Deserialize, Debug)]
struct ConstellixRecord {
    id: i64,
    #[serde(default)]
    ttl: u32,
    #[serde(rename = "roundRobin", default)]
    round_robin: Vec<RoundRobinValue>,
}

impl ConstellixProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        secret_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        let secret_key = secret_key.as_ref();
        if api_key.is_empty() || secret_key.is_empty() {
            return Err(Error::Api("Constellix credentials missing".into()));
        }
        let client = HttpClientBuilder::default()
            .with_header("Accept", "application/json")
            .with_timeout(timeout);
        Ok(Self {
            client,
            api_key: api_key.to_string(),
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

    fn security_token(&self) -> String {
        let timestamp = Utc::now().timestamp_millis();
        let timestamp_str = timestamp.to_string();
        let mac = hmac_sha1(self.secret_key.as_bytes(), timestamp_str.as_bytes());
        let encoded = BASE64_STANDARD.encode(&mac);
        format!("{}:{}:{}", self.api_key, encoded, timestamp_str)
    }

    fn signed(&self, request: crate::http::HttpClient) -> crate::http::HttpClient {
        request.with_header("x-cns-security-token", self.security_token())
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
        let type_segment = record_type_segment(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let domain_id = self.obtain_domain_id(&domain).await?;

        let mut entries: Vec<RoundRobinValue> = Vec::with_capacity(records.len());
        for record in &records {
            entries.extend(record_to_round_robin_entries(record)?);
        }

        let mut ops: Vec<Value> = Vec::with_capacity(2);
        ops.push(json!({
            "type": type_segment,
            "delete": true,
            "filter": { "field": "name", "op": "eq", "value": subdomain },
        }));
        if !entries.is_empty() {
            ops.push(json!({
                "type": type_segment,
                "add": true,
                "set": {
                    "name": subdomain,
                    "ttl": ttl,
                    "roundRobin": entries,
                },
            }));
        }

        self.signed(
            self.client
                .post(format!(
                    "{}/{}/domains/{}/records",
                    self.endpoint, API_VERSION, domain_id
                ))
                .with_body(ops)?,
        )
        .send_raw()
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
        check_record_types(record_type, &records)?;
        let type_segment = record_type_segment(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let domain_id = self.obtain_domain_id(&domain).await?;

        let mut to_add: Vec<RoundRobinValue> = Vec::new();
        for record in &records {
            to_add.extend(record_to_round_robin_entries(record)?);
        }

        let existing = self
            .find_record(domain_id, type_segment, &subdomain)
            .await?;
        match existing {
            Some(current) => {
                let mut merged = current.round_robin.clone();
                for entry in to_add {
                    if !merged.contains(&entry) {
                        merged.push(entry);
                    }
                }
                if merged == current.round_robin {
                    return Ok(());
                }
                let body = CreateRecordRequest {
                    name: &subdomain,
                    ttl,
                    round_robin: merged,
                };
                self.signed(
                    self.client
                        .put(format!(
                            "{}/{}/domains/{}/records/{}/{}",
                            self.endpoint, API_VERSION, domain_id, type_segment, current.id
                        ))
                        .with_body(body)?,
                )
                .send_raw()
                .await
                .map(|_| ())
            }
            None => {
                let body = CreateRecordRequest {
                    name: &subdomain,
                    ttl,
                    round_robin: to_add,
                };
                self.signed(
                    self.client
                        .post(format!(
                            "{}/{}/domains/{}/records/{}",
                            self.endpoint, API_VERSION, domain_id, type_segment
                        ))
                        .with_body(body)?,
                )
                .send_raw()
                .await
                .map(|_| ())
            }
        }
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
        let type_segment = record_type_segment(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let domain_id = self.obtain_domain_id(&domain).await?;

        let mut to_remove: Vec<RoundRobinValue> = Vec::new();
        for record in &records {
            to_remove.extend(record_to_round_robin_entries(record)?);
        }

        let existing = match self
            .find_record(domain_id, type_segment, &subdomain)
            .await?
        {
            Some(r) => r,
            None => return Ok(()),
        };

        let mut remaining: Vec<RoundRobinValue> = existing
            .round_robin
            .iter()
            .filter(|entry| !to_remove.contains(entry))
            .cloned()
            .collect();

        if remaining.len() == existing.round_robin.len() {
            return Ok(());
        }

        if remaining.is_empty() {
            self.signed(self.client.delete(format!(
                "{}/{}/domains/{}/records/{}/{}",
                self.endpoint, API_VERSION, domain_id, type_segment, existing.id
            )))
            .send_raw()
            .await
            .map(|_| ())
        } else {
            let ttl = existing.ttl;
            let body = CreateRecordRequest {
                name: &subdomain,
                ttl,
                round_robin: std::mem::take(&mut remaining),
            };
            self.signed(
                self.client
                    .put(format!(
                        "{}/{}/domains/{}/records/{}/{}",
                        self.endpoint, API_VERSION, domain_id, type_segment, existing.id
                    ))
                    .with_body(body)?,
            )
            .send_raw()
            .await
            .map(|_| ())
        }
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let type_segment = record_type_segment(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let domain_id = self.obtain_domain_id(&domain).await?;

        let existing = match self
            .find_record(domain_id, type_segment, &subdomain)
            .await?
        {
            Some(r) => r,
            None => return Ok(Vec::new()),
        };

        let mut out = Vec::with_capacity(existing.round_robin.len());
        for entry in existing.round_robin {
            out.push(round_robin_to_record(record_type, entry)?);
        }
        Ok(out)
    }

    async fn obtain_domain_id(&self, domain: &str) -> crate::Result<i64> {
        let url = format!(
            "{}/{}/domains/search?exact={}",
            self.endpoint,
            API_VERSION,
            urlencode(domain)
        );
        let domains: Vec<ConstellixDomain> = self.signed(self.client.get(url)).send().await?;
        domains
            .into_iter()
            .next()
            .map(|d| d.id)
            .ok_or_else(|| Error::Api(format!("Constellix domain {} not found", domain)))
    }

    async fn find_record(
        &self,
        domain_id: i64,
        type_segment: &str,
        subdomain: &str,
    ) -> crate::Result<Option<ConstellixRecord>> {
        let url = format!(
            "{}/{}/domains/{}/records/{}/search?exact={}",
            self.endpoint,
            API_VERSION,
            domain_id,
            type_segment,
            urlencode(subdomain)
        );
        let records: Vec<ConstellixRecord> = self.signed(self.client.get(url)).send().await?;
        Ok(records.into_iter().next())
    }
}

fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let c = *byte as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
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

fn record_type_segment(record_type: DnsRecordType) -> crate::Result<&'static str> {
    match record_type {
        DnsRecordType::A => Ok("a"),
        DnsRecordType::AAAA => Ok("aaaa"),
        DnsRecordType::CNAME => Ok("cname"),
        DnsRecordType::NS => Ok("ns"),
        DnsRecordType::MX => Ok("mx"),
        DnsRecordType::TXT => Ok("txt"),
        DnsRecordType::SRV => Ok("srv"),
        DnsRecordType::CAA => Ok("caa"),
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by Constellix".into(),
        )),
    }
}

fn render_txt_value(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    txt_chunks_to_text(&mut out, text, " ");
    out
}

fn record_to_round_robin_entries(record: &DnsRecord) -> crate::Result<Vec<RoundRobinValue>> {
    let mut entry = RoundRobinValue::default();
    match record {
        DnsRecord::A(addr) => entry.value = Some(addr.to_string()),
        DnsRecord::AAAA(addr) => entry.value = Some(addr.to_string()),
        DnsRecord::CNAME(target) => entry.host = Some(target.clone()),
        DnsRecord::NS(target) => entry.host = Some(target.clone()),
        DnsRecord::MX(mx) => {
            entry.value = Some(mx.exchange.clone());
            entry.level = Some(mx.priority);
        }
        DnsRecord::TXT(text) => {
            entry.value = Some(render_txt_value(text));
        }
        DnsRecord::SRV(srv) => {
            entry.host = Some(srv.target.clone());
            entry.priority = Some(srv.priority);
            entry.weight = Some(srv.weight);
            entry.port = Some(srv.port);
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Constellix".into(),
            ));
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, val) = caa.clone().decompose();
            entry.value = Some(val);
            entry.flags = Some(flags);
            entry.tag = Some(tag);
        }
    }
    Ok(vec![entry])
}

fn round_robin_to_record(
    record_type: DnsRecordType,
    entry: RoundRobinValue,
) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => {
            let value = entry
                .value
                .ok_or_else(|| Error::Parse("Constellix A record missing value".into()))?;
            let addr: Ipv4Addr = value
                .parse()
                .map_err(|e| Error::Parse(format!("invalid IPv4 in Constellix A record: {e}")))?;
            Ok(DnsRecord::A(addr))
        }
        DnsRecordType::AAAA => {
            let value = entry
                .value
                .ok_or_else(|| Error::Parse("Constellix AAAA record missing value".into()))?;
            let addr: Ipv6Addr = value.parse().map_err(|e| {
                Error::Parse(format!("invalid IPv6 in Constellix AAAA record: {e}"))
            })?;
            Ok(DnsRecord::AAAA(addr))
        }
        DnsRecordType::CNAME => {
            let target = entry
                .host
                .or(entry.value)
                .ok_or_else(|| Error::Parse("Constellix CNAME record missing host".into()))?;
            Ok(DnsRecord::CNAME(target))
        }
        DnsRecordType::NS => {
            let target = entry
                .host
                .or(entry.value)
                .ok_or_else(|| Error::Parse("Constellix NS record missing host".into()))?;
            Ok(DnsRecord::NS(target))
        }
        DnsRecordType::MX => {
            let exchange = entry
                .value
                .or_else(|| entry.host.clone())
                .ok_or_else(|| Error::Parse("Constellix MX record missing exchange".into()))?;
            let priority = entry
                .level
                .or(entry.priority)
                .ok_or_else(|| Error::Parse("Constellix MX record missing level".into()))?;
            Ok(DnsRecord::MX(MXRecord { exchange, priority }))
        }
        DnsRecordType::TXT => {
            let value = entry
                .value
                .ok_or_else(|| Error::Parse("Constellix TXT record missing value".into()))?;
            Ok(DnsRecord::TXT(unquote_txt(&value)))
        }
        DnsRecordType::SRV => {
            let target = entry
                .host
                .ok_or_else(|| Error::Parse("Constellix SRV record missing host".into()))?;
            let priority = entry
                .priority
                .ok_or_else(|| Error::Parse("Constellix SRV record missing priority".into()))?;
            let weight = entry
                .weight
                .ok_or_else(|| Error::Parse("Constellix SRV record missing weight".into()))?;
            let port = entry
                .port
                .ok_or_else(|| Error::Parse("Constellix SRV record missing port".into()))?;
            Ok(DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target,
            }))
        }
        DnsRecordType::CAA => {
            let value = entry
                .value
                .ok_or_else(|| Error::Parse("Constellix CAA record missing value".into()))?;
            let flags = entry.flags.unwrap_or(0);
            let tag = entry
                .tag
                .ok_or_else(|| Error::Parse("Constellix CAA record missing tag".into()))?;
            Ok(DnsRecord::CAA(build_caa(flags, &tag, value)?))
        }
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by Constellix".into(),
        )),
    }
}

fn unquote_txt(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let chars = content.chars().peekable();
    let mut in_quote = false;
    let mut escape = false;
    for ch in chars {
        if escape {
            out.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' if in_quote => escape = true,
            '"' => in_quote = !in_quote,
            _ if in_quote => out.push(ch),
            _ => {}
        }
    }
    if !out.is_empty() || content.contains('"') {
        out
    } else {
        content.to_string()
    }
}

fn build_caa(flags: u8, tag: &str, value: String) -> crate::Result<CAARecord> {
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
