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
    TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector,
    http::{HttpClient, HttpClientBuilder},
    utils::{strip_origin_from_name, txt_chunks_to_text},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api.infomaniak.com";

#[derive(Clone)]
pub struct InfomaniakProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Deserialize, Debug)]
struct ApiResponse<T> {
    #[serde(default)]
    result: String,
    #[serde(default)]
    data: Option<T>,
    #[serde(default)]
    error: Option<ApiErrorBody>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ApiErrorBody {
    #[serde(default)]
    code: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize, Debug, Clone)]
struct ExistingRecord {
    id: u64,
    #[serde(default)]
    source: String,
    #[serde(default, rename = "source_idn")]
    source_idn: Option<String>,
    #[serde(default, rename = "type")]
    record_type: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    priority: Option<u16>,
}

#[derive(Serialize, Debug)]
struct RecordPayload<'a> {
    source: &'a str,
    target: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    dkim_type: Option<&'a str>,
}

const ERR_DKIM_TYPE: &str = "choose_dkim_type";
const ERR_SPF_SINGLETON: &str = "you_can_only_add_one_spf_save_for_each_dns_zone";
const SPF_TOKEN: &str = "v=spf1";

#[derive(Debug, Clone, PartialEq, Eq)]
struct WireRecord {
    target: String,
    priority: Option<u16>,
}

impl InfomaniakProvider {
    pub(crate) fn new(access_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", access_token.as_ref()))
            .with_header("Accept", "application/json")
            .with_timeout(timeout)
            .build();
        Self {
            client,
            endpoint: DEFAULT_ENDPOINT.to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().trim_end_matches('/').to_string(),
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
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let (domain, all_records) = self.fetch_zone_records(&origin).await?;
        let source = source_from_name(&name, &domain);

        let desired = build_wire_records(records)?;
        let mut existing_pool = filter_records(all_records, &source, record_type);

        let mut to_add = Vec::new();
        for wire in desired {
            if let Some(idx) = existing_pool.iter().position(|r| matches_wire(r, &wire)) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(wire);
            }
        }

        for entry in existing_pool {
            self.delete_record(&domain, entry.id).await?;
        }
        let dkim_type = is_dkim_owner(record_type.as_str(), &source).then_some("rsa");
        for wire in to_add {
            self.post_record(
                &domain,
                &source,
                &wire.target,
                record_type.as_str(),
                ttl,
                dkim_type,
            )
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
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let (domain, all_records) = self.fetch_zone_records(&origin).await?;
        let source = source_from_name(&name, &domain);

        let desired = build_wire_records(records)?;
        let existing = filter_records(all_records, &source, record_type);
        let dkim_type = is_dkim_owner(record_type.as_str(), &source).then_some("rsa");

        for wire in desired {
            if existing.iter().any(|r| matches_wire(r, &wire)) {
                continue;
            }
            self.post_record(
                &domain,
                &source,
                &wire.target,
                record_type.as_str(),
                ttl,
                dkim_type,
            )
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
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let (domain, all_records) = self.fetch_zone_records(&origin).await?;
        let source = source_from_name(&name, &domain);

        let to_remove = build_wire_records(records)?;
        let existing = filter_records(all_records, &source, record_type);

        for wire in to_remove {
            if let Some(entry) = existing.iter().find(|r| matches_wire(r, &wire)) {
                self.delete_record(&domain, entry.id).await?;
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
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let (domain, all_records) = self.fetch_zone_records(&origin).await?;
        let source = source_from_name(&name, &domain);
        let existing = filter_records(all_records, &source, record_type);
        existing
            .into_iter()
            .map(|r| decode_existing(&r, record_type))
            .collect()
    }

    async fn replace_existing_spf(
        &self,
        domain: &str,
        source: &str,
        target: &str,
        ttl: u32,
    ) -> crate::Result<()> {
        let url = format!("{}/2/zones/{}/records", self.endpoint, domain);
        let existing = self
            .send_expect_success::<Vec<ExistingRecord>>(self.client.get(&url))
            .await?;
        let existing_id = existing
            .into_iter()
            .find(|r| {
                r.record_type.eq_ignore_ascii_case("TXT")
                    && (r.source == source || r.source_idn.as_deref() == Some(source))
                    && unquote_txt(&r.target).starts_with(SPF_TOKEN)
            })
            .map(|r| r.id)
            .ok_or_else(|| {
                Error::Api(
                    "Infomaniak rejected SPF as singleton but no existing SPF record was found"
                        .to_string(),
                )
            })?;

        self.put_record(domain, existing_id, source, target, "TXT", ttl, None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn post_record(
        &self,
        domain: &str,
        source: &str,
        target: &str,
        record_type: &str,
        ttl: u32,
        mut dkim_type: Option<&'static str>,
    ) -> crate::Result<()> {
        let url = format!("{}/2/zones/{}/records", self.endpoint, domain);
        loop {
            let payload = RecordPayload {
                source,
                target,
                record_type,
                ttl,
                dkim_type,
            };
            let request = self.client.post(url.clone()).with_body(&payload)?;
            match self.send_expect_success::<serde_json::Value>(request).await {
                Ok(_) => return Ok(()),
                Err(err) => match recovery_action(&err, dkim_type) {
                    Recovery::RetryWithDkim(next) => {
                        dkim_type = Some(next);
                        continue;
                    }
                    Recovery::ReplaceSpf => {
                        return self.replace_existing_spf(domain, source, target, ttl).await;
                    }
                    Recovery::Propagate => return Err(err),
                },
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn put_record(
        &self,
        domain: &str,
        record_id: u64,
        source: &str,
        target: &str,
        record_type: &str,
        ttl: u32,
        dkim_type: Option<&'static str>,
    ) -> crate::Result<()> {
        let payload = RecordPayload {
            source,
            target,
            record_type,
            ttl,
            dkim_type,
        };
        let url = format!("{}/2/zones/{}/records/{}", self.endpoint, domain, record_id);
        self.send_expect_success::<serde_json::Value>(self.client.put(url).with_body(payload)?)
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, domain: &str, record_id: u64) -> crate::Result<()> {
        let url = format!("{}/2/zones/{}/records/{}", self.endpoint, domain, record_id);
        self.send_expect_success::<serde_json::Value>(self.client.delete(url))
            .await
            .map(|_| ())
    }

    async fn fetch_zone_records(
        &self,
        origin: &str,
    ) -> crate::Result<(String, Vec<ExistingRecord>)> {
        let origin = origin.trim_end_matches('.');
        let mut candidate = origin;
        loop {
            match self.try_fetch_records(candidate).await {
                Ok(records) => return Ok((candidate.to_string(), records)),
                Err(Error::NotFound) => {}
                Err(err) => return Err(err),
            }
            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => {
                    return Err(Error::Api(format!(
                        "Infomaniak: no managed DNS zone found for '{origin}'"
                    )));
                }
            }
        }
    }

    async fn try_fetch_records(&self, zone: &str) -> crate::Result<Vec<ExistingRecord>> {
        let url = format!("{}/2/zones/{}/records", self.endpoint, zone);
        self.send_expect_success::<Vec<ExistingRecord>>(self.client.get(url))
            .await
    }

    async fn send_expect_success<T>(&self, request: crate::http::HttpRequest) -> crate::Result<T>
    where
        T: serde::de::DeserializeOwned + Default,
    {
        let response: ApiResponse<T> = request.send().await?;
        if response.result != "success" {
            return Err(Error::Api(format!(
                "Infomaniak API error: {:?}",
                response.error
            )));
        }
        Ok(response.data.unwrap_or_default())
    }
}

fn source_from_name(name: &str, domain: &str) -> String {
    strip_origin_from_name(name, domain, Some(""))
}

fn filter_records(
    records: Vec<ExistingRecord>,
    source: &str,
    record_type: DnsRecordType,
) -> Vec<ExistingRecord> {
    let type_str = record_type.as_str();
    records
        .into_iter()
        .filter(|r| {
            (r.source == source || r.source_idn.as_deref() == Some(source))
                && r.record_type.eq_ignore_ascii_case(type_str)
        })
        .collect()
}

fn ensure_trailing_dot(value: &str) -> String {
    if value.ends_with('.') {
        value.to_string()
    } else {
        format!("{value}.")
    }
}

fn is_dkim_owner(record_type: &str, source: &str) -> bool {
    record_type.eq_ignore_ascii_case("TXT")
        && source
            .split('.')
            .any(|label| label.eq_ignore_ascii_case("_domainkey"))
}

fn unquote_txt(target: &str) -> String {
    target
        .split('"')
        .filter(|s| !s.trim().is_empty())
        .flat_map(|chunk| chunk.chars())
        .filter(|c| *c != ' ')
        .collect()
}

fn normalize_txt_wire(target: &str) -> String {
    let mut out = String::with_capacity(target.len() + 4);
    txt_chunks_to_text(&mut out, &unquote_txt(target), " ");
    out
}

fn encode_txt_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 4);
    txt_chunks_to_text(&mut out, value, " ");
    out
}

enum Recovery {
    RetryWithDkim(&'static str),
    ReplaceSpf,
    Propagate,
}

fn recovery_action(err: &Error, current_dkim: Option<&str>) -> Recovery {
    let Error::Api(msg) = err else {
        return Recovery::Propagate;
    };
    if msg.contains(ERR_DKIM_TYPE) {
        return match current_dkim {
            None => Recovery::RetryWithDkim("rsa"),
            Some("rsa") => Recovery::RetryWithDkim("ed25519"),
            _ => Recovery::Propagate,
        };
    }
    if msg.contains(ERR_SPF_SINGLETON) {
        return Recovery::ReplaceSpf;
    }
    Recovery::Propagate
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

fn build_wire_records(records: Vec<DnsRecord>) -> crate::Result<Vec<WireRecord>> {
    records
        .into_iter()
        .map(|r| {
            let (_, target, priority) = encode_record(&r)?;
            Ok(WireRecord { target, priority })
        })
        .collect()
}

fn normalize_tlsa_wire(target: &str) -> String {
    let mut parts = target.split_whitespace();

    let header = parts.by_ref().take(3).collect::<Vec<_>>().join(" ");

    let data = parts
        .map(|p| p.to_ascii_uppercase())
        .collect::<Vec<_>>()
        .join("");

    if data.is_empty() {
        header
    } else {
        format!("{header} {data}")
    }
}

fn matches_wire(existing: &ExistingRecord, wire: &WireRecord) -> bool {
    let target_match = if existing.record_type == "TLSA" {
        normalize_tlsa_wire(&existing.target) == normalize_tlsa_wire(&wire.target)
    } else {
        normalize_txt_wire(&existing.target) == normalize_txt_wire(&wire.target)
    };
    if !target_match {
        return false;
    }

    match (wire.priority, existing.priority) {
        (Some(a), Some(b)) => a == b,
        (None, _) => true,
        (Some(_), None) => false,
    }
}

fn encode_record(record: &DnsRecord) -> crate::Result<(&'static str, String, Option<u16>)> {
    Ok(match record {
        DnsRecord::A(addr) => ("A", addr.to_string(), None),
        DnsRecord::AAAA(addr) => ("AAAA", addr.to_string(), None),
        DnsRecord::CNAME(value) => ("CNAME", ensure_trailing_dot(value), None),
        DnsRecord::NS(value) => ("NS", ensure_trailing_dot(value), None),
        DnsRecord::MX(mx) => (
            "MX",
            format!("{} {}", mx.priority, ensure_trailing_dot(&mx.exchange)),
            None,
        ),
        DnsRecord::TXT(value) => ("TXT", encode_txt_value(value), None),
        DnsRecord::SRV(srv) => (
            "SRV",
            format!(
                "{} {} {} {}",
                srv.priority,
                srv.weight,
                srv.port,
                ensure_trailing_dot(&srv.target),
            ),
            None,
        ),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            (
                "CAA",
                format!("{} {} \"{}\"", flags, tag, value.replace('"', "\\\"")),
                None,
            )
        }
        DnsRecord::TLSA(tlsa) => (
            "TLSA",
            format!(
                "{} {} {} {}",
                u8::from(tlsa.cert_usage),
                u8::from(tlsa.selector),
                u8::from(tlsa.matching),
                hex::encode(&tlsa.cert_data),
            ),
            None,
        ),
    })
}

fn decode_existing(
    record: &ExistingRecord,
    record_type: DnsRecordType,
) -> crate::Result<DnsRecord> {
    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(
            record
                .target
                .parse()
                .map_err(|e| Error::Parse(format!("invalid A target {}: {e}", record.target)))?,
        ),
        DnsRecordType::AAAA => DnsRecord::AAAA(
            record
                .target
                .parse()
                .map_err(|e| Error::Parse(format!("invalid AAAA target {}: {e}", record.target)))?,
        ),
        DnsRecordType::CNAME => DnsRecord::CNAME(record.target.clone()),
        DnsRecordType::NS => DnsRecord::NS(record.target.clone()),
        DnsRecordType::MX => DnsRecord::MX(MXRecord {
            exchange: record.target.clone(),
            priority: record.priority.unwrap_or(0),
        }),
        DnsRecordType::TXT => DnsRecord::TXT(unquote_txt(&record.target)),
        DnsRecordType::SRV => DnsRecord::SRV(parse_srv(&record.target)?),
        DnsRecordType::CAA => DnsRecord::CAA(parse_caa(&record.target)?),
        DnsRecordType::TLSA => DnsRecord::TLSA(parse_tlsa(&record.target)?),
    })
}

fn parse_srv(target: &str) -> crate::Result<SRVRecord> {
    let mut parts = target.split_whitespace();
    let priority = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("invalid SRV target {target}")))?;
    let weight = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("invalid SRV target {target}")))?;
    let port = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("invalid SRV target {target}")))?;
    let host = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV target {target}")))?;
    Ok(SRVRecord {
        priority,
        weight,
        port,
        target: host.to_string(),
    })
}

fn parse_caa(target: &str) -> crate::Result<CAARecord> {
    let mut parts = target.splitn(3, ' ');
    let flags_str = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA target {target}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA target {target}")))?;
    let value_raw = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA target {target}")))?;
    let flags: u8 = flags_str
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags in {target}: {e}")))?;
    let value = value_raw
        .trim()
        .trim_start_matches('"')
        .trim_end_matches('"')
        .replace("\\\"", "\"");
    let issuer_critical = flags & 0x80 != 0;
    match tag {
        "issue" | "issuewild" => {
            let (name, options) = parse_caa_value(&value);
            if tag == "issue" {
                Ok(CAARecord::Issue {
                    issuer_critical,
                    name,
                    options,
                })
            } else {
                Ok(CAARecord::IssueWild {
                    issuer_critical,
                    name,
                    options,
                })
            }
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

fn parse_tlsa(target: &str) -> crate::Result<TLSARecord> {
    let mut parts = target.split_whitespace();

    let cert_usage = parts
        .next()
        .and_then(|s| s.parse::<u8>().ok())
        .and_then(tlsa_cert_usage_from_u8)
        .ok_or_else(|| Error::Parse(format!("invalid TLSA cert usage in {target}")))?;

    let selector = parts
        .next()
        .and_then(|s| s.parse::<u8>().ok())
        .and_then(tlsa_selector_from_u8)
        .ok_or_else(|| Error::Parse(format!("invalid TLSA selector in {target}")))?;

    let matching = parts
        .next()
        .and_then(|s| s.parse::<u8>().ok())
        .and_then(tlsa_matching_from_u8)
        .ok_or_else(|| Error::Parse(format!("invalid TLSA matching type in {target}")))?;

    let cert_data_hex = parts.collect::<String>();
    if cert_data_hex.is_empty() {
        return Err(Error::Parse(format!(
            "missing TLSA certificate data in {target}"
        )));
    }

    let cert_data = hex::decode(&cert_data_hex)
        .map_err(|e| Error::Parse(format!("invalid TLSA certificate data in {target}: {e}")))?;

    Ok(TLSARecord {
        cert_usage,
        selector,
        matching,
        cert_data,
    })
}

fn tlsa_cert_usage_from_u8(value: u8) -> Option<TlsaCertUsage> {
    Some(match value {
        0 => TlsaCertUsage::PkixTa,
        1 => TlsaCertUsage::PkixEe,
        2 => TlsaCertUsage::DaneTa,
        3 => TlsaCertUsage::DaneEe,
        255 => TlsaCertUsage::Private,
        _ => return None,
    })
}

fn tlsa_selector_from_u8(value: u8) -> Option<TlsaSelector> {
    Some(match value {
        0 => TlsaSelector::Full,
        1 => TlsaSelector::Spki,
        255 => TlsaSelector::Private,
        _ => return None,
    })
}

fn tlsa_matching_from_u8(value: u8) -> Option<TlsaMatching> {
    Some(match value {
        0 => TlsaMatching::Raw,
        1 => TlsaMatching::Sha256,
        2 => TlsaMatching::Sha512,
        255 => TlsaMatching::Private,
        _ => return None,
    })
}
