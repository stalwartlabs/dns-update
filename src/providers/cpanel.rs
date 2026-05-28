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
    http::{HttpClient, HttpClientBuilder},
    utils::txt_chunks_to_text,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const SERIAL_RETRY_BUDGET: u32 = 3;

#[derive(Clone)]
pub struct CpanelProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Deserialize, Debug)]
struct ApiResponse<T> {
    #[serde(default)]
    status: i32,
    #[serde(default)]
    errors: Option<Vec<String>>,
    #[serde(default)]
    messages: Option<Vec<String>>,
    data: Option<T>,
}

#[derive(Deserialize, Debug, Clone)]
struct ZoneRecord {
    #[serde(default, rename = "line_index")]
    line_index: i64,
    #[serde(default, rename = "type")]
    record_class: String,
    #[serde(default, rename = "record_type")]
    record_type: String,
    #[serde(default, rename = "dname_b64")]
    dname_b64: String,
    #[serde(default, rename = "data_b64")]
    data_b64: Vec<String>,
    #[serde(default)]
    ttl: u32,
}

#[derive(Serialize, Debug)]
struct AddRecord<'a> {
    dname: &'a str,
    ttl: u32,
    record_type: &'a str,
    data: Vec<String>,
}

#[derive(Serialize, Debug)]
struct EditRecord<'a> {
    line_index: i64,
    dname: &'a str,
    ttl: u32,
    record_type: &'a str,
    data: Vec<String>,
}

impl CpanelProvider {
    pub(crate) fn new(
        base_url: impl AsRef<str>,
        username: impl AsRef<str>,
        token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let auth = format!("cpanel {}:{}", username.as_ref(), token.as_ref());
        let client = HttpClientBuilder::default()
            .with_header("Authorization", auth)
            .with_timeout(timeout)
            .build();
        Self {
            client,
            endpoint: base_url.as_ref().trim_end_matches('/').to_string(),
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
        reject_tlsa(record_type)?;

        let name = name.into_fqdn().into_owned();
        let domain = origin.into_name().into_owned();
        let desired = encode_desired_records(&records)?;

        self.mutate_with_retry(&domain, |zone_info, serial| {
            let mut params: Vec<(&'static str, String)> =
                vec![("zone", domain.clone()), ("serial", serial.to_string())];

            let matching: Vec<&ZoneRecord> = zone_info
                .iter()
                .filter(|r| {
                    r.record_class == "record"
                        && r.record_type.eq_ignore_ascii_case(record_type.as_str())
                        && decoded_dname_matches(&r.dname_b64, &name)
                })
                .collect();

            let mut existing_pool: Vec<&ZoneRecord> = matching.clone();
            let mut to_add: Vec<&Vec<String>> = Vec::new();
            let mut to_edit: Vec<(i64, &Vec<String>)> = Vec::new();

            for desired_data in &desired {
                if let Some(idx) = existing_pool
                    .iter()
                    .position(|r| decoded_data_matches(&r.data_b64, desired_data))
                {
                    let existing = existing_pool.swap_remove(idx);
                    if existing.ttl != ttl {
                        to_edit.push((existing.line_index, desired_data));
                    }
                } else {
                    to_add.push(desired_data);
                }
            }

            for stale in existing_pool.iter() {
                if let Some((line_index, data)) = to_add.first().map(|d| (stale.line_index, *d)) {
                    to_edit.push((line_index, data));
                    to_add.remove(0);
                } else {
                    params.push(("remove", stale.line_index.to_string()));
                }
            }

            for (line_index, data) in to_edit {
                let edit = EditRecord {
                    line_index,
                    dname: &name,
                    ttl,
                    record_type: record_type.as_str(),
                    data: data.clone(),
                };
                let edit_str = serde_json::to_string(&edit)
                    .map_err(|err| Error::Serialize(err.to_string()))?;
                params.push(("edit", edit_str));
            }

            for data in to_add {
                let add = AddRecord {
                    dname: &name,
                    ttl,
                    record_type: record_type.as_str(),
                    data: data.clone(),
                };
                let add_str =
                    serde_json::to_string(&add).map_err(|err| Error::Serialize(err.to_string()))?;
                params.push(("add", add_str));
            }

            Ok(MutationPlan {
                params,
                action: "apply rrset",
            })
        })
        .await
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
        reject_tlsa(record_type)?;

        let name = name.into_fqdn().into_owned();
        let domain = origin.into_name().into_owned();
        let desired = encode_desired_records(&records)?;

        self.mutate_with_retry(&domain, |zone_info, serial| {
            let mut params: Vec<(&'static str, String)> =
                vec![("zone", domain.clone()), ("serial", serial.to_string())];

            let matching: Vec<&ZoneRecord> = zone_info
                .iter()
                .filter(|r| {
                    r.record_class == "record"
                        && r.record_type.eq_ignore_ascii_case(record_type.as_str())
                        && decoded_dname_matches(&r.dname_b64, &name)
                })
                .collect();

            for desired_data in &desired {
                if matching
                    .iter()
                    .any(|r| decoded_data_matches(&r.data_b64, desired_data))
                {
                    continue;
                }
                let add = AddRecord {
                    dname: &name,
                    ttl,
                    record_type: record_type.as_str(),
                    data: desired_data.clone(),
                };
                let add_str =
                    serde_json::to_string(&add).map_err(|err| Error::Serialize(err.to_string()))?;
                params.push(("add", add_str));
            }

            Ok(MutationPlan {
                params,
                action: "add to rrset",
            })
        })
        .await
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
        reject_tlsa(record_type)?;

        let name = name.into_fqdn().into_owned();
        let domain = origin.into_name().into_owned();
        let to_remove = encode_desired_records(&records)?;

        self.mutate_with_retry(&domain, |zone_info, serial| {
            let mut params: Vec<(&'static str, String)> =
                vec![("zone", domain.clone()), ("serial", serial.to_string())];

            let matching: Vec<&ZoneRecord> = zone_info
                .iter()
                .filter(|r| {
                    r.record_class == "record"
                        && r.record_type.eq_ignore_ascii_case(record_type.as_str())
                        && decoded_dname_matches(&r.dname_b64, &name)
                })
                .collect();

            for data in &to_remove {
                if let Some(target) = matching
                    .iter()
                    .find(|r| decoded_data_matches(&r.data_b64, data))
                {
                    let line_index = target.line_index.to_string();
                    if !params
                        .iter()
                        .any(|(k, v)| *k == "remove" && v == &line_index)
                    {
                        params.push(("remove", line_index));
                    }
                }
            }

            Ok(MutationPlan {
                params,
                action: "remove from rrset",
            })
        })
        .await
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        if matches!(record_type, DnsRecordType::TLSA) {
            return Err(Error::Unsupported(
                "TLSA records are not supported by cPanel".to_string(),
            ));
        }
        let name = name.into_fqdn();
        let domain = origin.into_name();
        let zone_info = self.fetch_zone_information(&domain).await?;

        let mut out = Vec::new();
        for entry in zone_info {
            if entry.record_class != "record"
                || !entry.record_type.eq_ignore_ascii_case(record_type.as_str())
                || !decoded_dname_matches(&entry.dname_b64, name.as_ref())
            {
                continue;
            }
            let fields = decode_data_fields(&entry.data_b64)?;
            out.push(decode_to_dns_record(record_type, &fields)?);
        }
        Ok(out)
    }

    async fn mutate_with_retry<F>(&self, domain: &str, mut build_plan: F) -> crate::Result<()>
    where
        F: FnMut(&[ZoneRecord], u32) -> crate::Result<MutationPlan>,
    {
        let mut attempt: u32 = 0;
        loop {
            let zone_info = self.fetch_zone_information(domain).await?;
            let serial = extract_zone_serial(&zone_info, domain)?;
            let plan = build_plan(&zone_info, serial)?;

            if !params_have_mutations(&plan.params) {
                return Ok(());
            }

            let query = serde_urlencoded::to_string(&plan.params)
                .map_err(|err| Error::Serialize(err.to_string()))?;

            let result = self
                .client
                .get(format!(
                    "{}/execute/DNS/mass_edit_zone?{}",
                    self.endpoint, query
                ))
                .send_with_retry::<ApiResponse<serde_json::Value>>(3)
                .await
                .and_then(|r| r.unwrap_response(plan.action));

            match result {
                Ok(_) => return Ok(()),
                Err(err) => {
                    if is_serial_mismatch(&err) && attempt < SERIAL_RETRY_BUDGET {
                        attempt += 1;
                        continue;
                    }
                    return Err(err);
                }
            }
        }
    }

    async fn fetch_zone_information(&self, domain: &str) -> crate::Result<Vec<ZoneRecord>> {
        let query = serde_urlencoded::to_string([("zone", domain)])
            .map_err(|err| Error::Serialize(err.to_string()))?;
        self.client
            .get(format!(
                "{}/execute/DNS/parse_zone?{}",
                self.endpoint, query
            ))
            .send_with_retry::<ApiResponse<Vec<ZoneRecord>>>(3)
            .await
            .and_then(|r| r.unwrap_response("parse zone"))
    }
}

struct MutationPlan {
    params: Vec<(&'static str, String)>,
    action: &'static str,
}

fn params_have_mutations(params: &[(&'static str, String)]) -> bool {
    params
        .iter()
        .any(|(k, _)| *k == "add" || *k == "edit" || *k == "remove")
}

fn is_serial_mismatch(err: &Error) -> bool {
    match err {
        Error::Api(msg) => {
            let lower = msg.to_ascii_lowercase();
            lower.contains("serial")
                && (lower.contains("does not match")
                    || lower.contains("mismatch")
                    || lower.contains("changed"))
        }
        _ => false,
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

fn reject_tlsa(record_type: DnsRecordType) -> crate::Result<()> {
    if matches!(record_type, DnsRecordType::TLSA) {
        Err(Error::Unsupported(
            "TLSA records are not supported by cPanel".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn encode_desired_records(records: &[DnsRecord]) -> crate::Result<Vec<Vec<String>>> {
    records.iter().map(encode_record_data).collect()
}

impl<T> ApiResponse<T> {
    fn unwrap_response(self, action: &str) -> crate::Result<T> {
        if self.status == 0 {
            let errs = self.errors.unwrap_or_default().join(", ");
            let msgs = self.messages.unwrap_or_default().join(", ");
            return Err(Error::Api(format!(
                "cPanel failed to {action}: {errs} {msgs}"
            )));
        }
        self.data
            .ok_or_else(|| Error::Api(format!("cPanel missing data for {action}")))
    }
}

fn encode_record_data(record: &DnsRecord) -> crate::Result<Vec<String>> {
    Ok(match record {
        DnsRecord::A(addr) => vec![addr.to_string()],
        DnsRecord::AAAA(addr) => vec![addr.to_string()],
        DnsRecord::CNAME(value) => vec![ensure_trailing_dot(value)],
        DnsRecord::NS(value) => vec![ensure_trailing_dot(value)],
        DnsRecord::MX(mx) => vec![mx.priority.to_string(), ensure_trailing_dot(&mx.exchange)],
        DnsRecord::TXT(value) => {
            if value.len() <= 255 && !value.contains('"') && !value.contains('\\') {
                vec![value.clone()]
            } else {
                let mut out = String::new();
                txt_chunks_to_text(&mut out, value, " ");
                vec![out]
            }
        }
        DnsRecord::SRV(srv) => vec![
            srv.priority.to_string(),
            srv.weight.to_string(),
            srv.port.to_string(),
            ensure_trailing_dot(&srv.target),
        ],
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            vec![flags.to_string(), tag, value]
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Unsupported(
                "TLSA records are not supported by cPanel".to_string(),
            ));
        }
    })
}

fn ensure_trailing_dot(value: &str) -> String {
    if value.ends_with('.') {
        value.to_string()
    } else {
        format!("{value}.")
    }
}

fn extract_zone_serial(zone: &[ZoneRecord], domain: &str) -> crate::Result<u32> {
    let target = BASE64.encode(domain.trim_end_matches('.').as_bytes());
    let target_with_dot = BASE64.encode(format!("{}.", domain.trim_end_matches('.')).as_bytes());

    for record in zone {
        if record.record_class != "record" || record.record_type != "SOA" {
            continue;
        }
        if record.dname_b64 != target && record.dname_b64 != target_with_dot {
            continue;
        }
        if record.data_b64.len() < 3 {
            continue;
        }
        let decoded = BASE64
            .decode(&record.data_b64[2])
            .map_err(|err| Error::Parse(format!("Failed to decode SOA serial: {err}")))?;
        let serial_str = String::from_utf8(decoded)
            .map_err(|err| Error::Parse(format!("Failed to parse SOA serial: {err}")))?;
        return serial_str
            .trim()
            .parse::<u32>()
            .map_err(|err| Error::Parse(format!("Failed to parse SOA serial value: {err}")));
    }

    Err(Error::Api(format!(
        "cPanel zone serial not found for {domain}"
    )))
}

fn decoded_dname_matches(dname_b64: &str, name: &str) -> bool {
    BASE64
        .decode(dname_b64)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|s| {
            s.trim_end_matches('.')
                .eq_ignore_ascii_case(name.trim_end_matches('.'))
        })
        .unwrap_or(false)
}

fn decode_data_fields(data_b64: &[String]) -> crate::Result<Vec<String>> {
    data_b64
        .iter()
        .map(|encoded| {
            let bytes = BASE64
                .decode(encoded)
                .map_err(|err| Error::Parse(format!("Failed to decode data field: {err}")))?;
            String::from_utf8(bytes)
                .map_err(|err| Error::Parse(format!("Failed to parse data field: {err}")))
        })
        .collect()
}

fn decoded_data_matches(stored_b64: &[String], desired: &[String]) -> bool {
    let Ok(stored) = decode_data_fields(stored_b64) else {
        return false;
    };
    if stored.len() != desired.len() {
        return false;
    }
    stored
        .iter()
        .zip(desired.iter())
        .all(|(a, b)| a == b || unquote_txt(a) == *b)
}

fn decode_to_dns_record(record_type: DnsRecordType, fields: &[String]) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => {
            let raw = fields
                .first()
                .ok_or_else(|| Error::Parse("missing A rdata".to_string()))?;
            raw.parse()
                .map(DnsRecord::A)
                .map_err(|err| Error::Parse(format!("invalid A address: {err}")))
        }
        DnsRecordType::AAAA => {
            let raw = fields
                .first()
                .ok_or_else(|| Error::Parse("missing AAAA rdata".to_string()))?;
            raw.parse()
                .map(DnsRecord::AAAA)
                .map_err(|err| Error::Parse(format!("invalid AAAA address: {err}")))
        }
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(strip_trailing_dot(
            fields
                .first()
                .ok_or_else(|| Error::Parse("missing CNAME rdata".to_string()))?,
        ))),
        DnsRecordType::NS => Ok(DnsRecord::NS(strip_trailing_dot(
            fields
                .first()
                .ok_or_else(|| Error::Parse("missing NS rdata".to_string()))?,
        ))),
        DnsRecordType::MX => {
            if fields.len() < 2 {
                return Err(Error::Parse("MX record requires 2 fields".to_string()));
            }
            let priority: u16 = fields[0]
                .parse()
                .map_err(|err| Error::Parse(format!("invalid MX priority: {err}")))?;
            Ok(DnsRecord::MX(MXRecord {
                priority,
                exchange: strip_trailing_dot(&fields[1]),
            }))
        }
        DnsRecordType::TXT => {
            let raw = fields
                .first()
                .ok_or_else(|| Error::Parse("missing TXT rdata".to_string()))?;
            Ok(DnsRecord::TXT(unquote_txt(raw)))
        }
        DnsRecordType::SRV => {
            if fields.len() < 4 {
                return Err(Error::Parse("SRV record requires 4 fields".to_string()));
            }
            let priority: u16 = fields[0]
                .parse()
                .map_err(|err| Error::Parse(format!("invalid SRV priority: {err}")))?;
            let weight: u16 = fields[1]
                .parse()
                .map_err(|err| Error::Parse(format!("invalid SRV weight: {err}")))?;
            let port: u16 = fields[2]
                .parse()
                .map_err(|err| Error::Parse(format!("invalid SRV port: {err}")))?;
            Ok(DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target: strip_trailing_dot(&fields[3]),
            }))
        }
        DnsRecordType::CAA => {
            if fields.len() < 3 {
                return Err(Error::Parse("CAA record requires 3 fields".to_string()));
            }
            let flags: u8 = fields[0]
                .parse()
                .map_err(|err| Error::Parse(format!("invalid CAA flags: {err}")))?;
            Ok(DnsRecord::CAA(build_caa(flags, &fields[1], &fields[2])?))
        }
        DnsRecordType::TLSA => Err(Error::Unsupported(
            "TLSA records are not supported by cPanel".to_string(),
        )),
    }
}

fn strip_trailing_dot(value: &str) -> String {
    value.strip_suffix('.').unwrap_or(value).to_string()
}

fn unquote_txt(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
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
            ' ' if !in_quotes => {}
            _ => out.push(ch),
        }
    }
    out
}

fn build_caa(flags: u8, tag: &str, value: &str) -> crate::Result<CAARecord> {
    let issuer_critical = flags & 0x80 != 0;
    match tag {
        "issue" => {
            let (name, options) = parse_caa_value(value);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(value);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: value.to_string(),
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
