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
    http::HttpClientBuilder,
    utils::{strip_origin_from_name, txt_chunks_to_text},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api.infomaniak.com";

#[derive(Clone)]
pub struct InfomaniakProvider {
    client: HttpClientBuilder,
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

#[derive(Deserialize, Debug)]
struct Domain {
    id: u64,
    #[serde(default, rename = "customer_name")]
    customer_name: String,
}

#[derive(Deserialize, Debug, Clone)]
struct ExistingRecord {
    id: String,
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
    priority: Option<u16>,
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
            .with_timeout(timeout);
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
        let domain = origin.into_name().into_owned();
        let ik_domain = self.find_domain(&domain).await?;
        let source = source_from_name(&name, &ik_domain.customer_name);

        let desired = build_wire_records(record_type, records)?;
        let mut existing_pool = self
            .list_filtered(ik_domain.id, &source, record_type)
            .await?;

        let mut to_add = Vec::new();
        for wire in desired {
            if let Some(idx) = existing_pool.iter().position(|r| matches_wire(r, &wire)) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(wire);
            }
        }

        for entry in existing_pool {
            self.delete_record(ik_domain.id, &entry.id).await?;
        }
        let dkim_type = is_dkim_owner(record_type.as_str(), &source).then_some("rsa");
        for wire in to_add {
            self.post_record(
                ik_domain.id,
                &source,
                &wire.target,
                record_type.as_str(),
                ttl,
                wire.priority,
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
        let domain = origin.into_name().into_owned();
        let ik_domain = self.find_domain(&domain).await?;
        let source = source_from_name(&name, &ik_domain.customer_name);

        let desired = build_wire_records(record_type, records)?;
        let existing = self
            .list_filtered(ik_domain.id, &source, record_type)
            .await?;
        let dkim_type = is_dkim_owner(record_type.as_str(), &source).then_some("rsa");

        for wire in desired {
            if existing.iter().any(|r| matches_wire(r, &wire)) {
                continue;
            }
            self.post_record(
                ik_domain.id,
                &source,
                &wire.target,
                record_type.as_str(),
                ttl,
                wire.priority,
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
        let domain = origin.into_name().into_owned();
        let ik_domain = self.find_domain(&domain).await?;
        let source = source_from_name(&name, &ik_domain.customer_name);

        let to_remove = build_wire_records(record_type, records)?;
        let existing = self
            .list_filtered(ik_domain.id, &source, record_type)
            .await?;

        for wire in to_remove {
            if let Some(entry) = existing.iter().find(|r| matches_wire(r, &wire)) {
                self.delete_record(ik_domain.id, &entry.id).await?;
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
        if matches!(record_type, DnsRecordType::TLSA) {
            return Err(Error::Api(
                "TLSA records are not supported by Infomaniak".to_string(),
            ));
        }
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let ik_domain = self.find_domain(&domain).await?;
        let source = source_from_name(&name, &ik_domain.customer_name);
        let existing = self
            .list_filtered(ik_domain.id, &source, record_type)
            .await?;
        existing
            .into_iter()
            .map(|r| decode_existing(&r, record_type))
            .collect()
    }

    async fn replace_existing_spf(
        &self,
        domain_id: u64,
        source: &str,
        target: &str,
        ttl: u32,
    ) -> crate::Result<()> {
        let url = format!("{}/1/domain/{}/dns/record", self.endpoint, domain_id);
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

        self.put_record(
            domain_id,
            &existing_id,
            source,
            target,
            "TXT",
            ttl,
            None,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn post_record(
        &self,
        domain_id: u64,
        source: &str,
        target: &str,
        record_type: &str,
        ttl: u32,
        priority: Option<u16>,
        mut dkim_type: Option<&'static str>,
    ) -> crate::Result<()> {
        let url = format!("{}/1/domain/{}/dns/record", self.endpoint, domain_id);
        loop {
            let payload = RecordPayload {
                source,
                target,
                record_type,
                ttl,
                priority,
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
                        return self
                            .replace_existing_spf(domain_id, source, target, ttl)
                            .await;
                    }
                    Recovery::Propagate => return Err(err),
                },
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn put_record(
        &self,
        domain_id: u64,
        record_id: &str,
        source: &str,
        target: &str,
        record_type: &str,
        ttl: u32,
        priority: Option<u16>,
        dkim_type: Option<&'static str>,
    ) -> crate::Result<()> {
        let payload = RecordPayload {
            source,
            target,
            record_type,
            ttl,
            priority,
            dkim_type,
        };
        let url = format!(
            "{}/1/domain/{}/dns/record/{}",
            self.endpoint, domain_id, record_id
        );
        self.send_expect_success::<serde_json::Value>(self.client.put(url).with_body(payload)?)
            .await
            .map(|_| ())
    }

    async fn delete_record(&self, domain_id: u64, record_id: &str) -> crate::Result<()> {
        let url = format!(
            "{}/1/domain/{}/dns/record/{}",
            self.endpoint, domain_id, record_id
        );
        self.send_expect_success::<serde_json::Value>(self.client.delete(url))
            .await
            .map(|_| ())
    }

    async fn find_domain(&self, name: &str) -> crate::Result<Domain> {
        let mut candidate = name.trim_end_matches('.');
        loop {
            let url = format!(
                "{}/1/product?service_name=domain&customer_name={}",
                self.endpoint, candidate
            );
            let domains = self
                .send_expect_success::<Vec<Domain>>(self.client.get(url))
                .await?;
            if let Some(domain) = domains.into_iter().find(|d| d.customer_name == candidate) {
                return Ok(domain);
            }
            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => {
                    return Err(Error::Api(format!(
                        "No Infomaniak domain found for {}",
                        name
                    )));
                }
            }
        }
    }

    async fn list_filtered(
        &self,
        domain_id: u64,
        source: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ExistingRecord>> {
        let url = format!("{}/1/domain/{}/dns/record", self.endpoint, domain_id);
        let records = self
            .send_expect_success::<Vec<ExistingRecord>>(self.client.get(url))
            .await?;
        let type_str = record_type.as_str();
        Ok(records
            .into_iter()
            .filter(|r| {
                (r.source == source || r.source_idn.as_deref() == Some(source))
                    && r.record_type.eq_ignore_ascii_case(type_str)
            })
            .collect())
    }

    async fn send_expect_success<T>(&self, request: crate::http::HttpClient) -> crate::Result<T>
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
    let mut out = String::with_capacity(target.len());
    let mut chars = target.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => continue,
            '\\' => {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            _ => out.push(ch),
        }
    }
    out
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
    if matches!(expected, DnsRecordType::TLSA) {
        return Err(Error::Api(
            "TLSA records are not supported by Infomaniak".to_string(),
        ));
    }
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

fn build_wire_records(
    expected: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<WireRecord>> {
    records
        .into_iter()
        .map(|r| {
            let (_, target, priority) = encode_record(&r)?;
            let target = if matches!(expected, DnsRecordType::TXT) {
                normalize_txt_wire(&target)
            } else {
                target
            };
            Ok(WireRecord { target, priority })
        })
        .collect()
}

fn matches_wire(existing: &ExistingRecord, wire: &WireRecord) -> bool {
    let target_match =
        existing.target == wire.target || normalize_txt_wire(&existing.target) == wire.target;
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
        DnsRecord::CNAME(value) => ("CNAME", value.clone(), None),
        DnsRecord::NS(value) => ("NS", value.clone(), None),
        DnsRecord::MX(mx) => ("MX", ensure_trailing_dot(&mx.exchange), Some(mx.priority)),
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
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Infomaniak".to_string(),
            ));
        }
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
        DnsRecordType::TLSA => {
            return Err(Error::Api(
                "TLSA records are not supported by Infomaniak".to_string(),
            ));
        }
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
