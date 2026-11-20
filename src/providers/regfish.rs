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

use crate::utils::{
    decode_hex, parse_mx, parse_srv, parse_tlsa, split_caa_value, strip_trailing_dot,
    tlsa_cert_usage_from_u8, tlsa_cert_usage_to_u8, tlsa_matching_from_u8, tlsa_matching_to_u8,
    tlsa_selector_from_u8, tlsa_selector_to_u8, unquote_txt,
};
use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord, TLSARecord,
    http::{HttpClient, HttpClientBuilder},
};
use serde::{Deserialize, Serialize, de::IgnoredAny};
use std::{net::AddrParseError, time::Duration};

#[derive(Clone)]
pub struct RegfishProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct RecordBody {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    data: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flags: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selector: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matching_type: Option<u8>,
}

#[derive(Deserialize, Debug)]
struct ApiEnvelope<T> {
    success: bool,
    #[serde(default)]
    response: Option<T>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
struct RegfishRecord {
    id: u64,
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    data: String,
    #[serde(default)]
    ttl: Option<u32>,
    #[serde(default)]
    priority: Option<u16>,
    #[serde(default)]
    weight: Option<u16>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    flags: Option<u8>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    usage: Option<u8>,
    #[serde(default)]
    selector: Option<u8>,
    #[serde(default)]
    matching_type: Option<u8>,
}

const DEFAULT_API_ENDPOINT: &str = "https://api.regfish.de";
const RETRIES: u32 = 3;

impl RegfishProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        if api_key.is_empty() {
            return Err(Error::Api("Regfish API key must not be empty".to_string()));
        }

        Ok(Self {
            client: HttpClientBuilder::default()
                .with_header("x-api-key", api_key)
                .with_timeout(timeout)
                .build(),
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
        })
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
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        reject_unsupported(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();

        let mut pool = self.rrset_records(&name, record_type, &domain).await?;

        let mut to_create: Vec<DnsRecord> = Vec::new();
        for record in records {
            match pool.iter().position(|r| records_match(r, &record)) {
                Some(idx) => {
                    let existing = pool.swap_remove(idx);
                    if existing.ttl.is_some() && existing.ttl != Some(ttl) {
                        self.update_record(existing.id, &name, record_type, ttl, &record)
                            .await?;
                    }
                }
                None => to_create.push(record),
            }
        }

        for stale in pool {
            self.delete_record(stale.id).await?;
        }
        for record in to_create {
            self.create_record(&name, record_type, ttl, &record).await?;
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
        reject_unsupported(record_type)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name();
        let domain = origin.into_name();

        let pool = self.rrset_records(&name, record_type, &domain).await?;

        for record in records {
            if pool.iter().any(|r| records_match(r, &record)) {
                continue;
            }
            self.create_record(&name, record_type, ttl, &record).await?;
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
        reject_unsupported(record_type)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_name();
        let domain = origin.into_name();

        let pool = self.rrset_records(&name, record_type, &domain).await?;

        for record in records {
            if let Some(existing) = pool.iter().find(|r| records_match(r, &record)) {
                self.delete_record(existing.id).await?;
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
        let zone = self.resolve_zone(domain.as_ref()).await?;

        let records = match self.list_zone_records(&zone).await {
            Ok(records) => records,
            Err(Error::NotFound) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };

        let mut out = Vec::new();
        for r in records {
            if normalize_record_name(&r.name, &zone) == name.as_ref()
                && r.record_type.eq_ignore_ascii_case(record_type.as_str())
            {
                out.push(record_to_dns(r)?);
            }
        }
        Ok(out)
    }

    async fn rrset_records(
        &self,
        name: &str,
        record_type: DnsRecordType,
        domain: &str,
    ) -> crate::Result<Vec<RegfishRecord>> {
        let zone = self.resolve_zone(domain).await?;
        Ok(self
            .list_zone_records(&zone)
            .await?
            .into_iter()
            .filter(|r| {
                normalize_record_name(&r.name, &zone) == name
                    && r.record_type.eq_ignore_ascii_case(record_type.as_str())
            })
            .collect())
    }

    async fn resolve_zone(&self, domain: &str) -> crate::Result<String> {
        let mut candidate = domain.to_string();
        loop {
            let url = format!("{}/dns/zones/{candidate}", self.endpoint);
            match self
                .client
                .get(url)
                .send_with_retry::<IgnoredAny>(RETRIES)
                .await
            {
                Ok(_) => return Ok(candidate),
                Err(Error::NotFound) => match candidate.split_once('.') {
                    Some((_, parent)) => candidate = parent.to_string(),
                    None => {
                        return Err(Error::NotFound);
                    }
                },
                Err(e) => return Err(e),
            }
        }
    }

    async fn list_zone_records(&self, domain: &str) -> crate::Result<Vec<RegfishRecord>> {
        let url = format!("{}/dns/{domain}/rr", self.endpoint);
        let envelope: ApiEnvelope<Vec<RegfishRecord>> =
            self.client.get(url).send_with_retry(RETRIES).await?;
        if !envelope.success {
            return Err(Error::Api(envelope.message.unwrap_or_else(|| {
                format!("Regfish API request for zone {domain} failed")
            })));
        }
        Ok(envelope.response.unwrap_or_default())
    }

    async fn create_record(
        &self,
        name: &str,
        record_type: DnsRecordType,
        ttl: u32,
        record: &DnsRecord,
    ) -> crate::Result<()> {
        let body = build_record_body(name, record_type, ttl, record)?;
        self.send_write(
            self.client
                .post(format!("{}/dns/rr", self.endpoint))
                .with_body(body)?,
        )
        .await
    }

    async fn update_record(
        &self,
        id: u64,
        name: &str,
        record_type: DnsRecordType,
        ttl: u32,
        record: &DnsRecord,
    ) -> crate::Result<()> {
        let body = build_record_body(name, record_type, ttl, record)?;
        self.send_write(
            self.client
                .patch(format!("{}/dns/rr/{id}", self.endpoint))
                .with_body(body)?,
        )
        .await
    }

    async fn delete_record(&self, id: u64) -> crate::Result<()> {
        match self
            .send_write(self.client.delete(format!("{}/dns/rr/{id}", self.endpoint)))
            .await
        {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn send_write(&self, request: crate::http::HttpRequest) -> crate::Result<()> {
        let envelope: ApiEnvelope<serde_json::Value> = request.send_with_retry(RETRIES).await?;
        if !envelope.success {
            return Err(Error::Api(
                envelope
                    .message
                    .unwrap_or_else(|| "Regfish API write request failed".to_string()),
            ));
        }
        Ok(())
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

fn reject_unsupported(record_type: DnsRecordType) -> crate::Result<()> {
    if matches!(record_type, DnsRecordType::NS) {
        return Err(Error::Unsupported(format!(
            "{} records are not supported by Regfish",
            record_type.as_str()
        )));
    }
    Ok(())
}

fn normalize_record_name(name: &str, domain: &str) -> String {
    let trimmed = strip_trailing_dot(name);
    if trimmed == "@" || trimmed.is_empty() {
        strip_trailing_dot(domain).to_string()
    } else {
        trimmed.to_string()
    }
}

fn records_match(existing: &RegfishRecord, desired: &DnsRecord) -> bool {
    record_to_dns(existing.clone())
        .map(|parsed| parsed == *desired)
        .unwrap_or(false)
}

fn build_record_body(
    name: &str,
    record_type: DnsRecordType,
    ttl: u32,
    record: &DnsRecord,
) -> crate::Result<RecordBody> {
    let fqdn = format!("{name}.");
    let mut body = RecordBody {
        record_type: record_type.as_str().to_string(),
        name: fqdn,
        data: String::new(),
        ttl,
        priority: None,
        weight: None,
        port: None,
        flags: None,
        tag: None,
        usage: None,
        selector: None,
        matching_type: None,
    };
    match record {
        DnsRecord::A(addr) => body.data = addr.to_string(),
        DnsRecord::AAAA(addr) => body.data = addr.to_string(),
        DnsRecord::CNAME(target) => body.data = target.as_str().into_fqdn().into_owned(),
        DnsRecord::MX(mx) => {
            body.data = mx.exchange.as_str().into_fqdn().into_owned();
            body.priority = Some(mx.priority);
        }
        DnsRecord::TXT(content) => body.data = content.clone(),
        DnsRecord::CAA(caa) => {
            let (caa_flags, caa_tag, value) = caa.clone().decompose();
            body.data = value;
            body.flags = Some(if caa_flags & 0x80 != 0 { 1 } else { 0 });
            body.tag = Some(caa_tag);
        }
        DnsRecord::NS(_) => {
            return Err(Error::Unsupported(format!(
                "{} records are not supported by Regfish",
                record_type.as_str()
            )));
        }
        DnsRecord::SRV(srv) => {
            body.data = srv.target.as_str().into_fqdn().into_owned();
            body.priority = Some(srv.priority);
            body.weight = Some(srv.weight);
            body.port = Some(srv.port);
        }
        DnsRecord::TLSA(tlsa) => {
            body.data = hex::encode(&tlsa.cert_data);
            body.usage = Some(tlsa_cert_usage_to_u8(tlsa.cert_usage));
            body.selector = Some(tlsa_selector_to_u8(tlsa.selector));
            body.matching_type = Some(tlsa_matching_to_u8(tlsa.matching));
        }
    }

    Ok(body)
}

fn record_to_dns(record: RegfishRecord) -> crate::Result<DnsRecord> {
    let data = record.data.trim();
    let record_type = record
        .record_type
        .eq_ignore_ascii_case("A")
        .then_some(DnsRecordType::A)
        .or_else(|| {
            record
                .record_type
                .eq_ignore_ascii_case("AAAA")
                .then_some(DnsRecordType::AAAA)
        })
        .or_else(|| {
            record
                .record_type
                .eq_ignore_ascii_case("CNAME")
                .then_some(DnsRecordType::CNAME)
        })
        .or_else(|| {
            record
                .record_type
                .eq_ignore_ascii_case("NS")
                .then_some(DnsRecordType::NS)
        })
        .or_else(|| {
            record
                .record_type
                .eq_ignore_ascii_case("MX")
                .then_some(DnsRecordType::MX)
        })
        .or_else(|| {
            record
                .record_type
                .eq_ignore_ascii_case("TXT")
                .then_some(DnsRecordType::TXT)
        })
        .or_else(|| {
            record
                .record_type
                .eq_ignore_ascii_case("SRV")
                .then_some(DnsRecordType::SRV)
        })
        .or_else(|| {
            record
                .record_type
                .eq_ignore_ascii_case("TLSA")
                .then_some(DnsRecordType::TLSA)
        })
        .or_else(|| {
            record
                .record_type
                .eq_ignore_ascii_case("CAA")
                .then_some(DnsRecordType::CAA)
        });

    let Some(record_type) = record_type else {
        return Err(Error::Unsupported(format!(
            "unsupported Regfish record type: {}",
            record.record_type
        )));
    };

    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(data.parse().map_err(|e: AddrParseError| {
            Error::Parse(format!("invalid A value '{}': {e}", record.data))
        })?),
        DnsRecordType::AAAA => DnsRecord::AAAA(data.parse().map_err(|e: AddrParseError| {
            Error::Parse(format!("invalid AAAA value '{}': {e}", record.data))
        })?),
        DnsRecordType::CNAME => DnsRecord::CNAME(strip_trailing_dot(data).to_string()),
        DnsRecordType::NS => DnsRecord::NS(strip_trailing_dot(data).to_string()),
        DnsRecordType::MX => {
            let (priority, exchange) = match record.priority {
                Some(priority) => (priority, strip_trailing_dot(data).to_string()),
                None => match parse_mx(&record.data) {
                    Ok(DnsRecord::MX(mx)) => (mx.priority, mx.exchange),
                    _ => return Err(Error::Parse(format!("invalid MX value '{}'", record.data))),
                },
            };
            DnsRecord::MX(MXRecord { exchange, priority })
        }
        DnsRecordType::TXT => DnsRecord::TXT(unquote_txt(data)),
        DnsRecordType::SRV => {
            let (priority, weight, port, target) =
                match (record.priority, record.weight, record.port) {
                    (Some(priority), Some(weight), Some(port)) => {
                        (priority, weight, port, strip_trailing_dot(data).to_string())
                    }
                    _ => match parse_srv(&record.data) {
                        Ok(DnsRecord::SRV(srv)) => (srv.priority, srv.weight, srv.port, srv.target),
                        _ => {
                            return Err(Error::Parse(format!(
                                "invalid SRV value '{}'",
                                record.data
                            )));
                        }
                    },
                };
            DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target,
            })
        }
        DnsRecordType::TLSA => {
            let (usage, selector, matching, hex) =
                match (record.usage, record.selector, record.matching_type) {
                    (Some(usage), Some(selector), Some(matching)) => {
                        (usage, selector, matching, data)
                    }
                    _ => match parse_tlsa(&record.data) {
                        Ok(DnsRecord::TLSA(tlsa)) => {
                            return Ok(DnsRecord::TLSA(tlsa));
                        }
                        _ => {
                            return Err(Error::Parse(format!(
                                "invalid TLSA value '{}'",
                                record.data
                            )));
                        }
                    },
                };
            DnsRecord::TLSA(TLSARecord {
                cert_usage: tlsa_cert_usage_from_u8(usage)?,
                selector: tlsa_selector_from_u8(selector)?,
                matching: tlsa_matching_from_u8(matching)?,
                cert_data: decode_hex(hex)?,
            })
        }
        DnsRecordType::CAA => {
            let flags = record.flags.unwrap_or(0);
            let issuer_critical = flags & 0x80 != 0 || flags == 1;
            let tag = record
                .tag
                .clone()
                .unwrap_or_else(|| "issue".to_string())
                .to_ascii_lowercase();
            let value = data.to_string();
            match tag.as_str() {
                "issue" => {
                    let (name, options) = split_caa_value(&value);
                    DnsRecord::CAA(CAARecord::Issue {
                        issuer_critical,
                        name,
                        options,
                    })
                }
                "issuewild" => {
                    let (name, options) = split_caa_value(&value);
                    DnsRecord::CAA(CAARecord::IssueWild {
                        issuer_critical,
                        name,
                        options,
                    })
                }
                "iodef" => DnsRecord::CAA(CAARecord::Iodef {
                    issuer_critical,
                    url: value,
                }),
                other => {
                    return Err(Error::Parse(format!("unknown CAA tag: {other}")));
                }
            }
        }
    })
}
