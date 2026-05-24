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
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

#[derive(Clone)]
pub struct PorkBunProvider {
    client: HttpClientBuilder,
    api_key: String,
    secret_api_key: String,
    endpoint: String,
}

#[derive(Serialize, Debug)]
pub struct AuthParams<'a> {
    pub secretapikey: &'a str,
    pub apikey: &'a str,
}

#[derive(Serialize, Debug)]
pub struct DnsRecordParams<'a> {
    #[serde(flatten)]
    pub auth: AuthParams<'a>,
    pub name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<&'a str>,
    #[serde(flatten)]
    content: RecordData,
}

#[derive(Serialize, Debug)]
pub struct EditByNameTypeParams<'a> {
    #[serde(flatten)]
    pub auth: AuthParams<'a>,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prio: Option<u16>,
}

#[derive(Deserialize, Debug)]
pub struct ApiResponse {
    pub status: String,
    pub message: Option<String>,
}

#[derive(Deserialize, Debug)]
struct RetrieveResponse {
    status: String,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    records: Vec<ListedRecord>,
}

#[derive(Deserialize, Debug, Clone)]
struct ListedRecord {
    id: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
    #[serde(default, deserialize_with = "deserialize_opt_u16_from_string")]
    prio: Option<u16>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type")]
#[allow(clippy::upper_case_acronyms)]
pub enum RecordData {
    A { content: Ipv4Addr },
    MX { content: String, prio: u16 },
    CNAME { content: String },
    ALIAS { content: String },
    TXT { content: String },
    NS { content: String },
    AAAA { content: Ipv6Addr },
    SRV { content: String, prio: u16 },
    TLSA { content: String },
    CAA { content: String },
    HTTPS { content: String },
    SVCB { content: String },
    SSHFP { content: String },
}

const DEFAULT_API_ENDPOINT: &str = "https://api.porkbun.com/api/json/v3";

impl PorkBunProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        secret_api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default().with_timeout(timeout);

        Self {
            client,
            api_key: api_key.as_ref().to_string(),
            secret_api_key: secret_api_key.as_ref().to_string(),
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
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
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));

        if records.is_empty() {
            return self
                .delete_by_name_type(&domain, record_type.as_str(), &subdomain)
                .await;
        }

        let desired = build_record_data(record_type, records)?;

        if desired.len() == 1 {
            let data = desired.into_iter().next().unwrap();
            return self.edit_by_name_type(&domain, &subdomain, ttl, data).await;
        }

        let existing = self
            .retrieve_by_name_type(&domain, record_type.as_str(), &subdomain)
            .await?;

        let mut existing_pool = existing;
        let mut to_add: Vec<RecordData> = Vec::new();

        for data in desired {
            if let Some(idx) = existing_pool.iter().position(|r| listed_matches(r, &data)) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(data);
            }
        }

        for entry in existing_pool {
            self.delete_record(&domain, &entry.id).await?;
        }
        for data in to_add {
            self.create_record(&domain, &subdomain, ttl, data).await?;
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
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let desired = build_record_data(record_type, records)?;
        let existing = self
            .retrieve_by_name_type(&domain, record_type.as_str(), &subdomain)
            .await?;

        for data in desired {
            if existing.iter().any(|r| listed_matches(r, &data)) {
                continue;
            }
            self.create_record(&domain, &subdomain, ttl, data).await?;
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
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let to_remove = build_record_data(record_type, records)?;
        let existing = self
            .retrieve_by_name_type(&domain, record_type.as_str(), &subdomain)
            .await?;

        for data in to_remove {
            if let Some(entry) = existing.iter().find(|r| listed_matches(r, &data)) {
                self.delete_record(&domain, &entry.id).await?;
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
        let domain = origin.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let listed = self
            .retrieve_by_name_type(&domain, record_type.as_str(), &subdomain)
            .await?;
        listed
            .into_iter()
            .map(|r| listed_to_dns_record(r, record_type))
            .collect()
    }

    fn auth(&self) -> AuthParams<'_> {
        AuthParams {
            secretapikey: &self.secret_api_key,
            apikey: &self.api_key,
        }
    }

    async fn retrieve_by_name_type(
        &self,
        domain: &str,
        record_type: &str,
        subdomain: &str,
    ) -> crate::Result<Vec<ListedRecord>> {
        let url = retrieve_by_name_type_url(&self.endpoint, domain, record_type, subdomain);
        let response: RetrieveResponse = self
            .client
            .post(url)
            .with_body(self.auth())?
            .send_with_retry(3)
            .await?;
        if response.status == "SUCCESS" {
            Ok(response
                .records
                .into_iter()
                .filter(|r| r.record_type.eq_ignore_ascii_case(record_type))
                .collect())
        } else {
            Err(Error::Api(response.status_message()))
        }
    }

    async fn create_record(
        &self,
        domain: &str,
        subdomain: &str,
        ttl: u32,
        content: RecordData,
    ) -> crate::Result<()> {
        self.client
            .post(format!(
                "{endpoint}/dns/create/{domain}",
                endpoint = self.endpoint,
            ))
            .with_body(DnsRecordParams {
                auth: self.auth(),
                name: subdomain,
                ttl: Some(ttl),
                notes: None,
                content,
            })?
            .send_with_retry::<ApiResponse>(3)
            .await?
            .into_result()
    }

    async fn delete_record(&self, domain: &str, record_id: &str) -> crate::Result<()> {
        self.client
            .post(format!(
                "{endpoint}/dns/delete/{domain}/{record_id}",
                endpoint = self.endpoint,
            ))
            .with_body(self.auth())?
            .send_with_retry::<ApiResponse>(3)
            .await?
            .into_result()
    }

    async fn delete_by_name_type(
        &self,
        domain: &str,
        record_type: &str,
        subdomain: &str,
    ) -> crate::Result<()> {
        self.client
            .post(delete_by_name_type_url(
                &self.endpoint,
                domain,
                record_type,
                subdomain,
            ))
            .with_body(self.auth())?
            .send_with_retry::<ApiResponse>(3)
            .await?
            .into_result()
    }

    async fn edit_by_name_type(
        &self,
        domain: &str,
        subdomain: &str,
        ttl: u32,
        data: RecordData,
    ) -> crate::Result<()> {
        let variant = data.variant_name();
        let (content, prio) = data.into_content_prio();
        self.client
            .post(edit_by_name_type_url(
                &self.endpoint,
                domain,
                variant,
                subdomain,
            ))
            .with_body(EditByNameTypeParams {
                auth: self.auth(),
                content,
                ttl: Some(ttl),
                prio,
            })?
            .send_with_retry::<ApiResponse>(3)
            .await?
            .into_result()
    }
}

fn retrieve_by_name_type_url(
    endpoint: &str,
    domain: &str,
    record_type: &str,
    subdomain: &str,
) -> String {
    if subdomain.is_empty() {
        format!("{endpoint}/dns/retrieveByNameType/{domain}/{record_type}")
    } else {
        format!("{endpoint}/dns/retrieveByNameType/{domain}/{record_type}/{subdomain}")
    }
}

fn edit_by_name_type_url(
    endpoint: &str,
    domain: &str,
    record_type: &str,
    subdomain: &str,
) -> String {
    if subdomain.is_empty() {
        format!("{endpoint}/dns/editByNameType/{domain}/{record_type}")
    } else {
        format!("{endpoint}/dns/editByNameType/{domain}/{record_type}/{subdomain}")
    }
}

fn delete_by_name_type_url(
    endpoint: &str,
    domain: &str,
    record_type: &str,
    subdomain: &str,
) -> String {
    if subdomain.is_empty() {
        format!("{endpoint}/dns/deleteByNameType/{domain}/{record_type}")
    } else {
        format!("{endpoint}/dns/deleteByNameType/{domain}/{record_type}/{subdomain}")
    }
}

fn build_record_data(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<RecordData>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(record.into());
    }
    Ok(out)
}

fn listed_matches(listed: &ListedRecord, data: &RecordData) -> bool {
    if !listed.record_type.eq_ignore_ascii_case(data.variant_name()) {
        return false;
    }
    let (expected_content, expected_prio) = data.as_content_prio();
    if listed.content.trim_end_matches('.') != expected_content.trim_end_matches('.') {
        return false;
    }
    match expected_prio {
        Some(p) => listed.prio == Some(p),
        None => true,
    }
}

fn listed_to_dns_record(
    listed: ListedRecord,
    record_type: DnsRecordType,
) -> crate::Result<DnsRecord> {
    let content = listed.content;
    let prio = listed.prio;
    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(
            content
                .parse()
                .map_err(|e| Error::Parse(format!("invalid A record content {content}: {e}")))?,
        ),
        DnsRecordType::AAAA => DnsRecord::AAAA(
            content
                .parse()
                .map_err(|e| Error::Parse(format!("invalid AAAA record content {content}: {e}")))?,
        ),
        DnsRecordType::CNAME => DnsRecord::CNAME(content.trim_end_matches('.').to_string()),
        DnsRecordType::NS => DnsRecord::NS(content.trim_end_matches('.').to_string()),
        DnsRecordType::MX => DnsRecord::MX(MXRecord {
            exchange: content.trim_end_matches('.').to_string(),
            priority: prio.unwrap_or(0),
        }),
        DnsRecordType::TXT => DnsRecord::TXT(content),
        DnsRecordType::SRV => DnsRecord::SRV(parse_srv_content(&content, prio.unwrap_or(0))?),
        DnsRecordType::TLSA => DnsRecord::TLSA(parse_tlsa_content(&content)?),
        DnsRecordType::CAA => DnsRecord::CAA(parse_caa_content(&content)?),
    })
}

fn parse_srv_content(content: &str, priority: u16) -> crate::Result<SRVRecord> {
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(Error::Parse(format!(
            "invalid SRV content {content}: expected 'weight port target'"
        )));
    }
    let weight: u16 = parts[0]
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV weight {}: {e}", parts[0])))?;
    let port: u16 = parts[1]
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV port {}: {e}", parts[1])))?;
    Ok(SRVRecord {
        priority,
        weight,
        port,
        target: parts[2].trim_end_matches('.').to_string(),
    })
}

fn parse_tlsa_content(content: &str) -> crate::Result<TLSARecord> {
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() != 4 {
        return Err(Error::Parse(format!(
            "invalid TLSA content {content}: expected 'usage selector matching hex'"
        )));
    }
    let usage: u8 = parts[0]
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA usage: {e}")))?;
    let selector: u8 = parts[1]
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA selector: {e}")))?;
    let matching: u8 = parts[2]
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA matching: {e}")))?;
    Ok(TLSARecord {
        cert_usage: tlsa_cert_usage_from_u8(usage)?,
        selector: tlsa_selector_from_u8(selector)?,
        matching: tlsa_matching_from_u8(matching)?,
        cert_data: decode_hex(parts[3])?,
    })
}

fn parse_caa_content(content: &str) -> crate::Result<CAARecord> {
    let trimmed = content.trim();
    let (flags_str, rest) = trimmed
        .split_once(char::is_whitespace)
        .ok_or_else(|| Error::Parse(format!("invalid CAA content {content}: missing tag")))?;
    let (tag, raw_value) = rest
        .trim_start()
        .split_once(char::is_whitespace)
        .ok_or_else(|| Error::Parse(format!("invalid CAA content {content}: missing value")))?;
    let flags: u8 = flags_str
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags {flags_str}: {e}")))?;
    let value = raw_value.trim().trim_matches('"').to_string();
    build_caa(flags, tag.to_string(), value)
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

fn deserialize_opt_u16_from_string<'de, D>(deserializer: D) -> Result<Option<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        Str(String),
        Num(u16),
        None,
    }
    match Option::<Either>::deserialize(deserializer)? {
        None | Some(Either::None) => Ok(None),
        Some(Either::Num(n)) => Ok(Some(n)),
        Some(Either::Str(s)) => {
            if s.is_empty() {
                Ok(None)
            } else {
                s.parse::<u16>().map(Some).map_err(serde::de::Error::custom)
            }
        }
    }
}

impl ApiResponse {
    fn into_result(self) -> crate::Result<()> {
        if self.status == "SUCCESS" {
            Ok(())
        } else {
            Err(Error::Api(self.message.unwrap_or(self.status)))
        }
    }
}

impl RetrieveResponse {
    fn status_message(self) -> String {
        self.message.unwrap_or(self.status)
    }
}

impl RecordData {
    pub fn variant_name(&self) -> &'static str {
        match self {
            RecordData::A { .. } => "A",
            RecordData::MX { .. } => "MX",
            RecordData::CNAME { .. } => "CNAME",
            RecordData::ALIAS { .. } => "ALIAS",
            RecordData::TXT { .. } => "TXT",
            RecordData::NS { .. } => "NS",
            RecordData::AAAA { .. } => "AAAA",
            RecordData::SRV { .. } => "SRV",
            RecordData::TLSA { .. } => "TLSA",
            RecordData::CAA { .. } => "CAA",
            RecordData::HTTPS { .. } => "HTTPS",
            RecordData::SVCB { .. } => "SVCB",
            RecordData::SSHFP { .. } => "SSHFP",
        }
    }

    fn as_content_prio(&self) -> (String, Option<u16>) {
        match self {
            RecordData::A { content } => (content.to_string(), None),
            RecordData::AAAA { content } => (content.to_string(), None),
            RecordData::CNAME { content }
            | RecordData::ALIAS { content }
            | RecordData::NS { content }
            | RecordData::TXT { content }
            | RecordData::TLSA { content }
            | RecordData::CAA { content }
            | RecordData::HTTPS { content }
            | RecordData::SVCB { content }
            | RecordData::SSHFP { content } => (content.clone(), None),
            RecordData::MX { content, prio } => (content.clone(), Some(*prio)),
            RecordData::SRV { content, prio } => (content.clone(), Some(*prio)),
        }
    }

    fn into_content_prio(self) -> (String, Option<u16>) {
        match self {
            RecordData::A { content } => (content.to_string(), None),
            RecordData::AAAA { content } => (content.to_string(), None),
            RecordData::CNAME { content }
            | RecordData::ALIAS { content }
            | RecordData::NS { content }
            | RecordData::TXT { content }
            | RecordData::TLSA { content }
            | RecordData::CAA { content }
            | RecordData::HTTPS { content }
            | RecordData::SVCB { content }
            | RecordData::SSHFP { content } => (content, None),
            RecordData::MX { content, prio } => (content, Some(prio)),
            RecordData::SRV { content, prio } => (content, Some(prio)),
        }
    }
}

fn strip_trailing_dot(value: String) -> String {
    if value.ends_with('.') {
        value.trim_end_matches('.').to_string()
    } else {
        value
    }
}

impl From<DnsRecord> for RecordData {
    fn from(record: DnsRecord) -> Self {
        match record {
            DnsRecord::A(content) => RecordData::A { content },
            DnsRecord::AAAA(content) => RecordData::AAAA { content },
            DnsRecord::CNAME(content) => RecordData::CNAME {
                content: strip_trailing_dot(content),
            },
            DnsRecord::NS(content) => RecordData::NS {
                content: strip_trailing_dot(content),
            },
            DnsRecord::MX(mx) => RecordData::MX {
                content: strip_trailing_dot(mx.exchange),
                prio: mx.priority,
            },
            DnsRecord::TXT(content) => RecordData::TXT { content },
            DnsRecord::SRV(srv) => RecordData::SRV {
                content: format!(
                    "{} {} {}",
                    srv.weight,
                    srv.port,
                    strip_trailing_dot(srv.target)
                ),
                prio: srv.priority,
            },
            DnsRecord::TLSA(tlsa) => RecordData::TLSA {
                content: tlsa.to_string(),
            },
            DnsRecord::CAA(caa) => RecordData::CAA {
                content: caa.to_string(),
            },
        }
    }
}
