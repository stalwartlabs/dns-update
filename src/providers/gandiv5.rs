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
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, KeyValue as DnsKeyValue, MXRecord,
    SRVRecord, TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector, http::HttpClientBuilder,
    utils::strip_origin_from_name,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone)]
pub struct GandiV5Provider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct RRSetPayload {
    rrset_ttl: u32,
    rrset_values: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct RRSetResponse {
    #[serde(default)]
    rrset_values: Vec<String>,
}

const DEFAULT_API_ENDPOINT: &str = "https://api.gandi.net/v5/livedns";

impl GandiV5Provider {
    pub(crate) fn new(
        personal_access_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let token = personal_access_token.as_ref();
        if token.is_empty() {
            return Err(Error::Api(
                "Gandi personal access token must not be empty".to_string(),
            ));
        }

        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {token}"))
            .with_timeout(timeout);

        Ok(Self {
            client,
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);

        if records.is_empty() {
            return self
                .delete_rrset_url(&domain, &subdomain, record_type)
                .await;
        }

        let values = build_values(record_type, records)?;
        self.put_rrset_url(&domain, &subdomain, record_type, ttl, values)
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let new_values = build_values(record_type, records)?;

        let mut current = self
            .get_rrset_values(&domain, &subdomain, record_type)
            .await?;
        let mut changed = false;
        for value in new_values {
            if !current.iter().any(|existing| existing == &value) {
                current.push(value);
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
        self.put_rrset_url(&domain, &subdomain, record_type, ttl, current)
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let to_remove = build_values(record_type, records)?;

        let current = self
            .get_rrset_values(&domain, &subdomain, record_type)
            .await?;
        if current.is_empty() {
            return Ok(());
        }
        let remaining: Vec<String> = current
            .into_iter()
            .filter(|v| !to_remove.iter().any(|r| r == v))
            .collect();

        if remaining.is_empty() {
            return self
                .delete_rrset_url(&domain, &subdomain, record_type)
                .await;
        }
        let ttl = self
            .get_rrset_ttl(&domain, &subdomain, record_type)
            .await?
            .unwrap_or(3600);
        self.put_rrset_url(&domain, &subdomain, record_type, ttl, remaining)
            .await
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let values = self
            .get_rrset_values(&domain, &subdomain, record_type)
            .await?;
        values
            .into_iter()
            .map(|v| parse_value(record_type, &v))
            .collect()
    }

    async fn put_rrset_url(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        ttl: u32,
        values: Vec<String>,
    ) -> crate::Result<()> {
        self.client
            .put(format!(
                "{}/domains/{}/records/{}/{}",
                self.endpoint,
                domain,
                subdomain,
                record_type.as_str(),
            ))
            .with_body(RRSetPayload {
                rrset_ttl: ttl,
                rrset_values: values,
            })?
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn delete_rrset_url(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let result = self
            .client
            .delete(format!(
                "{}/domains/{}/records/{}/{}",
                self.endpoint,
                domain,
                subdomain,
                record_type.as_str(),
            ))
            .send_raw()
            .await;
        match result {
            Ok(_) | Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn get_rrset_values(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<String>> {
        match self.fetch_rrset(domain, subdomain, record_type).await? {
            Some(rrset) => Ok(rrset.rrset_values),
            None => Ok(Vec::new()),
        }
    }

    async fn get_rrset_ttl(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Option<u32>> {
        #[derive(Deserialize)]
        struct WithTtl {
            #[serde(default)]
            rrset_ttl: Option<u32>,
        }
        let result = self
            .client
            .get(format!(
                "{}/domains/{}/records/{}/{}",
                self.endpoint,
                domain,
                subdomain,
                record_type.as_str(),
            ))
            .send::<WithTtl>()
            .await;
        match result {
            Ok(r) => Ok(r.rrset_ttl),
            Err(Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn fetch_rrset(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Option<RRSetResponse>> {
        let result = self
            .client
            .get(format!(
                "{}/domains/{}/records/{}/{}",
                self.endpoint,
                domain,
                subdomain,
                record_type.as_str(),
            ))
            .send::<RRSetResponse>()
            .await;
        match result {
            Ok(r) => Ok(Some(r)),
            Err(Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

fn build_values(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<String>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(render_value(record)?);
    }
    Ok(out)
}

fn render_value(record: DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => ensure_trailing_dot(content),
        DnsRecord::NS(content) => ensure_trailing_dot(content),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, ensure_trailing_dot(mx.exchange)),
        DnsRecord::TXT(content) => format!("\"{}\"", content.replace('\"', "\\\"")),
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            ensure_trailing_dot(srv.target),
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    })
}

fn ensure_trailing_dot(value: String) -> String {
    if value.ends_with('.') {
        value
    } else {
        format!("{value}.")
    }
}

fn strip_trailing_dot(s: &str) -> String {
    s.strip_suffix('.').unwrap_or(s).to_string()
}

fn parse_value(record_type: DnsRecordType, content: &str) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => content
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A record: {e}"))),
        DnsRecordType::AAAA => content
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA record: {e}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(strip_trailing_dot(content))),
        DnsRecordType::NS => Ok(DnsRecord::NS(strip_trailing_dot(content))),
        DnsRecordType::MX => parse_mx(content),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(unquote_txt(content))),
        DnsRecordType::SRV => parse_srv(content),
        DnsRecordType::TLSA => parse_tlsa(content),
        DnsRecordType::CAA => parse_caa(content),
    }
}

fn unquote_txt(content: &str) -> String {
    let trimmed = content
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(content);
    trimmed.replace("\\\"", "\"")
}

fn parse_mx(content: &str) -> crate::Result<DnsRecord> {
    let (prio, exchange) = content
        .split_once(' ')
        .ok_or_else(|| Error::Parse(format!("invalid MX record: {content}")))?;
    let priority: u16 = prio
        .parse()
        .map_err(|e| Error::Parse(format!("invalid MX priority {prio}: {e}")))?;
    Ok(DnsRecord::MX(MXRecord {
        priority,
        exchange: strip_trailing_dot(exchange.trim()),
    }))
}

fn parse_srv(content: &str) -> crate::Result<DnsRecord> {
    let mut parts = content.split_whitespace();
    let priority: u16 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV priority: {e}")))?;
    let weight: u16 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV weight: {e}")))?;
    let port: u16 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV port: {e}")))?;
    let target = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV record: {content}")))?;
    Ok(DnsRecord::SRV(SRVRecord {
        priority,
        weight,
        port,
        target: strip_trailing_dot(target),
    }))
}

fn parse_tlsa(content: &str) -> crate::Result<DnsRecord> {
    let mut parts = content.split_whitespace();
    let usage: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA usage: {e}")))?;
    let selector: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA selector: {e}")))?;
    let matching: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA matching: {e}")))?;
    let hex: String = parts.collect::<Vec<_>>().join("");
    Ok(DnsRecord::TLSA(TLSARecord {
        cert_usage: tlsa_cert_usage_from_u8(usage)?,
        selector: tlsa_selector_from_u8(selector)?,
        matching: tlsa_matching_from_u8(matching)?,
        cert_data: decode_hex(&hex)?,
    }))
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

fn parse_caa(content: &str) -> crate::Result<DnsRecord> {
    let mut parts = content.splitn(3, ' ');
    let flags: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {content}")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags: {e}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {content}")))?
        .to_string();
    let raw_value = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA record: {content}")))?;
    let value = raw_value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(raw_value)
        .to_string();

    let issuer_critical = flags & 0x80 != 0;
    match tag.as_str() {
        "issue" => {
            let (name, options) = parse_caa_value(&value);
            Ok(DnsRecord::CAA(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }))
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(&value);
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

fn parse_caa_value(value: &str) -> (Option<String>, Vec<DnsKeyValue>) {
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
            Some((k, v)) => DnsKeyValue {
                key: k.trim().to_string(),
                value: v.trim().to_string(),
            },
            None => DnsKeyValue {
                key: p.trim().to_string(),
                value: String::new(),
            },
        })
        .collect();
    (name, options)
}
