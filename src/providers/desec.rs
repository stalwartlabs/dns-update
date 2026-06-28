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
    SRVRecord, TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector,
    http::{HttpClient, HttpClientBuilder},
    utils::strip_origin_from_name,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub struct DesecDnsRecordRepresentation {
    pub record_type: String,
    pub content: String,
}

#[derive(Clone)]
pub struct DesecProvider {
    client: HttpClient,
    endpoint: String,
    zones: Arc<Mutex<HashMap<String, (String, Instant)>>>,
}

#[derive(Serialize, Clone, Debug)]
pub struct DnsRecordParams<'a> {
    pub subname: &'a str,
    #[serde(rename = "type")]
    pub rr_type: &'a str,
    pub ttl: Option<u32>,
    pub records: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct DesecApiResponse {
    pub created: String,
    pub domain: String,
    pub subname: String,
    pub name: String,
    pub records: Vec<String>,
    pub ttl: u32,
    #[serde(rename = "type")]
    pub record_type: String,
    pub touched: String,
}

#[derive(Deserialize)]
struct DesecEmptyResponse {}

const DEFAULT_API_ENDPOINT: &str = "https://desec.io/api/v1";

const DESEC_MIN_TTL: u32 = 3600;

fn url_subname(subname: &str) -> &str {
    if subname.is_empty() { "@" } else { subname }
}

impl DesecProvider {
    pub(crate) fn new(auth_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Token {}", auth_token.as_ref()))
            .with_timeout(timeout)
            .build();

        Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            zones: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn resolve_domain(&self, origin: &str) -> crate::Result<String> {
        let origin = origin.trim_end_matches('.');

        if let Ok(guard) = self.zones.lock()
            && let Some((resolved, expiry)) = guard.get(origin)
            && Instant::now() < *expiry
        {
            return Ok(resolved.clone());
        }

        let resolved = self.discover_domain(origin).await;

        if let Ok(mut guard) = self.zones.lock() {
            guard.insert(
                origin.to_string(),
                (resolved.clone(), Instant::now() + Duration::from_secs(300)),
            );
        }

        Ok(resolved)
    }

    async fn discover_domain(&self, origin: &str) -> String {
        let mut candidate = origin;
        loop {
            let domain_url = format!(
                "{endpoint}/domains/{candidate}/",
                endpoint = self.endpoint,
                candidate = candidate,
            );

            if self
                .client
                .get(domain_url)
                .send_with_retry::<DesecEmptyResponse>(3)
                .await
                .is_ok()
            {
                return candidate.to_string();
            }

            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => return origin.to_string(),
            }
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
        let name = name.into_name().to_ascii_lowercase();
        let origin = origin.into_name().to_ascii_lowercase();
        let domain = self.resolve_domain(&origin).await?;
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let rr_type = record_type.as_str();

        if records.is_empty() {
            let rrset_url = format!(
                "{endpoint}/domains/{domain}/rrsets/{subdomain}/{rr_type}/",
                endpoint = self.endpoint,
                domain = &domain,
                subdomain = url_subname(&subdomain),
                rr_type = rr_type,
            );

            return self
                .client
                .delete(rrset_url)
                .send_with_retry::<DesecEmptyResponse>(3)
                .await
                .map(|_| ())
                .or_else(|err| match err {
                    crate::Error::NotFound => Ok(()),
                    err => Err(err),
                });
        }

        let contents = build_contents(record_type, records)?;
        let ttl = ttl.max(DESEC_MIN_TTL);

        let rrsets_url = format!(
            "{endpoint}/domains/{domain}/rrsets/",
            endpoint = self.endpoint,
            domain = &domain,
        );

        self.client
            .put(rrsets_url)
            .with_body(vec![DnsRecordParams {
                subname: &subdomain,
                rr_type,
                ttl: Some(ttl),
                records: contents,
            }])?
            .send_with_retry::<Vec<DesecApiResponse>>(3)
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

        let name = name.into_name().to_ascii_lowercase();
        let origin = origin.into_name().to_ascii_lowercase();
        let domain = self.resolve_domain(&origin).await?;
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let rr_type = record_type.as_str();
        let ttl = ttl.max(DESEC_MIN_TTL);

        let to_add = build_contents(record_type, records)?;

        let rrset_url = format!(
            "{endpoint}/domains/{domain}/rrsets/{subdomain}/{rr_type}/",
            endpoint = self.endpoint,
            domain = &domain,
            subdomain = url_subname(&subdomain),
            rr_type = rr_type,
        );

        let (mut current, existed) = match self
            .client
            .get(rrset_url.clone())
            .send_with_retry::<DesecApiResponse>(3)
            .await
        {
            Ok(existing) => (existing.records, true),
            Err(crate::Error::NotFound) => (Vec::new(), false),
            Err(err) => return Err(err),
        };

        let before = current.len();
        for content in to_add {
            if !current.iter().any(|r| r == &content) {
                current.push(content);
            }
        }

        if existed && current.len() == before {
            return Ok(());
        }

        let params = DnsRecordParams {
            subname: &subdomain,
            rr_type,
            ttl: Some(ttl),
            records: current,
        };

        if existed {
            self.client.put(rrset_url)
        } else {
            self.client.post(format!(
                "{endpoint}/domains/{domain}/rrsets/",
                endpoint = self.endpoint,
                domain = domain
            ))
        }
        .with_body(params)?
        .send_with_retry::<DesecApiResponse>(3)
        .await
        .map(|_| ())
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

        let name = name.into_name().to_ascii_lowercase();
        let origin = origin.into_name().to_ascii_lowercase();
        let domain = self.resolve_domain(&origin).await?;
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let rr_type = record_type.as_str();

        let to_remove = build_contents(record_type, records)?;

        let rrset_url = format!(
            "{endpoint}/domains/{domain}/rrsets/{subdomain}/{rr_type}/",
            endpoint = self.endpoint,
            domain = &domain,
            subdomain = url_subname(&subdomain),
            rr_type = rr_type,
        );

        let existing = match self
            .client
            .get(rrset_url.clone())
            .send_with_retry::<DesecApiResponse>(3)
            .await
        {
            Ok(existing) => existing,
            Err(crate::Error::NotFound) => return Ok(()),
            Err(err) => return Err(err),
        };

        let original_len = existing.records.len();
        let filtered: Vec<String> = existing
            .records
            .into_iter()
            .filter(|content| !to_remove.iter().any(|r| r == content))
            .collect();

        if filtered.len() == original_len {
            return Ok(());
        }

        if filtered.is_empty() {
            return self
                .client
                .delete(rrset_url)
                .send_with_retry::<DesecEmptyResponse>(3)
                .await
                .map(|_| ())
                .or_else(|err| match err {
                    crate::Error::NotFound => Ok(()),
                    err => Err(err),
                });
        }

        self.client
            .put(rrset_url)
            .with_body(DnsRecordParams {
                subname: &subdomain,
                rr_type,
                ttl: Some(existing.ttl),
                records: filtered,
            })?
            .send_with_retry::<DesecApiResponse>(3)
            .await
            .map(|_| ())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let name = name.into_name().to_ascii_lowercase();
        let origin = origin.into_name().to_ascii_lowercase();
        let domain = self.resolve_domain(&origin).await?;
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let rr_type = record_type.as_str();

        let rrset_url = format!(
            "{endpoint}/domains/{domain}/rrsets/{subdomain}/{rr_type}/",
            endpoint = self.endpoint,
            domain = &domain,
            subdomain = url_subname(&subdomain),
            rr_type = rr_type,
        );

        let response = match self
            .client
            .get(rrset_url)
            .send_with_retry::<DesecApiResponse>(3)
            .await
        {
            Ok(response) => response,
            Err(crate::Error::NotFound) => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };

        response
            .records
            .into_iter()
            .map(|content| parse_record(record_type, &content))
            .collect()
    }
}

fn build_contents(
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
        out.push(DesecDnsRecordRepresentation::from(record).content);
    }
    Ok(out)
}

fn parse_record(record_type: DnsRecordType, content: &str) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => content
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A record: {e}"))),
        DnsRecordType::AAAA => content
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA record: {e}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(strip_trailing_dot(content).to_string())),
        DnsRecordType::NS => Ok(DnsRecord::NS(strip_trailing_dot(content).to_string())),
        DnsRecordType::MX => parse_mx(content),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(unquote_txt(content))),
        DnsRecordType::SRV => parse_srv(content),
        DnsRecordType::TLSA => parse_tlsa(content),
        DnsRecordType::CAA => parse_caa(content),
    }
}

fn strip_trailing_dot(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
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
        exchange: strip_trailing_dot(exchange.trim()).to_string(),
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
        target: strip_trailing_dot(target).to_string(),
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

fn ensure_fqdn(name: String) -> String {
    if name.ends_with('.') {
        name
    } else {
        format!("{name}.")
    }
}

impl From<DnsRecord> for DesecDnsRecordRepresentation {
    fn from(record: DnsRecord) -> Self {
        match record {
            DnsRecord::A(content) => DesecDnsRecordRepresentation {
                record_type: "A".to_string(),
                content: content.to_string(),
            },
            DnsRecord::AAAA(content) => DesecDnsRecordRepresentation {
                record_type: "AAAA".to_string(),
                content: content.to_string(),
            },
            DnsRecord::CNAME(content) => DesecDnsRecordRepresentation {
                record_type: "CNAME".to_string(),
                content: ensure_fqdn(content),
            },
            DnsRecord::NS(content) => DesecDnsRecordRepresentation {
                record_type: "NS".to_string(),
                content: ensure_fqdn(content),
            },
            DnsRecord::MX(mx) => DesecDnsRecordRepresentation {
                record_type: "MX".to_string(),
                content: format!("{} {}", mx.priority, ensure_fqdn(mx.exchange)),
            },
            DnsRecord::TXT(content) => DesecDnsRecordRepresentation {
                record_type: "TXT".to_string(),
                content: format!("\"{content}\""),
            },
            DnsRecord::SRV(srv) => DesecDnsRecordRepresentation {
                record_type: "SRV".to_string(),
                content: format!(
                    "{} {} {} {}",
                    srv.priority,
                    srv.weight,
                    srv.port,
                    ensure_fqdn(srv.target)
                ),
            },
            DnsRecord::TLSA(tlsa) => DesecDnsRecordRepresentation {
                record_type: "TLSA".to_string(),
                content: tlsa.to_string(),
            },
            DnsRecord::CAA(caa) => DesecDnsRecordRepresentation {
                record_type: "CAA".to_string(),
                content: caa.to_string(),
            },
        }
    }
}
