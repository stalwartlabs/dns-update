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
    utils::strip_origin_from_name,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone)]
pub struct GodaddyProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GodaddyRecord {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none", default)]
    pub record_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    pub data: String,
    pub ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub service: Option<String>,
}

const DEFAULT_API_ENDPOINT: &str = "https://api.godaddy.com";

impl GodaddyProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        api_secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        let api_secret = api_secret.as_ref();
        if api_key.is_empty() || api_secret.is_empty() {
            return Err(Error::Api(
                "GoDaddy API key and secret must not be empty".to_string(),
            ));
        }

        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("sso-key {api_key}:{api_secret}"))
            .with_timeout(timeout)
            .build();

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
        let url = self.rrset_url(&domain, record_type, &subdomain);

        if records.is_empty() {
            return self
                .client
                .delete(url)
                .send_with_retry::<serde_json::Value>(3)
                .await
                .map(|_| ())
                .or_else(|err| match err {
                    Error::NotFound => Ok(()),
                    err => Err(err),
                });
        }

        let payload = build_payload(record_type, ttl, records)?;
        self.client
            .put(url)
            .with_body(payload)?
            .send_with_retry::<serde_json::Value>(3)
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

        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let url = self.rrset_url(&domain, record_type, &subdomain);
        let to_add = build_payload(record_type, ttl, records)?;

        let current = self.fetch_rrset(&url).await?;

        let mut merged = current.clone();
        let mut additions = 0usize;
        for candidate in to_add {
            if !merged
                .iter()
                .any(|existing| same_rdata(existing, &candidate))
            {
                merged.push(candidate);
                additions += 1;
            }
        }

        if additions == 0 {
            return Ok(());
        }

        for entry in merged.iter_mut() {
            entry.ttl = ttl;
        }

        self.client
            .put(url)
            .with_body(merged)?
            .send_with_retry::<serde_json::Value>(3)
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

        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let url = self.rrset_url(&domain, record_type, &subdomain);
        let to_remove = build_payload(record_type, 0, records)?;

        let current = self.fetch_rrset(&url).await?;
        if current.is_empty() {
            return Ok(());
        }

        let original_len = current.len();
        let filtered: Vec<GodaddyRecord> = current
            .into_iter()
            .filter(|existing| !to_remove.iter().any(|target| same_rdata(existing, target)))
            .collect();

        if filtered.len() == original_len {
            return Ok(());
        }

        if filtered.is_empty() {
            return self
                .client
                .delete(url)
                .send_with_retry::<serde_json::Value>(3)
                .await
                .map(|_| ())
                .or_else(|err| match err {
                    Error::NotFound => Ok(()),
                    err => Err(err),
                });
        }

        self.client
            .put(url)
            .with_body(filtered)?
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
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
        let url = self.rrset_url(&domain, record_type, &subdomain);

        let listed = self.fetch_rrset(&url).await?;
        listed
            .into_iter()
            .map(|record| parse_record(record_type, &record))
            .collect()
    }

    async fn fetch_rrset(&self, url: &str) -> crate::Result<Vec<GodaddyRecord>> {
        match self.client.get(url.to_string()).send().await {
            Ok(records) => Ok(records),
            Err(Error::NotFound) => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }

    fn rrset_url(&self, domain: &str, record_type: DnsRecordType, subdomain: &str) -> String {
        format!(
            "{}/v1/domains/{}/records/{}/{}",
            self.endpoint,
            domain,
            record_type.as_str(),
            subdomain,
        )
    }
}

fn build_payload(
    expected_type: DnsRecordType,
    ttl: u32,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<GodaddyRecord>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(build_record(record, ttl)?);
    }
    Ok(out)
}

fn same_rdata(a: &GodaddyRecord, b: &GodaddyRecord) -> bool {
    a.data == b.data
        && a.priority.unwrap_or(0) == b.priority.unwrap_or(0)
        && a.port.unwrap_or(0) == b.port.unwrap_or(0)
        && a.weight.unwrap_or(0) == b.weight.unwrap_or(0)
}

fn build_record(record: DnsRecord, ttl: u32) -> crate::Result<GodaddyRecord> {
    Ok(match record {
        DnsRecord::A(addr) => GodaddyRecord {
            record_type: None,
            name: None,
            data: addr.to_string(),
            ttl,
            priority: None,
            port: None,
            weight: None,
            protocol: None,
            service: None,
        },
        DnsRecord::AAAA(addr) => GodaddyRecord {
            record_type: None,
            name: None,
            data: addr.to_string(),
            ttl,
            priority: None,
            port: None,
            weight: None,
            protocol: None,
            service: None,
        },
        DnsRecord::CNAME(content) => GodaddyRecord {
            record_type: None,
            name: None,
            data: content,
            ttl,
            priority: None,
            port: None,
            weight: None,
            protocol: None,
            service: None,
        },
        DnsRecord::NS(content) => GodaddyRecord {
            record_type: None,
            name: None,
            data: content,
            ttl,
            priority: None,
            port: None,
            weight: None,
            protocol: None,
            service: None,
        },
        DnsRecord::MX(mx) => GodaddyRecord {
            record_type: None,
            name: None,
            data: mx.exchange,
            ttl,
            priority: Some(mx.priority),
            port: None,
            weight: None,
            protocol: None,
            service: None,
        },
        DnsRecord::TXT(content) => GodaddyRecord {
            record_type: None,
            name: None,
            data: content,
            ttl,
            priority: None,
            port: None,
            weight: None,
            protocol: None,
            service: None,
        },
        DnsRecord::SRV(srv) => GodaddyRecord {
            record_type: None,
            name: None,
            data: srv.target,
            ttl,
            priority: Some(srv.priority),
            port: Some(srv.port),
            weight: Some(srv.weight),
            protocol: None,
            service: None,
        },
        DnsRecord::CAA(caa) => GodaddyRecord {
            record_type: None,
            name: None,
            data: caa.to_string(),
            ttl,
            priority: None,
            port: None,
            weight: None,
            protocol: None,
            service: None,
        },
        DnsRecord::TLSA(_) => {
            return Err(Error::Unsupported(
                "TLSA records are not supported by GoDaddy".to_string(),
            ));
        }
    })
}

fn parse_record(record_type: DnsRecordType, record: &GodaddyRecord) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => record
            .data
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A record: {e}"))),
        DnsRecordType::AAAA => record
            .data
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA record: {e}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(strip_trailing_dot(&record.data))),
        DnsRecordType::NS => Ok(DnsRecord::NS(strip_trailing_dot(&record.data))),
        DnsRecordType::MX => Ok(DnsRecord::MX(MXRecord {
            exchange: strip_trailing_dot(&record.data),
            priority: record.priority.unwrap_or(0),
        })),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(record.data.clone())),
        DnsRecordType::SRV => Ok(DnsRecord::SRV(SRVRecord {
            priority: record.priority.unwrap_or(0),
            weight: record.weight.unwrap_or(0),
            port: record.port.unwrap_or(0),
            target: strip_trailing_dot(&record.data),
        })),
        DnsRecordType::CAA => Ok(DnsRecord::CAA(parse_caa(&record.data)?)),
        DnsRecordType::TLSA => Err(Error::Unsupported(
            "TLSA records are not supported by GoDaddy".to_string(),
        )),
    }
}

fn strip_trailing_dot(value: &str) -> String {
    value.strip_suffix('.').unwrap_or(value).to_string()
}

fn parse_caa(content: &str) -> crate::Result<CAARecord> {
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
