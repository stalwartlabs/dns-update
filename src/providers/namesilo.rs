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
use quick_xml::de::from_str;
use serde::Deserialize;
use std::time::Duration;

#[derive(Clone)]
pub struct NameSiloProvider {
    client: HttpClient,
    endpoint: String,
    api_key: String,
}

#[derive(Deserialize, Debug)]
struct NameSiloEnvelope {
    reply: NameSiloReply,
}

#[derive(Deserialize, Debug)]
struct NameSiloReply {
    code: String,
    detail: String,
    #[serde(default)]
    resource_record: Vec<ResourceRecord>,
}

#[derive(Deserialize, Debug, Clone)]
struct ResourceRecord {
    record_id: String,
    #[serde(rename = "type")]
    record_type: String,
    host: String,
    #[serde(default)]
    value: String,
    #[allow(dead_code)]
    #[serde(default)]
    ttl: String,
    #[serde(default)]
    distance: String,
}

const DEFAULT_API_ENDPOINT: &str = "https://www.namesilo.com/api";

impl NameSiloProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        let key = api_key.as_ref();
        if key.is_empty() {
            return Err(Error::Api("NameSilo API key must not be empty".to_string()));
        }
        Ok(Self {
            client: HttpClientBuilder::default().with_timeout(timeout).build(),
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            api_key: key.to_string(),
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
        ensure_supported_type(record_type)?;
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let desired = build_rendered(record_type, records)?;
        let existing = self.list_at(&domain, &name, record_type).await?;

        let mut existing_pool = existing;
        let mut to_add: Vec<RenderedRecord> = Vec::new();

        for rendered in desired {
            if let Some(idx) = existing_pool
                .iter()
                .position(|r| matches_rendered(r, &rendered))
            {
                existing_pool.swap_remove(idx);
            } else if !to_add.iter().any(|q| rendered_equal(q, &rendered)) {
                to_add.push(rendered);
            }
        }

        for entry in existing_pool {
            self.delete_record(&domain, &entry.record_id).await?;
        }
        for rendered in to_add {
            self.add_record(
                &domain,
                &subdomain,
                record_type,
                &rendered.value,
                ttl,
                rendered.distance,
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
        if records.is_empty() {
            return Ok(());
        }
        ensure_supported_type(record_type)?;
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let desired = build_rendered(record_type, records)?;
        let existing = self.list_at(&domain, &name, record_type).await?;

        let mut queued: Vec<RenderedRecord> = Vec::new();
        for rendered in desired {
            if existing.iter().any(|r| matches_rendered(r, &rendered)) {
                continue;
            }
            if queued.iter().any(|q| rendered_equal(q, &rendered)) {
                continue;
            }
            self.add_record(
                &domain,
                &subdomain,
                record_type,
                &rendered.value,
                ttl,
                rendered.distance,
            )
            .await?;
            queued.push(rendered);
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
        ensure_supported_type(record_type)?;
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let to_remove = build_rendered(record_type, records)?;
        let existing = self.list_at(&domain, &name, record_type).await?;

        for rendered in to_remove {
            if let Some(entry) = existing.iter().find(|r| matches_rendered(r, &rendered)) {
                self.delete_record(&domain, &entry.record_id).await?;
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
        ensure_supported_type(record_type)?;
        let name = name.into_name().into_owned();
        let domain = origin.into_name().into_owned();
        let listed = self.list_at(&domain, &name, record_type).await?;
        listed
            .into_iter()
            .map(|r| parse_record(record_type, &r))
            .collect()
    }

    async fn list_at(
        &self,
        domain: &str,
        fqdn: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ResourceRecord>> {
        let mut params = base_params(&self.api_key);
        params.push(("domain", domain.to_string()));
        let reply = self.call("dnsListRecords", &params).await?;
        let host_target = fqdn.trim_end_matches('.').to_ascii_lowercase();
        Ok(reply
            .resource_record
            .into_iter()
            .filter(|r| {
                r.record_type == record_type.as_str() && r.host.to_ascii_lowercase() == host_target
            })
            .collect())
    }

    async fn add_record(
        &self,
        domain: &str,
        subdomain: &str,
        record_type: DnsRecordType,
        value: &str,
        ttl: u32,
        distance: u16,
    ) -> crate::Result<()> {
        let mut params = base_params(&self.api_key);
        params.push(("domain", domain.to_string()));
        params.push(("rrtype", record_type.as_str().to_string()));
        params.push(("rrhost", subdomain.to_string()));
        params.push(("rrvalue", value.to_string()));
        params.push(("rrttl", ttl.to_string()));
        params.push(("rrdistance", distance.to_string()));
        self.call("dnsAddRecord", &params).await.map(|_| ())
    }

    async fn delete_record(&self, domain: &str, record_id: &str) -> crate::Result<()> {
        let mut params = base_params(&self.api_key);
        params.push(("domain", domain.to_string()));
        params.push(("rrid", record_id.to_string()));
        self.call("dnsDeleteRecord", &params).await.map(|_| ())
    }

    async fn call(
        &self,
        operation: &str,
        params: &[(&str, String)],
    ) -> crate::Result<NameSiloReply> {
        let query =
            serde_urlencoded::to_string(params).map_err(|e| Error::Serialize(e.to_string()))?;
        let url = format!("{}/{}?{}", self.endpoint, operation, query);
        let body = self.client.get(url).send_raw().await?;
        let envelope: NameSiloEnvelope =
            from_str(&body).map_err(|e| Error::Parse(format!("Invalid XML response: {e}")))?;
        if matches!(envelope.reply.code.as_str(), "300" | "301" | "302") {
            Ok(envelope.reply)
        } else {
            Err(Error::Api(format!(
                "NameSilo error {}: {}",
                envelope.reply.code, envelope.reply.detail
            )))
        }
    }
}

#[derive(Debug, Clone)]
struct RenderedRecord {
    value: String,
    distance: u16,
}

fn base_params(api_key: &str) -> Vec<(&'static str, String)> {
    vec![
        ("version", "1".to_string()),
        ("type", "xml".to_string()),
        ("key", api_key.to_string()),
    ]
}

fn ensure_supported_type(record_type: DnsRecordType) -> crate::Result<()> {
    match record_type {
        DnsRecordType::NS => Err(Error::Api(
            "NS records are not supported by NameSilo's dnsAddRecord; \
             use the registrar changeNameServers endpoint instead"
                .to_string(),
        )),
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by NameSilo".to_string(),
        )),
        _ => Ok(()),
    }
}

fn build_rendered(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<RenderedRecord>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        let distance = record.priority().unwrap_or(0);
        let value = render_value(record)?;
        out.push(RenderedRecord { value, distance });
    }
    Ok(out)
}

fn matches_rendered(existing: &ResourceRecord, rendered: &RenderedRecord) -> bool {
    if existing.value != rendered.value {
        return false;
    }
    let existing_distance: u16 = existing.distance.parse().unwrap_or(0);
    existing_distance == rendered.distance
}

fn rendered_equal(a: &RenderedRecord, b: &RenderedRecord) -> bool {
    a.value == b.value && a.distance == b.distance
}

fn render_value(record: DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content,
        DnsRecord::NS(_) => {
            return Err(Error::Api(
                "NS records are not supported by NameSilo's dnsAddRecord; \
                 use the registrar changeNameServers endpoint instead"
                    .to_string(),
            ));
        }
        DnsRecord::MX(mx) => mx.exchange,
        DnsRecord::TXT(content) => content,
        DnsRecord::SRV(srv) => format!("{}:{}:{}", srv.weight, srv.port, srv.target),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.decompose();
            format!("{}:{}:{}", flags, tag, value)
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by NameSilo".to_string(),
            ));
        }
    })
}

fn parse_record(record_type: DnsRecordType, raw: &ResourceRecord) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => raw
            .value
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A value '{}': {}", raw.value, e))),
        DnsRecordType::AAAA => raw
            .value
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA value '{}': {}", raw.value, e))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(raw.value.clone())),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(raw.value.clone())),
        DnsRecordType::MX => {
            let priority = raw.distance.parse().unwrap_or(0);
            Ok(DnsRecord::MX(MXRecord {
                exchange: raw.value.clone(),
                priority,
            }))
        }
        DnsRecordType::SRV => parse_srv(raw),
        DnsRecordType::CAA => parse_caa(&raw.value),
        DnsRecordType::NS => Err(Error::Api(
            "NS records are not supported by NameSilo".to_string(),
        )),
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by NameSilo".to_string(),
        )),
    }
}

fn parse_srv(raw: &ResourceRecord) -> crate::Result<DnsRecord> {
    let parts: Vec<&str> = raw.value.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(Error::Parse(format!(
            "invalid NameSilo SRV value '{}': expected weight:port:target",
            raw.value
        )));
    }
    let weight: u16 = parts[0]
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV weight '{}': {}", parts[0], e)))?;
    let port: u16 = parts[1]
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV port '{}': {}", parts[1], e)))?;
    let priority: u16 = raw.distance.parse().unwrap_or(0);
    Ok(DnsRecord::SRV(SRVRecord {
        priority,
        weight,
        port,
        target: parts[2].to_string(),
    }))
}

fn parse_caa(value: &str) -> crate::Result<DnsRecord> {
    let parts: Vec<&str> = value.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(Error::Parse(format!(
            "invalid NameSilo CAA value '{}': expected flag:tag:value",
            value
        )));
    }
    let flags: u8 = parts[0]
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flag '{}': {}", parts[0], e)))?;
    Ok(DnsRecord::CAA(build_caa(flags, parts[1], parts[2])?))
}

fn build_caa(flags: u8, tag: &str, value: &str) -> crate::Result<CAARecord> {
    let issuer_critical = flags & 0x80 != 0;
    match tag {
        "issue" => {
            let (name, options) = parse_caa_options(value);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = parse_caa_options(value);
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

fn parse_caa_options(value: &str) -> (Option<String>, Vec<KeyValue>) {
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
