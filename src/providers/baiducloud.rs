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
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord, TLSARecord,
    TlsaCertUsage, TlsaMatching, TlsaSelector,
    crypto::hmac_sha256,
    http::{HttpClient, HttpClientBuilder, HttpRequest},
    utils::txt_chunks,
};
use chrono::Utc;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const BAIDU_DEFAULT_ENDPOINT: &str = "https://dns.baidubce.com";
const BAIDU_EXPIRE_SECONDS: u32 = 1800;
const BAIDU_DESCRIPTION: &str = "dns-update";
const BAIDU_LIST_PAGE_SIZE: u32 = 1000;

#[derive(Clone)]
pub struct BaiduCloudProvider {
    client: HttpClient,
    access_key: String,
    secret_key: String,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct RecordBody<'a> {
    rr: &'a str,
    #[serde(rename = "type")]
    rr_type: &'a str,
    value: &'a str,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    description: &'a str,
}

#[derive(Deserialize, Debug)]
struct ListRecordsResponse {
    #[serde(default)]
    records: Vec<BaiduRecord>,
    #[serde(default, rename = "isTruncated")]
    is_truncated: bool,
    #[serde(default, rename = "nextMarker")]
    next_marker: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct BaiduRecord {
    id: String,
    rr: String,
    #[serde(rename = "type")]
    rr_type: String,
    value: String,
    #[serde(default)]
    ttl: Option<u32>,
    #[serde(default)]
    priority: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WireRecord {
    rr_type: &'static str,
    value: String,
    priority: Option<u16>,
}

impl BaiduCloudProvider {
    pub(crate) fn new(
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let access_key = access_key.into();
        let secret_key = secret_key.into();

        if access_key.is_empty() || secret_key.is_empty() {
            return Err(Error::Api("baiducloud: credentials missing".to_string()));
        }

        let client = HttpClientBuilder::default().with_timeout(timeout).build();

        Ok(Self {
            client,
            access_key,
            secret_key,
            endpoint: BAIDU_DEFAULT_ENDPOINT.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
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
        reject_unsupported_type(record_type)?;

        let name = name.into_name().to_string();
        let zone = origin.into_name().to_string();
        let rr = subdomain_for(&name, &zone);

        let desired = build_wires(record_type, records)?;
        let existing = self.list_at(&zone, &rr, record_type).await?;

        let mut existing_pool: Vec<BaiduRecord> = existing;
        let mut to_add: Vec<WireRecord> = Vec::new();

        for wire in desired {
            if let Some(idx) = existing_pool
                .iter()
                .position(|r| baidu_record_matches(r, &wire))
            {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(wire);
            }
        }

        for stale in existing_pool {
            self.delete_record(&zone, &stale.id).await?;
        }
        for wire in to_add {
            self.post_record(&zone, &rr, ttl, &wire).await?;
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
        reject_unsupported_type(record_type)?;

        let name = name.into_name().to_string();
        let zone = origin.into_name().to_string();
        let rr = subdomain_for(&name, &zone);

        let desired = build_wires(record_type, records)?;
        let existing = self.list_at(&zone, &rr, record_type).await?;

        for wire in desired {
            if existing.iter().any(|r| baidu_record_matches(r, &wire)) {
                continue;
            }
            self.post_record(&zone, &rr, ttl, &wire).await?;
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
        reject_unsupported_type(record_type)?;

        let name = name.into_name().to_string();
        let zone = origin.into_name().to_string();
        let rr = subdomain_for(&name, &zone);

        let to_remove = build_wires(record_type, records)?;
        let existing = self.list_at(&zone, &rr, record_type).await?;

        for wire in to_remove {
            if let Some(rec) = existing.iter().find(|r| baidu_record_matches(r, &wire)) {
                self.delete_record(&zone, &rec.id).await?;
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
        let name = name.into_name().to_string();
        let zone = origin.into_name().to_string();
        let rr = subdomain_for(&name, &zone);

        let existing = self.list_at(&zone, &rr, record_type).await?;
        existing
            .into_iter()
            .map(|r| parse_baidu_record(&r))
            .collect()
    }

    async fn list_at(
        &self,
        zone: &str,
        rr: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<BaiduRecord>> {
        let mut out: Vec<BaiduRecord> = Vec::new();
        let mut marker: Option<String> = None;
        let path = format!("/v1/dns/zone/{}/record", url_encode_segment(zone));
        let type_str = record_type.as_str();

        loop {
            let mut params: Vec<(String, String)> = Vec::new();
            params.push(("rr".to_string(), rr.to_string()));
            params.push(("maxKeys".to_string(), BAIDU_LIST_PAGE_SIZE.to_string()));
            if let Some(m) = &marker {
                params.push(("marker".to_string(), m.clone()));
            }
            let query = build_query(&params);

            let text = self
                .send_signed_raw(Method::GET, &path, &query, None)
                .await?;
            let resp = parse_list_response(&text)?;

            for rec in resp.records {
                if rec.rr == rr && rec.rr_type == type_str {
                    out.push(rec);
                }
            }

            if !resp.is_truncated {
                break;
            }
            marker = resp.next_marker;
            if marker.is_none() {
                break;
            }
        }

        Ok(out)
    }

    async fn post_record(
        &self,
        zone: &str,
        rr: &str,
        ttl: u32,
        wire: &WireRecord,
    ) -> crate::Result<()> {
        let path = format!("/v1/dns/zone/{}/record", url_encode_segment(zone));
        let query = format!("clientToken={}", generate_client_token());

        let body = serde_json::to_string(&RecordBody {
            rr,
            rr_type: wire.rr_type,
            value: &wire.value,
            ttl,
            priority: wire.priority,
            description: BAIDU_DESCRIPTION,
        })
        .map_err(|err| Error::Serialize(err.to_string()))?;

        let _ = self
            .send_signed_raw(Method::POST, &path, &query, Some(body))
            .await?;
        Ok(())
    }

    async fn delete_record(&self, zone: &str, record_id: &str) -> crate::Result<()> {
        let path = format!(
            "/v1/dns/zone/{}/record/{}",
            url_encode_segment(zone),
            url_encode_segment(record_id)
        );
        let query = format!("clientToken={}", generate_client_token());
        let _ = self
            .send_signed_raw(Method::DELETE, &path, &query, None)
            .await?;
        Ok(())
    }

    async fn send_signed_raw(
        &self,
        method: Method,
        path: &str,
        query: &str,
        body: Option<String>,
    ) -> crate::Result<String> {
        let url = if query.is_empty() {
            format!("{}{}", self.endpoint, path)
        } else {
            format!("{}{}?{}", self.endpoint, path, query)
        };

        let host = host_from_endpoint(&self.endpoint);
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let auth_string = format!(
            "bce-auth-v1/{}/{}/{}",
            self.access_key, timestamp, BAIDU_EXPIRE_SECONDS
        );

        let signing_key = hex::encode(hmac_sha256(
            self.secret_key.as_bytes(),
            auth_string.as_bytes(),
        ));

        let canonical_uri = canonicalize_uri(path);
        let canonical_query = canonical_query_string(query);

        let mut header_pairs: Vec<(&'static str, String)> = vec![
            ("host", uri_encode(&host, true)),
            ("content-type", uri_encode("application/json", true)),
        ];
        header_pairs.sort_by(|a, b| a.0.cmp(b.0));

        let canonical_headers = header_pairs
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<_>>()
            .join("\n");

        let signed_headers = header_pairs
            .iter()
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
            .join(";");

        let canonical_request = format!(
            "{}\n{}\n{}\n{}",
            method.as_str(),
            canonical_uri,
            canonical_query,
            canonical_headers
        );

        let signature = hex::encode(hmac_sha256(
            signing_key.as_bytes(),
            canonical_request.as_bytes(),
        ));

        let authorization = format!("{}/{}/{}", auth_string, signed_headers, signature);

        let mut http: HttpRequest = self
            .client
            .request(method, url)
            .with_header("Host", &host)
            .with_header("Authorization", &authorization);

        if let Some(b) = body {
            http = http.with_raw_body(b);
        }

        http.send_raw().await
    }
}

fn parse_list_response(text: &str) -> crate::Result<ListRecordsResponse> {
    if text.is_empty() {
        return Ok(ListRecordsResponse {
            records: vec![],
            is_truncated: false,
            next_marker: None,
        });
    }
    serde_json::from_str(text)
        .map_err(|err| Error::Serialize(format!("Failed to deserialize: {err}")))
}

fn host_from_endpoint(endpoint: &str) -> String {
    endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(endpoint)
        .to_string()
}

fn canonicalize_uri(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    let segments: Vec<String> = path.split('/').map(|s| uri_encode(s, true)).collect();
    segments.join("/")
}

fn canonical_query_string(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut parts: Vec<(String, String)> = query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next().unwrap_or("").to_string();
            if k.eq_ignore_ascii_case("authorization") {
                return None;
            }
            let v = it.next().unwrap_or("").to_string();
            Some((k, v))
        })
        .collect();
    parts.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    parts
        .into_iter()
        .map(|(k, v)| format!("{}={}", uri_encode(&k, true), uri_encode(&v, true)))
        .collect::<Vec<_>>()
        .join("&")
}

fn build_query(params: &[(String, String)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&")
}

fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let safe = b.is_ascii_alphanumeric()
            || b == b'-'
            || b == b'_'
            || b == b'.'
            || b == b'~'
            || (!encode_slash && b == b'/');
        if safe {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn url_encode_segment(s: &str) -> String {
    uri_encode(s, true)
}

fn subdomain_for(name: &str, origin: &str) -> String {
    let name = name.trim_end_matches('.');
    let origin = origin.trim_end_matches('.');
    if name == origin {
        return "@".to_string();
    }
    if let Some(stripped) = name.strip_suffix(&format!(".{}", origin)) {
        stripped.to_string()
    } else {
        name.to_string()
    }
}

fn generate_client_token() -> String {
    let now = Utc::now();
    format!("dnsupdate-{}", now.timestamp_micros())
}

fn ensure_fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    }
}

fn render_record(record: &DnsRecord) -> crate::Result<Vec<WireRecord>> {
    match record {
        DnsRecord::A(addr) => Ok(vec![WireRecord {
            rr_type: "A",
            value: addr.to_string(),
            priority: None,
        }]),
        DnsRecord::AAAA(addr) => Ok(vec![WireRecord {
            rr_type: "AAAA",
            value: addr.to_string(),
            priority: None,
        }]),
        DnsRecord::CNAME(name) => Ok(vec![WireRecord {
            rr_type: "CNAME",
            value: ensure_fqdn(name),
            priority: None,
        }]),
        DnsRecord::NS(name) => Ok(vec![WireRecord {
            rr_type: "NS",
            value: ensure_fqdn(name),
            priority: None,
        }]),
        DnsRecord::MX(mx) => Ok(vec![WireRecord {
            rr_type: "MX",
            value: ensure_fqdn(&mx.exchange),
            priority: Some(mx.priority),
        }]),
        DnsRecord::TXT(text) => Ok(txt_chunks(text.clone())
            .into_iter()
            .map(|chunk| WireRecord {
                rr_type: "TXT",
                value: chunk,
                priority: None,
            })
            .collect()),
        DnsRecord::SRV(srv) => Ok(vec![WireRecord {
            rr_type: "SRV",
            value: format!(
                "{} {} {} {}",
                srv.priority,
                srv.weight,
                srv.port,
                ensure_fqdn(&srv.target)
            ),
            priority: None,
        }]),
        DnsRecord::CAA(caa) => Ok(vec![WireRecord {
            rr_type: "CAA",
            value: caa.clone().to_string(),
            priority: None,
        }]),
        DnsRecord::TLSA(_) => Err(Error::Unsupported(
            "TLSA records are not supported by baiducloud".to_string(),
        )),
    }
}

fn build_wires(expected: DnsRecordType, records: Vec<DnsRecord>) -> crate::Result<Vec<WireRecord>> {
    let mut out: Vec<WireRecord> = Vec::new();
    for record in records {
        if record.as_type() != expected {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.extend(render_record(&record)?);
    }
    Ok(out)
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

fn reject_unsupported_type(record_type: DnsRecordType) -> crate::Result<()> {
    if record_type == DnsRecordType::TLSA {
        return Err(Error::Unsupported(
            "TLSA records are not supported by baiducloud".to_string(),
        ));
    }
    Ok(())
}

fn baidu_record_matches(record: &BaiduRecord, wire: &WireRecord) -> bool {
    if record.rr_type != wire.rr_type {
        return false;
    }
    if record.value != wire.value {
        return false;
    }
    match (wire.rr_type, wire.priority, record.priority) {
        ("MX", Some(want), Some(got)) => want == got,
        ("MX", Some(_), None) => false,
        _ => true,
    }
}

fn parse_baidu_record(record: &BaiduRecord) -> crate::Result<DnsRecord> {
    match record.rr_type.as_str() {
        "A" => record
            .value
            .parse()
            .map(DnsRecord::A)
            .map_err(|err| Error::Parse(format!("A record value {}: {err}", record.value))),
        "AAAA" => record
            .value
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|err| Error::Parse(format!("AAAA record value {}: {err}", record.value))),
        "CNAME" => Ok(DnsRecord::CNAME(record.value.clone())),
        "NS" => Ok(DnsRecord::NS(record.value.clone())),
        "MX" => {
            let priority = record.priority.unwrap_or(0);
            Ok(DnsRecord::MX(MXRecord {
                exchange: record.value.clone(),
                priority,
            }))
        }
        "TXT" => Ok(DnsRecord::TXT(record.value.clone())),
        "SRV" => parse_srv_value(&record.value).map(DnsRecord::SRV),
        "CAA" => parse_caa_value(&record.value).map(DnsRecord::CAA),
        "TLSA" => parse_tlsa_value(&record.value).map(DnsRecord::TLSA),
        other => Err(Error::Parse(format!(
            "Unknown baiducloud record type: {other}"
        ))),
    }
}

fn parse_srv_value(value: &str) -> crate::Result<SRVRecord> {
    let mut parts = value.split_ascii_whitespace();
    let priority = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("SRV priority missing: {value}")))?;
    let weight = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("SRV weight missing: {value}")))?;
    let port = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("SRV port missing: {value}")))?;
    let target = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("SRV target missing: {value}")))?
        .to_string();
    Ok(SRVRecord {
        priority,
        weight,
        port,
        target,
    })
}

fn parse_caa_value(value: &str) -> crate::Result<CAARecord> {
    let mut parts = value.splitn(3, ' ');
    let flags: u8 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("CAA flags missing: {value}")))?;
    let tag = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("CAA tag missing: {value}")))?;
    let raw_value = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("CAA value missing: {value}")))?;
    let trimmed = raw_value.trim().trim_matches('"').to_string();
    let issuer_critical = flags & 0x80 != 0;
    match tag {
        "issue" => Ok(CAARecord::Issue {
            issuer_critical,
            name: if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            },
            options: vec![],
        }),
        "issuewild" => Ok(CAARecord::IssueWild {
            issuer_critical,
            name: if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            },
            options: vec![],
        }),
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: trimmed,
        }),
        other => Err(Error::Parse(format!("Unknown CAA tag: {other}"))),
    }
}

fn parse_tlsa_value(value: &str) -> crate::Result<TLSARecord> {
    let mut parts = value.split_ascii_whitespace();
    let usage_byte: u8 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("TLSA usage missing: {value}")))?;
    let selector_byte: u8 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("TLSA selector missing: {value}")))?;
    let matching_byte: u8 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Parse(format!("TLSA matching missing: {value}")))?;
    let cert_hex = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("TLSA cert data missing: {value}")))?;
    let cert_data =
        hex::decode(cert_hex).map_err(|err| Error::Parse(format!("TLSA hex decode: {err}")))?;
    Ok(TLSARecord {
        cert_usage: tlsa_usage_from_u8(usage_byte),
        selector: tlsa_selector_from_u8(selector_byte),
        matching: tlsa_matching_from_u8(matching_byte),
        cert_data,
    })
}

fn tlsa_usage_from_u8(value: u8) -> TlsaCertUsage {
    match value {
        0 => TlsaCertUsage::PkixTa,
        1 => TlsaCertUsage::PkixEe,
        2 => TlsaCertUsage::DaneTa,
        3 => TlsaCertUsage::DaneEe,
        _ => TlsaCertUsage::Private,
    }
}

fn tlsa_selector_from_u8(value: u8) -> TlsaSelector {
    match value {
        0 => TlsaSelector::Full,
        1 => TlsaSelector::Spki,
        _ => TlsaSelector::Private,
    }
}

fn tlsa_matching_from_u8(value: u8) -> TlsaMatching {
    match value {
        0 => TlsaMatching::Raw,
        1 => TlsaMatching::Sha256,
        2 => TlsaMatching::Sha512,
        _ => TlsaMatching::Private,
    }
}
