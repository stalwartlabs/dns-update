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
    DnsRecord, DnsRecordType, Error, IntoFqdn,
    crypto::hmac_sha256,
    http::{HttpClient, HttpClientBuilder},
};
use chrono::Utc;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const BAIDU_DEFAULT_ENDPOINT: &str = "https://dns.baidubce.com";
const BAIDU_EXPIRE_SECONDS: u32 = 1800;

#[derive(Clone)]
pub struct BaiduCloudProvider {
    client: HttpClientBuilder,
    access_key: String,
    secret_key: String,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecordBody<'a> {
    rr: &'a str,
    #[serde(rename = "type")]
    rr_type: &'a str,
    value: &'a str,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    description: &'a str,
}

#[derive(Serialize, Debug)]
struct UpdateRecordBody<'a> {
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

#[derive(Deserialize, Debug)]
struct BaiduRecord {
    id: String,
    rr: String,
    #[serde(rename = "type")]
    rr_type: String,
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

        let client = HttpClientBuilder::default().with_timeout(timeout);

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

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name().to_string();
        let zone = origin.into_name().to_string();
        let rr = subdomain_for(&name, &zone);
        let (rr_type, value) = render_record(&record)?;
        let priority = record.priority();

        let path = format!("/v1/dns/zone/{}/record", url_encode_segment(&zone));
        let query = format!("clientToken={}", generate_client_token());

        let body = serde_json::to_string(&CreateRecordBody {
            rr: &rr,
            rr_type: &rr_type,
            value: &value,
            ttl,
            priority,
            description: "lego",
        })
        .map_err(|err| Error::Serialize(err.to_string()))?;

        let _ = self
            .send_signed_raw(Method::POST, &path, &query, Some(body))
            .await?;
        Ok(())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let (rr_type_str, value) = render_record(&record)?;
        let name = name.into_name().to_string();
        let zone = origin.into_name().to_string();
        let rr = subdomain_for(&name, &zone);
        let rr_type = record.as_type();
        let record_id = self
            .find_record_id(&zone, &rr, rr_type.as_str())
            .await?;
        let priority = record.priority();

        let path = format!(
            "/v1/dns/zone/{}/record/{}",
            url_encode_segment(&zone),
            url_encode_segment(&record_id)
        );
        let query = format!("clientToken={}", generate_client_token());

        let body = serde_json::to_string(&UpdateRecordBody {
            rr: &rr,
            rr_type: &rr_type_str,
            value: &value,
            ttl,
            priority,
            description: "lego",
        })
        .map_err(|err| Error::Serialize(err.to_string()))?;

        let _ = self
            .send_signed_raw(Method::PUT, &path, &query, Some(body))
            .await?;
        Ok(())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name().to_string();
        let zone = origin.into_name().to_string();
        let rr = subdomain_for(&name, &zone);
        let record_id = self
            .find_record_id(&zone, &rr, record_type.as_str())
            .await?;

        let path = format!(
            "/v1/dns/zone/{}/record/{}",
            url_encode_segment(&zone),
            url_encode_segment(&record_id)
        );
        let query = format!("clientToken={}", generate_client_token());

        let _ = self
            .send_signed_raw(Method::DELETE, &path, &query, None)
            .await?;
        Ok(())
    }

    async fn find_record_id(
        &self,
        zone: &str,
        rr: &str,
        rr_type: &str,
    ) -> crate::Result<String> {
        let mut marker: Option<String> = None;
        loop {
            let path = format!("/v1/dns/zone/{}/record", url_encode_segment(zone));
            let query = match &marker {
                Some(m) => format!("marker={}", uri_encode(m, true)),
                None => String::new(),
            };

            let text = self
                .send_signed_raw(Method::GET, &path, &query, None)
                .await?;
            let resp: ListRecordsResponse = if text.is_empty() {
                ListRecordsResponse {
                    records: vec![],
                    is_truncated: false,
                    next_marker: None,
                }
            } else {
                serde_json::from_str(&text)
                    .map_err(|err| Error::Serialize(format!("Failed to deserialize: {err}")))?
            };

            if let Some(rec) = resp
                .records
                .into_iter()
                .find(|r| r.rr == rr && r.rr_type == rr_type)
            {
                return Ok(rec.id);
            }

            if !resp.is_truncated {
                break;
            }
            marker = resp.next_marker;
            if marker.is_none() {
                break;
            }
        }

        Err(Error::Api(format!(
            "baiducloud: record {} of type {} not found in zone {}",
            rr, rr_type, zone
        )))
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
        let canonical_headers = format!("host:{}", uri_encode(&host, true));
        let signed_headers = "host";

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

        let mut http: HttpClient = self
            .client
            .build(method, url)
            .with_header("Host", &host)
            .with_header("Authorization", &authorization);

        if let Some(b) = body {
            http = http.with_raw_body(b);
        }

        http.send_raw().await
    }
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
    let segments: Vec<String> = path
        .split('/')
        .map(|s| uri_encode(s, true))
        .collect();
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
            Some((uri_encode(&k, true), uri_encode(&v, true)))
        })
        .collect();
    parts.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    parts
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
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

fn render_record(record: &DnsRecord) -> crate::Result<(String, String)> {
    match record {
        DnsRecord::A(addr) => Ok(("A".to_string(), addr.to_string())),
        DnsRecord::AAAA(addr) => Ok(("AAAA".to_string(), addr.to_string())),
        DnsRecord::CNAME(name) => Ok(("CNAME".to_string(), ensure_fqdn(name))),
        DnsRecord::NS(name) => Ok(("NS".to_string(), ensure_fqdn(name))),
        DnsRecord::MX(mx) => Ok(("MX".to_string(), ensure_fqdn(&mx.exchange))),
        DnsRecord::TXT(text) => Ok(("TXT".to_string(), text.clone())),
        DnsRecord::SRV(srv) => Ok((
            "SRV".to_string(),
            format!(
                "{} {} {} {}",
                srv.priority,
                srv.weight,
                srv.port,
                ensure_fqdn(&srv.target)
            ),
        )),
        DnsRecord::CAA(caa) => Ok(("CAA".to_string(), caa.clone().to_string())),
        DnsRecord::TLSA(_) => Err(Error::Api(
            "TLSA records are not supported by baiducloud".to_string(),
        )),
    }
}
