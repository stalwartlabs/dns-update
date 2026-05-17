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
    crypto::{hmac_sha256, sha256_digest},
    http::{HttpClient, HttpClientBuilder},
};
use chrono::Utc;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const HUAWEI_ALGORITHM: &str = "SDK-HMAC-SHA256";

#[derive(Clone)]
pub struct HuaweiCloudProvider {
    client: HttpClientBuilder,
    access_key: String,
    secret_key: String,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecordSetBody<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    rr_type: &'a str,
    ttl: u32,
    records: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
}

#[derive(Serialize, Debug)]
struct UpdateRecordSetBody<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    rr_type: &'a str,
    ttl: u32,
    records: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
}

#[derive(Deserialize, Debug)]
struct CreateRecordSetResponse {}

#[derive(Deserialize, Debug)]
struct ListZonesResponse {
    #[serde(default)]
    zones: Vec<HuaweiZone>,
}

#[derive(Deserialize, Debug)]
struct HuaweiZone {
    id: String,
    name: String,
}

#[derive(Deserialize, Debug)]
struct ListRecordSetsResponse {
    #[serde(default)]
    recordsets: Vec<HuaweiRecordSet>,
}

#[derive(Deserialize, Debug)]
struct HuaweiRecordSet {
    id: String,
    name: String,
    #[serde(rename = "type")]
    rr_type: String,
}

impl HuaweiCloudProvider {
    pub(crate) fn new(
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        region: impl Into<String>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let access_key = access_key.into();
        let secret_key = secret_key.into();
        let region = region.into();

        if access_key.is_empty() || secret_key.is_empty() || region.is_empty() {
            return Err(Error::Api("huaweicloud: credentials missing".to_string()));
        }

        let endpoint = format!("https://dns.{}.myhuaweicloud.com", region);
        let client = HttpClientBuilder::default().with_timeout(timeout);

        Ok(Self {
            client,
            access_key,
            secret_key,
            endpoint,
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
        let value = render_record(&record)?;
        let name_fqdn = ensure_fqdn(&name.into_name());
        let zone_id = self.resolve_zone_id(origin).await?;
        let rr_type = record.as_type().as_str();

        let body = serde_json::to_string(&CreateRecordSetBody {
            name: &name_fqdn,
            rr_type,
            ttl,
            records: vec![value],
            description: None,
        })
        .map_err(|err| Error::Serialize(err.to_string()))?;

        let path = format!("/v2/zones/{}/recordsets", zone_id);
        let _: CreateRecordSetResponse = self
            .send_signed(Method::POST, &path, "", Some(body))
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
        let value = render_record(&record)?;
        let name_fqdn = ensure_fqdn(&name.into_name());
        let zone_id = self.resolve_zone_id(origin).await?;
        let rr_type = record.as_type();
        let recordset_id = self
            .find_recordset_id(&zone_id, &name_fqdn, rr_type.as_str())
            .await?;

        let body = serde_json::to_string(&UpdateRecordSetBody {
            name: &name_fqdn,
            rr_type: rr_type.as_str(),
            ttl,
            records: vec![value],
            description: None,
        })
        .map_err(|err| Error::Serialize(err.to_string()))?;

        let path = format!("/v2/zones/{}/recordsets/{}", zone_id, recordset_id);
        let _ = self.send_signed_raw(Method::PUT, &path, "", Some(body)).await?;
        Ok(())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name_fqdn = ensure_fqdn(&name.into_name());
        let zone_id = self.resolve_zone_id(origin).await?;
        let recordset_id = self
            .find_recordset_id(&zone_id, &name_fqdn, record_type.as_str())
            .await?;

        let path = format!("/v2/zones/{}/recordsets/{}", zone_id, recordset_id);
        let _ = self.send_signed_raw(Method::DELETE, &path, "", None).await?;
        Ok(())
    }

    async fn resolve_zone_id(&self, origin: impl IntoFqdn<'_>) -> crate::Result<String> {
        let zone_name = ensure_fqdn(&origin.into_name());
        let query = format!("name={}", zone_name);
        let response: ListZonesResponse = self
            .send_signed(Method::GET, "/v2/zones", &query, None)
            .await?;

        response
            .zones
            .into_iter()
            .find(|z| z.name.trim_end_matches('.') == zone_name.trim_end_matches('.'))
            .map(|z| z.id)
            .ok_or_else(|| Error::Api(format!("huaweicloud: zone {} not found", zone_name)))
    }

    async fn find_recordset_id(
        &self,
        zone_id: &str,
        name_fqdn: &str,
        rr_type: &str,
    ) -> crate::Result<String> {
        let query = format!("name={}&type={}", name_fqdn, rr_type);
        let path = format!("/v2/zones/{}/recordsets", zone_id);
        let response: ListRecordSetsResponse =
            self.send_signed(Method::GET, &path, &query, None).await?;

        response
            .recordsets
            .into_iter()
            .find(|r| {
                r.name.trim_end_matches('.') == name_fqdn.trim_end_matches('.')
                    && r.rr_type == rr_type
            })
            .map(|r| r.id)
            .ok_or_else(|| {
                Error::Api(format!(
                    "huaweicloud: recordset {} of type {} not found",
                    name_fqdn, rr_type
                ))
            })
    }

    async fn send_signed<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &str,
        body: Option<String>,
    ) -> crate::Result<T> {
        let text = self.send_signed_raw(method, path, query, body).await?;
        if text.is_empty() {
            serde_json::from_str("{}")
                .map_err(|err| Error::Serialize(format!("Failed to deserialize empty: {err}")))
        } else {
            serde_json::from_str(&text)
                .map_err(|err| Error::Serialize(format!("Failed to deserialize: {err}")))
        }
    }

    async fn send_signed_raw(
        &self,
        method: Method,
        path: &str,
        query: &str,
        body: Option<String>,
    ) -> crate::Result<String> {
        let canonical_uri = canonicalize_path(path);
        let url = if query.is_empty() {
            format!("{}{}", self.endpoint, canonical_uri)
        } else {
            format!("{}{}?{}", self.endpoint, canonical_uri, query)
        };

        let host = host_from_endpoint(&self.endpoint);
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        let body_str = body.as_deref().unwrap_or("");
        let payload_hash = hex::encode(sha256_digest(body_str.as_bytes()));

        let canonical_query = canonical_query_string(query);

        let canonical_headers = format!(
            "content-type:application/json\nhost:{}\nx-sdk-date:{}\n",
            host, amz_date
        );
        let signed_headers = "content-type;host;x-sdk-date";

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash
        );

        let string_to_sign = format!(
            "{}\n{}\n{}",
            HUAWEI_ALGORITHM,
            amz_date,
            hex::encode(sha256_digest(canonical_request.as_bytes()))
        );

        let signature = hex::encode(hmac_sha256(
            self.secret_key.as_bytes(),
            string_to_sign.as_bytes(),
        ));

        let authorization = format!(
            "{} Access={}, SignedHeaders={}, Signature={}",
            HUAWEI_ALGORITHM, self.access_key, signed_headers, signature
        );

        let mut http: HttpClient = self
            .client
            .build(method, url)
            .with_header("Host", host)
            .with_header("X-Sdk-Date", &amz_date)
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

fn canonicalize_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{}/", path)
    }
}

fn canonical_query_string(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut parts: Vec<(String, String)> = query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next().unwrap_or("").to_string();
            let v = it.next().unwrap_or("").to_string();
            (uri_encode(&k, true), uri_encode(&v, true))
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

fn ensure_fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    }
}

fn render_record(record: &DnsRecord) -> crate::Result<String> {
    match record {
        DnsRecord::A(addr) => Ok(addr.to_string()),
        DnsRecord::AAAA(addr) => Ok(addr.to_string()),
        DnsRecord::CNAME(name) => Ok(ensure_fqdn(name)),
        DnsRecord::NS(name) => Ok(ensure_fqdn(name)),
        DnsRecord::MX(mx) => Ok(format!("{} {}", mx.priority, ensure_fqdn(&mx.exchange))),
        DnsRecord::TXT(text) => Ok(format!("\"{}\"", text.replace('\"', "\\\""))),
        DnsRecord::SRV(srv) => Ok(format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            ensure_fqdn(&srv.target)
        )),
        DnsRecord::CAA(caa) => Ok(caa.clone().to_string()),
        DnsRecord::TLSA(_) => Err(Error::Api(
            "TLSA records are not supported by huaweicloud".to_string(),
        )),
    }
}
