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
    DnsRecord, DnsRecordType, Error, IntoFqdn, crypto::hmac_sha256, http::HttpClientBuilder,
    utils::strip_origin_from_name,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api-ch-gva-2.exoscale.com/v2";
const SIGNATURE_EXPIRES_SECONDS: i64 = 300;

#[derive(Clone)]
pub struct ExoscaleProvider {
    client: HttpClientBuilder,
    api_key: String,
    api_secret: String,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecordRequest<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'static str,
    content: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
}

#[derive(Deserialize, Debug)]
struct DnsDomain {
    id: String,
    #[serde(rename = "unicode-name", default)]
    unicode_name: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize, Debug)]
struct DomainList {
    #[serde(rename = "dns-domains", default)]
    dns_domains: Vec<DnsDomain>,
}

#[derive(Deserialize, Debug)]
struct DnsRecordResponse {
    id: String,
    name: String,
    #[serde(rename = "type", default)]
    record_type: String,
}

#[derive(Deserialize, Debug)]
struct RecordList {
    #[serde(rename = "dns-domain-records", default)]
    records: Vec<DnsRecordResponse>,
}

impl ExoscaleProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        api_secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        let api_secret = api_secret.as_ref();
        if api_key.is_empty() || api_secret.is_empty() {
            return Err(Error::Api("Exoscale credentials missing".into()));
        }
        let client = HttpClientBuilder::default().with_timeout(timeout);
        Ok(Self {
            client,
            api_key: api_key.to_string(),
            api_secret: api_secret.to_string(),
            endpoint: DEFAULT_ENDPOINT.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    fn build_authorization(&self, method: &Method, path: &str, body: &str) -> String {
        let expires = Utc::now().timestamp() + SIGNATURE_EXPIRES_SECONDS;
        let signing_string = format!("{} {}\n\n{}\n\n{}", method.as_str(), path, body, expires);
        let signature = hmac_sha256(self.api_secret.as_bytes(), signing_string.as_bytes());
        let signature_b64 = BASE64_STANDARD.encode(&signature);
        format!(
            "EXO2-HMAC-SHA256 credential={},expires={},signature={}",
            self.api_key, expires, signature_b64
        )
    }

    fn signed(
        &self,
        request: crate::http::HttpClient,
        method: Method,
        path: &str,
        body: &str,
    ) -> crate::http::HttpClient {
        let auth = self.build_authorization(&method, path, body);
        request.with_header("Authorization", auth)
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let zone_id = self.obtain_zone_id(&domain).await?;
        let body = build_create_record(&subdomain, &record, ttl)?;
        let body_str = serde_json::to_string(&body)
            .map_err(|e| Error::Serialize(format!("body serialization failed: {e}")))?;
        let path = format!("/dns-domain/{}/record", zone_id);
        let url = format!("{}{}", self.endpoint, path);
        self.signed(
            self.client.post(url).with_raw_body(body_str.clone()),
            Method::POST,
            &path,
            &body_str,
        )
        .send_raw()
        .await
        .map(|_| ())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let zone_id = self.obtain_zone_id(&domain).await?;
        let record_type = record.as_type();
        let record_id = self
            .find_record_id(&zone_id, &subdomain, record_type)
            .await?
            .ok_or_else(|| {
                Error::Api(format!(
                    "Exoscale record {} of type {} not found",
                    subdomain,
                    record_type.as_str()
                ))
            })?;
        let body = build_create_record(&subdomain, &record, ttl)?;
        let body_str = serde_json::to_string(&body)
            .map_err(|e| Error::Serialize(format!("body serialization failed: {e}")))?;
        let path = format!("/dns-domain/{}/record/{}", zone_id, record_id);
        let url = format!("{}{}", self.endpoint, path);
        self.signed(
            self.client.put(url).with_raw_body(body_str.clone()),
            Method::PUT,
            &path,
            &body_str,
        )
        .send_raw()
        .await
        .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let zone_id = self.obtain_zone_id(&domain).await?;
        let record_id = self
            .find_record_id(&zone_id, &subdomain, record_type)
            .await?
            .ok_or(Error::NotFound)?;
        let path = format!("/dns-domain/{}/record/{}", zone_id, record_id);
        let url = format!("{}{}", self.endpoint, path);
        self.signed(self.client.delete(url), Method::DELETE, &path, "")
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn obtain_zone_id(&self, domain: &str) -> crate::Result<String> {
        let path = "/dns-domain";
        let url = format!("{}{}", self.endpoint, path);
        let response: DomainList = self
            .signed(self.client.get(url), Method::GET, path, "")
            .send()
            .await?;
        response
            .dns_domains
            .into_iter()
            .find(|d| {
                d.unicode_name == domain || d.name.as_deref() == Some(domain)
            })
            .map(|d| d.id)
            .ok_or_else(|| Error::Api(format!("Exoscale domain {} not found", domain)))
    }

    async fn find_record_id(
        &self,
        zone_id: &str,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Option<String>> {
        let path = format!("/dns-domain/{}/record", zone_id);
        let url = format!("{}{}", self.endpoint, path);
        let response: RecordList = self
            .signed(self.client.get(url), Method::GET, &path, "")
            .send()
            .await?;
        let type_str = record_type.as_str();
        Ok(response
            .records
            .into_iter()
            .find(|r| r.name == subdomain && r.record_type == type_str)
            .map(|r| r.id))
    }
}

fn build_create_record<'a>(
    name: &'a str,
    record: &DnsRecord,
    ttl: u32,
) -> crate::Result<CreateRecordRequest<'a>> {
    let mut req = CreateRecordRequest {
        name,
        record_type: dns_type(record)?,
        content: String::new(),
        ttl,
        priority: None,
    };
    match record {
        DnsRecord::A(addr) => req.content = addr.to_string(),
        DnsRecord::AAAA(addr) => req.content = addr.to_string(),
        DnsRecord::CNAME(target) => req.content = target.clone(),
        DnsRecord::NS(target) => req.content = target.clone(),
        DnsRecord::MX(mx) => {
            req.content = mx.exchange.clone();
            req.priority = Some(mx.priority);
        }
        DnsRecord::TXT(text) => {
            req.content = format!("\"{}\"", text.replace('\"', "\\\""));
        }
        DnsRecord::SRV(srv) => {
            req.content = format!("{} {} {}", srv.weight, srv.port, srv.target);
            req.priority = Some(srv.priority);
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Exoscale".into(),
            ));
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            req.content = format!("{} {} \"{}\"", flags, tag, value);
        }
    }
    Ok(req)
}

fn dns_type(record: &DnsRecord) -> crate::Result<&'static str> {
    match record {
        DnsRecord::A(_) => Ok("A"),
        DnsRecord::AAAA(_) => Ok("AAAA"),
        DnsRecord::CNAME(_) => Ok("CNAME"),
        DnsRecord::NS(_) => Ok("NS"),
        DnsRecord::MX(_) => Ok("MX"),
        DnsRecord::TXT(_) => Ok("TXT"),
        DnsRecord::SRV(_) => Ok("SRV"),
        DnsRecord::CAA(_) => Ok("CAA"),
        DnsRecord::TLSA(_) => Err(Error::Api(
            "TLSA records are not supported by Exoscale".into(),
        )),
    }
}
