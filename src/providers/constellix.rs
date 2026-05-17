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
    DnsRecord, DnsRecordType, Error, IntoFqdn, crypto::hmac_sha1, http::HttpClientBuilder,
    utils::strip_origin_from_name,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api.dns.constellix.com";
const API_VERSION: &str = "v1";

#[derive(Clone)]
pub struct ConstellixProvider {
    client: HttpClientBuilder,
    api_key: String,
    secret_key: String,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecordRequest<'a> {
    name: &'a str,
    ttl: u32,
    #[serde(rename = "roundRobin")]
    round_robin: Vec<RoundRobinValue>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RoundRobinValue {
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(rename = "priority", skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(rename = "level", skip_serializing_if = "Option::is_none")]
    level: Option<u16>,
    #[serde(rename = "weight", skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(rename = "port", skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(rename = "host", skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(rename = "caaType", skip_serializing_if = "Option::is_none")]
    caa_type: Option<String>,
    #[serde(rename = "flags", skip_serializing_if = "Option::is_none")]
    flags: Option<u8>,
    #[serde(rename = "tag", skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ConstellixDomain {
    id: i64,
}

#[derive(Deserialize, Debug)]
struct ConstellixRecord {
    id: i64,
}

impl ConstellixProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        secret_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        let secret_key = secret_key.as_ref();
        if api_key.is_empty() || secret_key.is_empty() {
            return Err(Error::Api("Constellix credentials missing".into()));
        }
        let client = HttpClientBuilder::default()
            .with_header("Accept", "application/json")
            .with_timeout(timeout);
        Ok(Self {
            client,
            api_key: api_key.to_string(),
            secret_key: secret_key.to_string(),
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

    fn security_token(&self) -> String {
        let timestamp = Utc::now().timestamp_millis();
        let timestamp_str = timestamp.to_string();
        let mac = hmac_sha1(self.secret_key.as_bytes(), timestamp_str.as_bytes());
        let encoded = BASE64_STANDARD.encode(&mac);
        format!("{}:{}:{}", self.api_key, encoded, timestamp_str)
    }

    fn signed(&self, request: crate::http::HttpClient) -> crate::http::HttpClient {
        request.with_header("x-cns-security-token", self.security_token())
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
        let record_type = record.as_type();
        let type_segment = record_type_segment(record_type)?;
        let domain_id = self.obtain_domain_id(&domain).await?;

        let body = CreateRecordRequest {
            name: &subdomain,
            ttl,
            round_robin: vec![record_to_round_robin(&record)?],
        };

        self.signed(
            self.client
                .post(format!(
                    "{}/{}/domains/{}/records/{}",
                    self.endpoint, API_VERSION, domain_id, type_segment
                ))
                .with_body(body)?,
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
        let record_type = record.as_type();
        let type_segment = record_type_segment(record_type)?;
        let domain_id = self.obtain_domain_id(&domain).await?;
        let record_id = self
            .find_record_id(domain_id, type_segment, &subdomain)
            .await?
            .ok_or_else(|| {
                Error::Api(format!(
                    "Constellix record {} of type {} not found",
                    subdomain,
                    record_type.as_str()
                ))
            })?;

        let body = CreateRecordRequest {
            name: &subdomain,
            ttl,
            round_robin: vec![record_to_round_robin(&record)?],
        };
        self.signed(
            self.client
                .put(format!(
                    "{}/{}/domains/{}/records/{}/{}",
                    self.endpoint, API_VERSION, domain_id, type_segment, record_id
                ))
                .with_body(body)?,
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
        let type_segment = record_type_segment(record_type)?;
        let domain_id = self.obtain_domain_id(&domain).await?;
        let record_id = self
            .find_record_id(domain_id, type_segment, &subdomain)
            .await?
            .ok_or(Error::NotFound)?;
        self.signed(self.client.delete(format!(
            "{}/{}/domains/{}/records/{}/{}",
            self.endpoint, API_VERSION, domain_id, type_segment, record_id
        )))
        .send_raw()
        .await
        .map(|_| ())
    }

    async fn obtain_domain_id(&self, domain: &str) -> crate::Result<i64> {
        let url = format!(
            "{}/{}/domains/search?exact={}",
            self.endpoint,
            API_VERSION,
            urlencode(domain)
        );
        let domains: Vec<ConstellixDomain> = self.signed(self.client.get(url)).send().await?;
        domains.into_iter().next().map(|d| d.id).ok_or_else(|| {
            Error::Api(format!("Constellix domain {} not found", domain))
        })
    }

    async fn find_record_id(
        &self,
        domain_id: i64,
        type_segment: &str,
        subdomain: &str,
    ) -> crate::Result<Option<i64>> {
        let url = format!(
            "{}/{}/domains/{}/records/{}/search?exact={}",
            self.endpoint,
            API_VERSION,
            domain_id,
            type_segment,
            urlencode(subdomain)
        );
        let records: Vec<ConstellixRecord> = self.signed(self.client.get(url)).send().await?;
        Ok(records.into_iter().next().map(|r| r.id))
    }
}

fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let c = *byte as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

fn record_type_segment(record_type: DnsRecordType) -> crate::Result<&'static str> {
    match record_type {
        DnsRecordType::A => Ok("a"),
        DnsRecordType::AAAA => Ok("aaaa"),
        DnsRecordType::CNAME => Ok("cname"),
        DnsRecordType::NS => Ok("ns"),
        DnsRecordType::MX => Ok("mx"),
        DnsRecordType::TXT => Ok("txt"),
        DnsRecordType::SRV => Ok("srv"),
        DnsRecordType::CAA => Ok("caa"),
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by Constellix".into(),
        )),
    }
}

fn record_to_round_robin(record: &DnsRecord) -> crate::Result<RoundRobinValue> {
    let mut value = RoundRobinValue {
        value: None,
        priority: None,
        level: None,
        weight: None,
        port: None,
        host: None,
        caa_type: None,
        flags: None,
        tag: None,
    };
    match record {
        DnsRecord::A(addr) => value.value = Some(addr.to_string()),
        DnsRecord::AAAA(addr) => value.value = Some(addr.to_string()),
        DnsRecord::CNAME(target) => value.host = Some(target.clone()),
        DnsRecord::NS(target) => value.host = Some(target.clone()),
        DnsRecord::MX(mx) => {
            value.value = Some(mx.exchange.clone());
            value.level = Some(mx.priority);
        }
        DnsRecord::TXT(text) => {
            value.value = Some(format!("\"{}\"", text.replace('\"', "\\\"")));
        }
        DnsRecord::SRV(srv) => {
            value.host = Some(srv.target.clone());
            value.priority = Some(srv.priority);
            value.weight = Some(srv.weight);
            value.port = Some(srv.port);
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Constellix".into(),
            ));
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, val) = caa.clone().decompose();
            value.value = Some(val);
            value.flags = Some(flags);
            value.tag = Some(tag);
        }
    }
    Ok(value)
}
