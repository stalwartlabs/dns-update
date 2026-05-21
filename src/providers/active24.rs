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
use chrono::{SecondsFormat, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://rest.active24.cz";

#[derive(Clone)]
pub struct Active24Provider {
    client: HttpClientBuilder,
    api_key: String,
    secret: String,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecord<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    name: &'a str,
    content: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flags: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
}

#[derive(Deserialize, Debug)]
struct Active24Record {
    id: i64,
    #[serde(rename = "type")]
    record_type: String,
    name: String,
}

#[derive(Deserialize, Debug)]
struct RecordResponse {
    data: Vec<Active24Record>,
}

#[derive(Deserialize, Debug)]
struct Service {
    id: i64,
    #[serde(rename = "serviceName", default)]
    service_name: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize, Debug)]
struct ServicesResponse {
    items: Vec<Service>,
}

impl Active24Provider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        let secret = secret.as_ref();
        if api_key.is_empty() || secret.is_empty() {
            return Err(Error::Api("Active24 credentials missing".into()));
        }
        let client = HttpClientBuilder::default()
            .with_header("Accept", "application/json")
            .with_header("Accept-Language", "en_us")
            .with_timeout(timeout);
        Ok(Self {
            client,
            api_key: api_key.to_string(),
            secret: secret.to_string(),
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

    fn signed(
        &self,
        request: crate::http::HttpClient,
        method: Method,
        path: &str,
    ) -> crate::http::HttpClient {
        let now = Utc::now();
        let timestamp = now.timestamp();
        let date = now.to_rfc3339_opts(SecondsFormat::Secs, true);
        let canonical = format!("{} {} {}", method.as_str(), path, timestamp);
        let signature = hex::encode(hmac_sha1(self.secret.as_bytes(), canonical.as_bytes()));
        let basic = BASE64_STANDARD.encode(format!("{}:{}", self.api_key, signature));
        request
            .with_header("Authorization", format!("Basic {}", basic))
            .with_header("Date", date)
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
        let service_id = self.obtain_service_id(&domain).await?;
        let path = format!("/v2/service/{}/dns/record", service_id);
        let body = build_create_record(&subdomain, &record, ttl)?;
        let url = format!("{}{}", self.endpoint, path);
        self.signed(self.client.post(url).with_body(body)?, Method::POST, &path)
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
        let service_id = self.obtain_service_id(&domain).await?;
        let record_type = record.as_type();
        let record_ids = self
            .find_record_ids(service_id, &subdomain, record_type)
            .await?;
        if record_ids.is_empty() {
            return Err(Error::Api(format!(
                "Active24 record {} of type {} not found",
                subdomain,
                record_type.as_str()
            )));
        }
        for id in record_ids {
            let path = format!("/v2/service/{}/dns/record/{}", service_id, id);
            let url = format!("{}{}", self.endpoint, path);
            self.signed(self.client.delete(url), Method::DELETE, &path)
                .send_raw()
                .await?;
        }
        let path = format!("/v2/service/{}/dns/record", service_id);
        let body = build_create_record(&subdomain, &record, ttl)?;
        let url = format!("{}{}", self.endpoint, path);
        self.signed(self.client.post(url).with_body(body)?, Method::POST, &path)
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
        let service_id = self.obtain_service_id(&domain).await?;
        let record_ids = self
            .find_record_ids(service_id, &subdomain, record_type)
            .await?;
        if record_ids.is_empty() {
            return Err(Error::NotFound);
        }
        for id in record_ids {
            let path = format!("/v2/service/{}/dns/record/{}", service_id, id);
            let url = format!("{}{}", self.endpoint, path);
            self.signed(self.client.delete(url), Method::DELETE, &path)
                .send_raw()
                .await?;
        }
        Ok(())
    }

    async fn obtain_service_id(&self, domain: &str) -> crate::Result<i64> {
        let path = "/v1/user/self/service";
        let url = format!("{}{}", self.endpoint, path);
        let response: ServicesResponse = self
            .signed(self.client.get(url), Method::GET, path)
            .send()
            .await?;
        response
            .items
            .into_iter()
            .find(|s| s.service_name == "domain" && s.name == domain)
            .map(|s| s.id)
            .ok_or_else(|| Error::Api(format!("Active24 domain service {} not found", domain)))
    }

    async fn find_record_ids(
        &self,
        service_id: i64,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<i64>> {
        let path = format!("/v2/service/{}/dns/record", service_id);
        let url = format!("{}{}", self.endpoint, path);
        let response: RecordResponse = self
            .signed(self.client.get(url), Method::GET, &path)
            .send()
            .await?;
        let type_str = record_type.as_str();
        Ok(response
            .data
            .into_iter()
            .filter(|r| r.name == subdomain && r.record_type == type_str)
            .map(|r| r.id)
            .collect())
    }
}

fn build_create_record<'a>(
    name: &'a str,
    record: &DnsRecord,
    ttl: u32,
) -> crate::Result<CreateRecord<'a>> {
    let mut req = CreateRecord {
        record_type: dns_type(record)?,
        name,
        content: String::new(),
        ttl,
        priority: None,
        port: None,
        weight: None,
        flags: None,
        tag: None,
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
        DnsRecord::TXT(text) => req.content = text.clone(),
        DnsRecord::SRV(srv) => {
            req.content = srv.target.clone();
            req.priority = Some(srv.priority);
            req.port = Some(srv.port);
            req.weight = Some(srv.weight);
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Active24".into(),
            ));
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            req.content = value;
            req.flags = Some(flags);
            req.tag = Some(tag);
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
            "TLSA records are not supported by Active24".into(),
        )),
    }
}
