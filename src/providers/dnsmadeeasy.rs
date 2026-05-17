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
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_PROD_ENDPOINT: &str = "https://api.dnsmadeeasy.com/V2.0";

#[derive(Clone)]
pub struct DnsMadeEasyProvider {
    client: HttpClientBuilder,
    api_key: String,
    api_secret: String,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct CreateRecordRequest<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    name: &'a str,
    value: String,
    ttl: u32,
    #[serde(rename = "mxLevel", skip_serializing_if = "Option::is_none")]
    mx_level: Option<u16>,
    #[serde(rename = "priority", skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(rename = "weight", skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(rename = "port", skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(rename = "issuerCritical", skip_serializing_if = "Option::is_none")]
    issuer_critical: Option<u8>,
    #[serde(rename = "caaType", skip_serializing_if = "Option::is_none")]
    caa_type: Option<String>,
}

#[derive(Deserialize, Debug)]
struct DomainRecord {
    id: i64,
}

#[derive(Deserialize, Debug)]
struct RecordList {
    data: Vec<DomainRecord>,
}

#[derive(Deserialize, Debug)]
struct DomainInfo {
    id: i64,
}

impl DnsMadeEasyProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        api_secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        let api_secret = api_secret.as_ref();
        if api_key.is_empty() || api_secret.is_empty() {
            return Err(Error::Api("DNSMadeEasy credentials missing".into()));
        }
        let client = HttpClientBuilder::default()
            .with_header("Accept", "application/json")
            .with_timeout(timeout);
        Ok(Self {
            client,
            api_key: api_key.to_string(),
            api_secret: api_secret.to_string(),
            endpoint: DEFAULT_PROD_ENDPOINT.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    fn signed_request(&self, request: crate::http::HttpClient) -> crate::http::HttpClient {
        let timestamp = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let signature = hex::encode(hmac_sha1(self.api_secret.as_bytes(), timestamp.as_bytes()));
        request
            .with_header("x-dnsme-apiKey", &self.api_key)
            .with_header("x-dnsme-requestDate", &timestamp)
            .with_header("x-dnsme-hmac", &signature)
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
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let domain_id = self.obtain_domain_id(&domain).await?;

        let body = build_create_request(&subdomain, &record, ttl)?;
        self.signed_request(
            self.client
                .post(format!("{}/dns/managed/{domain_id}/records", self.endpoint))
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
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let domain_id = self.obtain_domain_id(&domain).await?;
        let record_type = record.as_type();
        let record_ids = self
            .find_record_ids(domain_id, &subdomain, record_type)
            .await?;
        if record_ids.is_empty() {
            return Err(Error::Api(format!(
                "DNSMadeEasy record {} of type {} not found",
                subdomain,
                record_type.as_str()
            )));
        }

        let body = build_create_request(&subdomain, &record, ttl)?;
        for record_id in record_ids {
            self.signed_request(
                self.client
                    .delete(format!(
                        "{}/dns/managed/{domain_id}/records/{record_id}",
                        self.endpoint
                    )),
            )
            .send_raw()
            .await
            .map(|_| ())?;
        }
        self.signed_request(
            self.client
                .post(format!("{}/dns/managed/{domain_id}/records", self.endpoint))
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
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let domain_id = self.obtain_domain_id(&domain).await?;
        let record_ids = self
            .find_record_ids(domain_id, &subdomain, record_type)
            .await?;
        if record_ids.is_empty() {
            return Err(Error::NotFound);
        }
        for record_id in record_ids {
            self.signed_request(self.client.delete(format!(
                "{}/dns/managed/{domain_id}/records/{record_id}",
                self.endpoint
            )))
            .send_raw()
            .await
            .map(|_| ())?;
        }
        Ok(())
    }

    async fn obtain_domain_id(&self, domain: &str) -> crate::Result<i64> {
        let url = format!(
            "{}/dns/managed/name?domainname={}",
            self.endpoint,
            urlencode(domain)
        );
        let info: DomainInfo = self
            .signed_request(self.client.get(url))
            .send_with_retry(3)
            .await?;
        Ok(info.id)
    }

    async fn find_record_ids(
        &self,
        domain_id: i64,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<i64>> {
        let url = format!(
            "{}/dns/managed/{}/records?recordName={}&type={}",
            self.endpoint,
            domain_id,
            urlencode(subdomain),
            record_type.as_str()
        );
        let list: RecordList = self
            .signed_request(self.client.get(url))
            .send_with_retry(3)
            .await?;
        Ok(list.data.into_iter().map(|r| r.id).collect())
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

fn build_create_request<'a>(
    name: &'a str,
    record: &DnsRecord,
    ttl: u32,
) -> crate::Result<CreateRecordRequest<'a>> {
    let mut request = CreateRecordRequest {
        record_type: dns_type(record)?,
        name,
        value: String::new(),
        ttl,
        mx_level: None,
        priority: None,
        weight: None,
        port: None,
        issuer_critical: None,
        caa_type: None,
    };
    match record {
        DnsRecord::A(addr) => request.value = addr.to_string(),
        DnsRecord::AAAA(addr) => request.value = addr.to_string(),
        DnsRecord::CNAME(target) => request.value = target.clone(),
        DnsRecord::NS(target) => request.value = target.clone(),
        DnsRecord::MX(mx) => {
            request.value = mx.exchange.clone();
            request.mx_level = Some(mx.priority);
        }
        DnsRecord::TXT(text) => {
            request.value = text.clone();
        }
        DnsRecord::SRV(srv) => {
            request.value = srv.target.clone();
            request.priority = Some(srv.priority);
            request.weight = Some(srv.weight);
            request.port = Some(srv.port);
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by DNSMadeEasy".into(),
            ));
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            request.value = value;
            request.issuer_critical = Some(flags);
            request.caa_type = Some(tag);
        }
    }
    Ok(request)
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
            "TLSA records are not supported by DNSMadeEasy".into(),
        )),
    }
}
