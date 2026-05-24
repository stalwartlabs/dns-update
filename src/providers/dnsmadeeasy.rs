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
    crypto::hmac_sha1, http::HttpClientBuilder, utils::strip_origin_from_name,
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
struct ListedRecord {
    id: i64,
    #[serde(rename = "type")]
    record_type: String,
    value: String,
    #[serde(default, rename = "mxLevel")]
    mx_level: u16,
    #[serde(default)]
    priority: u16,
    #[serde(default)]
    weight: u16,
    #[serde(default)]
    port: u16,
    #[serde(default, rename = "caaType")]
    caa_type: String,
    #[serde(default, rename = "issuerCritical")]
    issuer_critical: u8,
}

#[derive(Deserialize, Debug)]
struct ListedRecordPage {
    data: Vec<ListedRecord>,
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

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        ensure_supported_type(record_type)?;

        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let domain_id = self.obtain_domain_id(&domain).await?;

        let existing = self.list_at(domain_id, &subdomain, record_type).await?;

        if records.is_empty() {
            let ids: Vec<i64> = existing.into_iter().map(|r| r.id).collect();
            self.bulk_delete(domain_id, &ids).await?;
            return Ok(());
        }

        let desired_bodies: Vec<CreateRecordRequest<'_>> = records
            .iter()
            .map(|r| build_create_request(&subdomain, r, ttl))
            .collect::<crate::Result<Vec<_>>>()?;

        let mut to_add: Vec<&CreateRecordRequest<'_>> = Vec::new();
        let mut existing_pool: Vec<ListedRecord> = existing;
        for body in &desired_bodies {
            if let Some(idx) = existing_pool
                .iter()
                .position(|listed| listed_matches_body(listed, body))
            {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(body);
            }
        }

        let to_delete_ids: Vec<i64> = existing_pool.into_iter().map(|r| r.id).collect();
        self.bulk_delete(domain_id, &to_delete_ids).await?;
        self.bulk_create(domain_id, &to_add).await?;
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
        ensure_supported_type(record_type)?;
        if records.is_empty() {
            return Ok(());
        }

        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let domain_id = self.obtain_domain_id(&domain).await?;

        let existing = self.list_at(domain_id, &subdomain, record_type).await?;

        let desired_bodies: Vec<CreateRecordRequest<'_>> = records
            .iter()
            .map(|r| build_create_request(&subdomain, r, ttl))
            .collect::<crate::Result<Vec<_>>>()?;

        let to_add: Vec<&CreateRecordRequest<'_>> = desired_bodies
            .iter()
            .filter(|body| {
                !existing
                    .iter()
                    .any(|listed| listed_matches_body(listed, body))
            })
            .collect();

        self.bulk_create(domain_id, &to_add).await?;
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
        ensure_supported_type(record_type)?;
        if records.is_empty() {
            return Ok(());
        }

        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let domain_id = self.obtain_domain_id(&domain).await?;

        let existing = self.list_at(domain_id, &subdomain, record_type).await?;

        let to_remove_bodies: Vec<CreateRecordRequest<'_>> = records
            .iter()
            .map(|r| build_create_request(&subdomain, r, 0))
            .collect::<crate::Result<Vec<_>>>()?;

        let ids: Vec<i64> = existing
            .iter()
            .filter(|listed| {
                to_remove_bodies
                    .iter()
                    .any(|body| listed_matches_body(listed, body))
            })
            .map(|r| r.id)
            .collect();

        self.bulk_delete(domain_id, &ids).await?;
        Ok(())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        ensure_supported_type(record_type)?;
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, None);
        let domain_id = self.obtain_domain_id(&domain).await?;
        let listed = self.list_at(domain_id, &subdomain, record_type).await?;
        listed
            .into_iter()
            .map(|r| listed_to_record(record_type, r))
            .collect()
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

    async fn list_at(
        &self,
        domain_id: i64,
        subdomain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ListedRecord>> {
        let url = format!(
            "{}/dns/managed/{}/records?recordName={}&type={}",
            self.endpoint,
            domain_id,
            urlencode(subdomain),
            record_type.as_str()
        );
        let page: ListedRecordPage = self
            .signed_request(self.client.get(url))
            .send_with_retry(3)
            .await?;
        Ok(page.data)
    }

    async fn bulk_create(
        &self,
        domain_id: i64,
        bodies: &[&CreateRecordRequest<'_>],
    ) -> crate::Result<()> {
        if bodies.is_empty() {
            return Ok(());
        }
        self.signed_request(
            self.client
                .post(format!(
                    "{}/dns/managed/{domain_id}/records/createMulti",
                    self.endpoint
                ))
                .with_body(bodies)?,
        )
        .send_raw()
        .await
        .map(|_| ())
    }

    async fn bulk_delete(&self, domain_id: i64, ids: &[i64]) -> crate::Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let query = ids
            .iter()
            .map(|id| format!("ids={id}"))
            .collect::<Vec<_>>()
            .join("&");
        self.signed_request(self.client.delete(format!(
            "{}/dns/managed/{domain_id}/records?{query}",
            self.endpoint
        )))
        .send_raw()
        .await
        .map(|_| ())
    }
}

fn check_record_types(expected_type: DnsRecordType, records: &[DnsRecord]) -> crate::Result<()> {
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
    }
    Ok(())
}

fn ensure_supported_type(record_type: DnsRecordType) -> crate::Result<()> {
    if record_type == DnsRecordType::TLSA {
        return Err(Error::Api(
            "TLSA records are not supported by DNSMadeEasy".into(),
        ));
    }
    Ok(())
}

fn listed_matches_body(listed: &ListedRecord, body: &CreateRecordRequest<'_>) -> bool {
    if listed.record_type != body.record_type {
        return false;
    }
    if !values_equal(body.record_type, &listed.value, &body.value) {
        return false;
    }
    match body.record_type {
        "MX" => Some(listed.mx_level) == body.mx_level,
        "SRV" => {
            Some(listed.priority) == body.priority
                && Some(listed.weight) == body.weight
                && Some(listed.port) == body.port
        }
        "CAA" => {
            Some(listed.issuer_critical) == body.issuer_critical
                && body.caa_type.as_deref() == Some(listed.caa_type.as_str())
        }
        _ => true,
    }
}

fn values_equal(record_type: &str, a: &str, b: &str) -> bool {
    match record_type {
        "CNAME" | "NS" | "MX" | "SRV" => normalize_dot(a) == normalize_dot(b),
        _ => a == b,
    }
}

fn normalize_dot(value: &str) -> &str {
    value.strip_suffix('.').unwrap_or(value)
}

fn listed_to_record(
    expected_type: DnsRecordType,
    listed: ListedRecord,
) -> crate::Result<DnsRecord> {
    match expected_type {
        DnsRecordType::A => listed
            .value
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A record value: {e}"))),
        DnsRecordType::AAAA => listed
            .value
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA record value: {e}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(listed.value)),
        DnsRecordType::NS => Ok(DnsRecord::NS(listed.value)),
        DnsRecordType::MX => Ok(DnsRecord::MX(MXRecord {
            exchange: listed.value,
            priority: listed.mx_level,
        })),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(listed.value)),
        DnsRecordType::SRV => Ok(DnsRecord::SRV(SRVRecord {
            target: listed.value,
            priority: listed.priority,
            weight: listed.weight,
            port: listed.port,
        })),
        DnsRecordType::CAA => {
            build_caa(&listed.caa_type, listed.issuer_critical, listed.value).map(DnsRecord::CAA)
        }
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by DNSMadeEasy".into(),
        )),
    }
}

fn build_caa(tag: &str, issuer_critical_flag: u8, value: String) -> crate::Result<CAARecord> {
    let issuer_critical = issuer_critical_flag != 0;
    match tag {
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
