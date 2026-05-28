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

use crate::http::{HttpClient, HttpClientBuilder};
use crate::utils::{strip_origin_from_name, txt_chunks};
use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, KeyValue, MXRecord, Result, SRVRecord,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct AzureDnsConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub subscription_id: String,
    pub resource_group: String,
    pub environment: AzureEnvironment,
    pub request_timeout: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AzureEnvironment {
    Public,
    China,
    UsGovernment,
}

impl AzureEnvironment {
    pub fn from_str_lossy(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "china" => AzureEnvironment::China,
            "usgovernment" => AzureEnvironment::UsGovernment,
            _ => AzureEnvironment::Public,
        }
    }

    fn login_host(self) -> &'static str {
        match self {
            AzureEnvironment::Public => "https://login.microsoftonline.com",
            AzureEnvironment::China => "https://login.chinacloudapi.cn",
            AzureEnvironment::UsGovernment => "https://login.microsoftonline.us",
        }
    }

    fn management_host(self) -> &'static str {
        match self {
            AzureEnvironment::Public => "https://management.azure.com",
            AzureEnvironment::China => "https://management.chinacloudapi.cn",
            AzureEnvironment::UsGovernment => "https://management.usgovcloudapi.net",
        }
    }

    fn scope(self) -> &'static str {
        match self {
            AzureEnvironment::Public => "https://management.azure.com/.default",
            AzureEnvironment::China => "https://management.chinacloudapi.cn/.default",
            AzureEnvironment::UsGovernment => "https://management.usgovcloudapi.net/.default",
        }
    }
}

#[derive(Clone)]
pub struct AzureDnsProvider {
    client: HttpClient,
    config: AzureDnsConfig,
    token: Arc<Mutex<Option<(String, Instant)>>>,
    endpoints: AzureEndpoints,
}

#[derive(Clone)]
struct AzureEndpoints {
    login_url: String,
    management_url: String,
}

const API_VERSION: &str = "2018-05-01";

impl AzureDnsProvider {
    pub fn new(config: AzureDnsConfig) -> Result<Self> {
        let client = HttpClientBuilder::default()
            .with_timeout(config.request_timeout)
            .build();

        let endpoints = AzureEndpoints {
            login_url: config.environment.login_host().to_string(),
            management_url: config.environment.management_host().to_string(),
        };

        Ok(Self {
            client,
            config,
            token: Arc::new(Mutex::new(None)),
            endpoints,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoints(
        mut self,
        login_url: impl AsRef<str>,
        management_url: impl AsRef<str>,
    ) -> Self {
        self.endpoints = AzureEndpoints {
            login_url: login_url.as_ref().trim_end_matches('/').to_string(),
            management_url: management_url.as_ref().trim_end_matches('/').to_string(),
        };
        self
    }

    #[cfg(test)]
    pub(crate) fn with_cached_token(self, token: impl Into<String>) -> Self {
        *self.token.lock().expect("test token lock") =
            Some((token.into(), Instant::now() + Duration::from_secs(55 * 60)));
        self
    }

    async fn ensure_token(&self) -> Result<String> {
        if let Some((ref token, expiry)) = *self.token_lock()?
            && Instant::now() < expiry
        {
            return Ok(token.clone());
        }

        let url = format!(
            "{}/{}/oauth2/v2.0/token",
            self.endpoints.login_url, self.config.tenant_id
        );
        let form = serde_urlencoded::to_string([
            ("grant_type", "client_credentials"),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("scope", self.config.environment.scope()),
        ])
        .map_err(|e| Error::Api(format!("Failed to encode token request: {e}")))?;

        let token_response: AzureTokenResponse = self
            .client
            .post(&url)
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_raw_body(form)
            .send_with_retry(3)
            .await?;

        if token_response.access_token.is_empty() {
            return Err(Error::Api(
                "Azure token response missing access_token".into(),
            ));
        }

        let lifetime = token_response
            .expires_in
            .unwrap_or(3600)
            .saturating_sub(60)
            .max(60);
        let expiry = Instant::now() + Duration::from_secs(lifetime);
        *self.token_lock()? = Some((token_response.access_token.clone(), expiry));
        Ok(token_response.access_token)
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        check_record_types(record_type, &records)?;
        check_cname_singleton(record_type, &records)?;
        let zone = origin.into_name().to_ascii_lowercase();
        let fqdn = name.into_name().to_ascii_lowercase();
        let relative = relative_record_name(&fqdn, &zone);
        let type_segment = azure_record_type(&record_type)?;
        let url = self.record_url(&zone, type_segment, &relative);
        let token = self.ensure_token().await?;

        if records.is_empty() {
            return self.delete_rrset_url(&url, &token, None).await;
        }

        self.put_rrset(&url, &token, ttl, record_type, &records, None)
            .await
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        check_cname_singleton(record_type, &records)?;
        let zone = origin.into_name().to_ascii_lowercase();
        let fqdn = name.into_name().to_ascii_lowercase();
        let relative = relative_record_name(&fqdn, &zone);
        let type_segment = azure_record_type(&record_type)?;
        let url = self.record_url(&zone, type_segment, &relative);
        let token = self.ensure_token().await?;

        let fetched = self.fetch_rrset(&url, &token).await?;
        let mut merged = fetched.records;
        for record in records {
            if !merged.iter().any(|r| r == &record) {
                merged.push(record);
            }
        }
        check_cname_singleton(record_type, &merged)?;
        self.put_rrset(
            &url,
            &token,
            ttl,
            record_type,
            &merged,
            fetched.etag.as_deref(),
        )
        .await
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let zone = origin.into_name().to_ascii_lowercase();
        let fqdn = name.into_name().to_ascii_lowercase();
        let relative = relative_record_name(&fqdn, &zone);
        let type_segment = azure_record_type(&record_type)?;
        let url = self.record_url(&zone, type_segment, &relative);
        let token = self.ensure_token().await?;

        let fetched = match self.fetch_rrset_optional(&url, &token).await? {
            Some(fetched) => fetched,
            None => return Ok(()),
        };

        let remaining: Vec<DnsRecord> = fetched
            .records
            .into_iter()
            .filter(|r| !records.contains(r))
            .collect();

        if remaining.is_empty() {
            return self
                .delete_rrset_url(&url, &token, fetched.etag.as_deref())
                .await;
        }

        let ttl = fetched.ttl.unwrap_or(0);
        self.put_rrset(
            &url,
            &token,
            ttl,
            record_type,
            &remaining,
            fetched.etag.as_deref(),
        )
        .await
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> Result<Vec<DnsRecord>> {
        let zone = origin.into_name().to_ascii_lowercase();
        let fqdn = name.into_name().to_ascii_lowercase();
        let relative = relative_record_name(&fqdn, &zone);
        let type_segment = azure_record_type(&record_type)?;
        let url = self.record_url(&zone, type_segment, &relative);
        let token = self.ensure_token().await?;

        match self.fetch_rrset_optional(&url, &token).await? {
            Some(fetched) => Ok(fetched.records),
            None => Ok(Vec::new()),
        }
    }

    async fn put_rrset(
        &self,
        url: &str,
        token: &str,
        ttl: u32,
        record_type: DnsRecordType,
        records: &[DnsRecord],
        if_match: Option<&str>,
    ) -> Result<()> {
        let mut properties = serde_json::Map::new();
        properties.insert("TTL".to_string(), json!(ttl));
        insert_rrset_payload(&mut properties, record_type, records)?;

        let mut body = serde_json::Map::new();
        body.insert("properties".to_string(), Value::Object(properties));

        let mut request = self
            .client
            .put(url)
            .with_header("authorization", format!("Bearer {token}"))
            .with_body(&body)?;
        if let Some(etag) = if_match {
            request = request.with_header("if-match", etag);
        }
        request.send_with_retry::<Value>(3).await.map(|_| ())
    }

    async fn delete_rrset_url(&self, url: &str, token: &str, if_match: Option<&str>) -> Result<()> {
        let mut request = self
            .client
            .delete(url)
            .with_header("authorization", format!("Bearer {token}"));
        if let Some(etag) = if_match {
            request = request.with_header("if-match", etag);
        }
        request
            .send_with_retry::<Value>(3)
            .await
            .map(|_| ())
            .or_else(|err| match err {
                Error::NotFound => Ok(()),
                err => Err(err),
            })
    }

    async fn fetch_rrset(&self, url: &str, token: &str) -> Result<FetchedRrset> {
        match self.fetch_rrset_optional(url, token).await? {
            Some(fetched) => Ok(fetched),
            None => Ok(FetchedRrset::default()),
        }
    }

    async fn fetch_rrset_optional(&self, url: &str, token: &str) -> Result<Option<FetchedRrset>> {
        let value: Value = match self
            .client
            .get(url)
            .with_header("authorization", format!("Bearer {token}"))
            .send_with_retry(3)
            .await
        {
            Ok(v) => v,
            Err(Error::NotFound) => return Ok(None),
            Err(err) => return Err(err),
        };

        let etag = value
            .get("etag")
            .and_then(Value::as_str)
            .map(str::to_string);

        let ttl = value
            .get("properties")
            .and_then(|p| p.get("TTL"))
            .and_then(Value::as_u64)
            .map(|v| v as u32);

        let records = parse_rrset_records(&value)?;
        Ok(Some(FetchedRrset { records, etag, ttl }))
    }

    fn record_url(&self, zone: &str, type_segment: &str, relative: &str) -> String {
        format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/{}/{}?api-version={}",
            self.endpoints.management_url,
            self.config.subscription_id,
            self.config.resource_group,
            zone,
            type_segment,
            relative,
            API_VERSION,
        )
    }

    fn token_lock(&self) -> Result<std::sync::MutexGuard<'_, Option<(String, Instant)>>> {
        self.token
            .lock()
            .map_err(|_| Error::Client("Azure DNS token cache lock poisoned".into()))
    }
}

fn relative_record_name(fqdn: &str, zone: &str) -> String {
    let stripped = strip_origin_from_name(fqdn, zone, Some("@"));
    if stripped.is_empty() {
        "@".to_string()
    } else {
        stripped
    }
}

fn azure_record_type(rt: &DnsRecordType) -> Result<&'static str> {
    Ok(match rt {
        DnsRecordType::A => "A",
        DnsRecordType::AAAA => "AAAA",
        DnsRecordType::CNAME => "CNAME",
        DnsRecordType::MX => "MX",
        DnsRecordType::NS => "NS",
        DnsRecordType::TXT => "TXT",
        DnsRecordType::SRV => "SRV",
        DnsRecordType::CAA => "CAA",
        DnsRecordType::TLSA => {
            return Err(Error::Unsupported(
                "TLSA records are not supported by Azure DNS".to_string(),
            ));
        }
    })
}

#[derive(Default)]
struct FetchedRrset {
    records: Vec<DnsRecord>,
    etag: Option<String>,
    ttl: Option<u32>,
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> Result<()> {
    azure_record_type(&expected)?;
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

fn check_cname_singleton(record_type: DnsRecordType, records: &[DnsRecord]) -> Result<()> {
    if record_type == DnsRecordType::CNAME && records.len() > 1 {
        return Err(Error::Api(
            "CNAME RRSet may contain at most one record".to_string(),
        ));
    }
    Ok(())
}

fn insert_rrset_payload(
    props: &mut serde_json::Map<String, Value>,
    record_type: DnsRecordType,
    records: &[DnsRecord],
) -> Result<()> {
    match record_type {
        DnsRecordType::A => {
            let arr: Vec<Value> = records
                .iter()
                .map(|r| match r {
                    DnsRecord::A(ip) => json!({"ipv4Address": ip.to_string()}),
                    _ => unreachable!(),
                })
                .collect();
            props.insert("ARecords".to_string(), Value::Array(arr));
        }
        DnsRecordType::AAAA => {
            let arr: Vec<Value> = records
                .iter()
                .map(|r| match r {
                    DnsRecord::AAAA(ip) => json!({"ipv6Address": ip.to_string()}),
                    _ => unreachable!(),
                })
                .collect();
            props.insert("AAAARecords".to_string(), Value::Array(arr));
        }
        DnsRecordType::CNAME => {
            if let Some(DnsRecord::CNAME(target)) = records.first() {
                props.insert(
                    "CNAMERecord".to_string(),
                    json!({"cname": target.trim_end_matches('.')}),
                );
            }
        }
        DnsRecordType::NS => {
            let arr: Vec<Value> = records
                .iter()
                .map(|r| match r {
                    DnsRecord::NS(target) => {
                        json!({"nsdname": target.trim_end_matches('.')})
                    }
                    _ => unreachable!(),
                })
                .collect();
            props.insert("NSRecords".to_string(), Value::Array(arr));
        }
        DnsRecordType::MX => {
            let arr: Vec<Value> = records
                .iter()
                .map(|r| match r {
                    DnsRecord::MX(mx) => json!({
                        "preference": mx.priority,
                        "exchange": mx.exchange.trim_end_matches('.'),
                    }),
                    _ => unreachable!(),
                })
                .collect();
            props.insert("MXRecords".to_string(), Value::Array(arr));
        }
        DnsRecordType::TXT => {
            let arr: Vec<Value> = records
                .iter()
                .map(|r| match r {
                    DnsRecord::TXT(text) => json!({"value": txt_chunks(text.clone())}),
                    _ => unreachable!(),
                })
                .collect();
            props.insert("TXTRecords".to_string(), Value::Array(arr));
        }
        DnsRecordType::SRV => {
            let arr: Vec<Value> = records
                .iter()
                .map(|r| match r {
                    DnsRecord::SRV(srv) => json!({
                        "priority": srv.priority,
                        "weight": srv.weight,
                        "port": srv.port,
                        "target": srv.target.trim_end_matches('.'),
                    }),
                    _ => unreachable!(),
                })
                .collect();
            props.insert("SRVRecords".to_string(), Value::Array(arr));
        }
        DnsRecordType::CAA => {
            let arr: Vec<Value> = records
                .iter()
                .map(|r| match r {
                    DnsRecord::CAA(caa) => {
                        let (flags, tag, value) = caa.clone().decompose();
                        json!({"flags": flags, "tag": tag, "value": value})
                    }
                    _ => unreachable!(),
                })
                .collect();
            props.insert("caaRecords".to_string(), Value::Array(arr));
        }
        DnsRecordType::TLSA => {
            return Err(Error::Unsupported(
                "TLSA records are not supported by Azure DNS".to_string(),
            ));
        }
    }
    Ok(())
}

fn parse_rrset_records(value: &Value) -> Result<Vec<DnsRecord>> {
    let props = match value.get("properties") {
        Some(p) => p,
        None => return Ok(Vec::new()),
    };

    let mut out = Vec::new();

    if let Some(arr) = props.get("ARecords").and_then(Value::as_array) {
        for entry in arr {
            if let Some(addr) = entry.get("ipv4Address").and_then(Value::as_str)
                && let Ok(ip) = Ipv4Addr::from_str(addr)
            {
                out.push(DnsRecord::A(ip));
            }
        }
    }
    if let Some(arr) = props.get("AAAARecords").and_then(Value::as_array) {
        for entry in arr {
            if let Some(addr) = entry.get("ipv6Address").and_then(Value::as_str)
                && let Ok(ip) = Ipv6Addr::from_str(addr)
            {
                out.push(DnsRecord::AAAA(ip));
            }
        }
    }
    if let Some(obj) = props.get("CNAMERecord")
        && let Some(target) = obj.get("cname").and_then(Value::as_str)
    {
        out.push(DnsRecord::CNAME(target.to_string()));
    }
    if let Some(arr) = props.get("NSRecords").and_then(Value::as_array) {
        for entry in arr {
            if let Some(target) = entry.get("nsdname").and_then(Value::as_str) {
                out.push(DnsRecord::NS(target.to_string()));
            }
        }
    }
    if let Some(arr) = props.get("MXRecords").and_then(Value::as_array) {
        for entry in arr {
            let priority = entry.get("preference").and_then(Value::as_u64).unwrap_or(0) as u16;
            if let Some(exchange) = entry.get("exchange").and_then(Value::as_str) {
                out.push(DnsRecord::MX(MXRecord {
                    priority,
                    exchange: exchange.to_string(),
                }));
            }
        }
    }
    if let Some(arr) = props.get("TXTRecords").and_then(Value::as_array) {
        for entry in arr {
            if let Some(values) = entry.get("value").and_then(Value::as_array) {
                let joined: String = values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .concat();
                out.push(DnsRecord::TXT(joined));
            }
        }
    }
    if let Some(arr) = props.get("SRVRecords").and_then(Value::as_array) {
        for entry in arr {
            let priority = entry.get("priority").and_then(Value::as_u64).unwrap_or(0) as u16;
            let weight = entry.get("weight").and_then(Value::as_u64).unwrap_or(0) as u16;
            let port = entry.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;
            if let Some(target) = entry.get("target").and_then(Value::as_str) {
                out.push(DnsRecord::SRV(SRVRecord {
                    priority,
                    weight,
                    port,
                    target: target.to_string(),
                }));
            }
        }
    }
    if let Some(arr) = props.get("caaRecords").and_then(Value::as_array) {
        for entry in arr {
            let flags = entry.get("flags").and_then(Value::as_u64).unwrap_or(0) as u8;
            let tag = entry.get("tag").and_then(Value::as_str).unwrap_or("");
            let value = entry
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let issuer_critical = flags & 0x80 != 0;
            let caa = match tag.to_ascii_lowercase().as_str() {
                "issue" => CAARecord::Issue {
                    issuer_critical,
                    name: if value.is_empty() { None } else { Some(value) },
                    options: Vec::<KeyValue>::new(),
                },
                "issuewild" => CAARecord::IssueWild {
                    issuer_critical,
                    name: if value.is_empty() { None } else { Some(value) },
                    options: Vec::<KeyValue>::new(),
                },
                "iodef" => CAARecord::Iodef {
                    issuer_critical,
                    url: value,
                },
                _ => continue,
            };
            out.push(DnsRecord::CAA(caa));
        }
    }

    Ok(out)
}

#[derive(Deserialize)]
struct AzureTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}
