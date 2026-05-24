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
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.cloudns.net/dns";

#[derive(Clone)]
pub struct ClouDnsProvider {
    client: HttpClient,
    endpoint: String,
    auth_id: Option<String>,
    sub_auth_id: Option<String>,
    auth_password: String,
}

#[derive(Deserialize, Debug)]
struct ApiResponse {
    status: Option<String>,
    #[serde(rename = "statusDescription")]
    status_description: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
struct ClouDnsRecord {
    id: String,
    #[serde(rename = "type")]
    rr_type: String,
    host: String,
    #[serde(default)]
    record: String,
    #[serde(default)]
    priority: Option<String>,
    #[serde(default)]
    weight: Option<String>,
    #[serde(default)]
    port: Option<String>,
    #[serde(default)]
    caa_flag: Option<String>,
    #[serde(default)]
    caa_type: Option<String>,
    #[serde(default)]
    caa_value: Option<String>,
}

impl ClouDnsProvider {
    pub(crate) fn new(
        auth_id: Option<impl AsRef<str>>,
        sub_auth_id: Option<impl AsRef<str>>,
        auth_password: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let auth_id = auth_id
            .map(|s| s.as_ref().to_string())
            .filter(|s| !s.is_empty());
        let sub_auth_id = sub_auth_id
            .map(|s| s.as_ref().to_string())
            .filter(|s| !s.is_empty());

        if auth_id.is_none() && sub_auth_id.is_none() {
            return Err(Error::Api(
                "ClouDNS requires either auth_id or sub_auth_id".to_string(),
            ));
        }

        let password = auth_password.as_ref().to_string();
        if password.is_empty() {
            return Err(Error::Api("ClouDNS auth_password is required".to_string()));
        }

        let client = HttpClientBuilder::default()
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_timeout(timeout)
            .build();

        Ok(Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            auth_id,
            sub_auth_id,
            auth_password: password,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    fn auth_params(&self) -> Vec<(&'static str, String)> {
        let mut params: Vec<(&'static str, String)> = Vec::new();
        if let Some(sub) = self.sub_auth_id.as_ref() {
            params.push(("sub-auth-id", sub.clone()));
        } else if let Some(id) = self.auth_id.as_ref() {
            params.push(("auth-id", id.clone()));
        }
        params.push(("auth-password", self.auth_password.clone()));
        params
    }

    async fn post_form(
        &self,
        path: &str,
        params: Vec<(&'static str, String)>,
    ) -> crate::Result<String> {
        let mut all = self.auth_params();
        all.extend(params);
        let body = serde_urlencoded::to_string(&all)
            .map_err(|err| Error::Serialize(format!("Failed to encode ClouDNS form: {err}")))?;
        self.client
            .post(format!("{}/{}", self.endpoint, path))
            .with_raw_body(body)
            .send_raw()
            .await
    }

    async fn get_form(
        &self,
        path: &str,
        params: Vec<(&'static str, String)>,
    ) -> crate::Result<String> {
        let mut all = self.auth_params();
        all.extend(params);
        let qs = serde_urlencoded::to_string(&all)
            .map_err(|err| Error::Serialize(format!("Failed to encode ClouDNS query: {err}")))?;
        self.client
            .get(format!("{}/{}?{}", self.endpoint, path, qs))
            .send_raw()
            .await
    }

    fn check_status(body: &str, action: &str) -> crate::Result<()> {
        match serde_json::from_str::<ApiResponse>(body) {
            Ok(resp) => {
                if resp.status.as_deref() == Some("Success") {
                    Ok(())
                } else {
                    Err(Error::Api(format!(
                        "ClouDNS {action} failed: {} {}",
                        resp.status.unwrap_or_default(),
                        resp.status_description.unwrap_or_default()
                    )))
                }
            }
            Err(err) => Err(Error::Serialize(format!(
                "Failed to parse ClouDNS response: {err}"
            ))),
        }
    }

    async fn list_at(
        &self,
        zone: &str,
        host: &str,
        rr_type: &str,
    ) -> crate::Result<Vec<ClouDnsRecord>> {
        let body = self
            .get_form(
                "records.json",
                vec![
                    ("domain-name", zone.to_string()),
                    ("host", host.to_string()),
                    ("type", rr_type.to_string()),
                ],
            )
            .await?;
        if body.trim() == "[]" {
            return Ok(Vec::new());
        }
        let records: HashMap<String, ClouDnsRecord> = serde_json::from_str(&body)
            .map_err(|err| Error::Serialize(format!("Failed to parse ClouDNS records: {err}")))?;
        Ok(records
            .into_values()
            .filter(|r| r.host == host && r.rr_type == rr_type)
            .collect())
    }

    async fn find_record_ids(
        &self,
        zone: &str,
        host: &str,
        rr_type: &str,
    ) -> crate::Result<Vec<String>> {
        let listed = self.list_at(zone, host, rr_type).await?;
        Ok(listed.into_iter().map(|r| r.id).collect())
    }

    async fn add_record(
        &self,
        zone: &str,
        host: &str,
        ttl: u32,
        record: &DnsRecord,
    ) -> crate::Result<()> {
        let mut params = build_record_params(record)?;
        params.push(("domain-name", zone.to_string()));
        params.push(("host", host.to_string()));
        params.push(("ttl", ttl_rounder(ttl).to_string()));
        let body = self.post_form("add-record.json", params).await?;
        Self::check_status(&body, "add-record")
    }

    async fn delete_record_by_id(&self, zone: &str, record_id: &str) -> crate::Result<()> {
        let params = vec![
            ("domain-name", zone.to_string()),
            ("record-id", record_id.to_string()),
        ];
        let body = self.post_form("delete-record.json", params).await?;
        Self::check_status(&body, "delete-record")
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
        reject_tlsa(record_type)?;
        let name = name.into_name().into_owned();
        let zone = origin.into_name().to_string();
        let host = strip_origin_from_name(&name, &zone, Some(""));
        let rr_type = record_type.as_str();

        if records.is_empty() {
            let ids = self.find_record_ids(&zone, &host, rr_type).await?;
            for id in ids {
                self.delete_record_by_id(&zone, &id).await?;
            }
            return Ok(());
        }

        let desired = normalize_records(records);
        let existing = self.list_at(&zone, &host, rr_type).await?;

        let mut existing_pool: Vec<ClouDnsRecord> = existing;
        let mut to_add: Vec<DnsRecord> = Vec::new();

        for desired_record in desired {
            if let Some(idx) = existing_pool
                .iter()
                .position(|r| record_matches(r, &desired_record))
            {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(desired_record);
            }
        }

        for stale in existing_pool {
            self.delete_record_by_id(&zone, &stale.id).await?;
        }
        for new_record in to_add {
            self.add_record(&zone, &host, ttl, &new_record).await?;
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
        reject_tlsa(record_type)?;
        let name = name.into_name().into_owned();
        let zone = origin.into_name().to_string();
        let host = strip_origin_from_name(&name, &zone, Some(""));
        let rr_type = record_type.as_str();

        let desired = normalize_records(records);
        let existing = self.list_at(&zone, &host, rr_type).await?;

        for desired_record in desired {
            if existing.iter().any(|r| record_matches(r, &desired_record)) {
                continue;
            }
            self.add_record(&zone, &host, ttl, &desired_record).await?;
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
        reject_tlsa(record_type)?;
        let name = name.into_name().into_owned();
        let zone = origin.into_name().to_string();
        let host = strip_origin_from_name(&name, &zone, Some(""));
        let rr_type = record_type.as_str();

        let to_remove = normalize_records(records);
        let mut existing = self.list_at(&zone, &host, rr_type).await?;

        for target in to_remove {
            if let Some(idx) = existing.iter().position(|r| record_matches(r, &target)) {
                let stale = existing.swap_remove(idx);
                self.delete_record_by_id(&zone, &stale.id).await?;
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
        reject_tlsa(record_type)?;
        let name = name.into_name().into_owned();
        let zone = origin.into_name().to_string();
        let host = strip_origin_from_name(&name, &zone, Some(""));
        let rr_type = record_type.as_str();
        let listed = self.list_at(&zone, &host, rr_type).await?;
        listed.into_iter().map(record_to_dns_record).collect()
    }
}

fn build_record_params(record: &DnsRecord) -> crate::Result<Vec<(&'static str, String)>> {
    let mut params: Vec<(&'static str, String)> = Vec::new();
    let rr_type = record.as_type().as_str();
    params.push(("record-type", rr_type.to_string()));
    match record {
        DnsRecord::A(addr) => params.push(("record", addr.to_string())),
        DnsRecord::AAAA(addr) => params.push(("record", addr.to_string())),
        DnsRecord::CNAME(content) => {
            params.push(("record", content.as_str().into_name().into_owned()))
        }
        DnsRecord::NS(content) => {
            params.push(("record", content.as_str().into_name().into_owned()))
        }
        DnsRecord::TXT(content) => params.push(("record", content.clone())),
        DnsRecord::MX(mx) => {
            params.push(("record", mx.exchange.as_str().into_name().into_owned()));
            params.push(("priority", mx.priority.to_string()));
        }
        DnsRecord::SRV(srv) => {
            params.push(("record", srv.target.as_str().into_name().into_owned()));
            params.push(("priority", srv.priority.to_string()));
            params.push(("weight", srv.weight.to_string()));
            params.push(("port", srv.port.to_string()));
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by ClouDNS".to_string(),
            ));
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            params.push(("caa_flag", flags.to_string()));
            params.push(("caa_type", tag));
            params.push(("caa_value", value));
        }
    }
    Ok(params)
}

fn normalize_records(records: Vec<DnsRecord>) -> Vec<DnsRecord> {
    records.into_iter().map(normalize_record).collect()
}

fn normalize_record(record: DnsRecord) -> DnsRecord {
    match record {
        DnsRecord::CNAME(s) => DnsRecord::CNAME(s.as_str().into_name().into_owned()),
        DnsRecord::NS(s) => DnsRecord::NS(s.as_str().into_name().into_owned()),
        DnsRecord::MX(mx) => DnsRecord::MX(MXRecord {
            exchange: mx.exchange.as_str().into_name().into_owned(),
            priority: mx.priority,
        }),
        DnsRecord::SRV(srv) => DnsRecord::SRV(SRVRecord {
            target: srv.target.as_str().into_name().into_owned(),
            priority: srv.priority,
            weight: srv.weight,
            port: srv.port,
        }),
        other => other,
    }
}

fn record_matches(existing: &ClouDnsRecord, desired: &DnsRecord) -> bool {
    match desired {
        DnsRecord::A(addr) => existing.record == addr.to_string(),
        DnsRecord::AAAA(addr) => existing.record == addr.to_string(),
        DnsRecord::CNAME(s) | DnsRecord::NS(s) => existing.record == *s,
        DnsRecord::TXT(s) => existing.record == *s,
        DnsRecord::MX(mx) => {
            existing.record == mx.exchange
                && existing.priority.as_deref() == Some(mx.priority.to_string().as_str())
        }
        DnsRecord::SRV(srv) => {
            existing.record == srv.target
                && existing.priority.as_deref() == Some(srv.priority.to_string().as_str())
                && existing.weight.as_deref() == Some(srv.weight.to_string().as_str())
                && existing.port.as_deref() == Some(srv.port.to_string().as_str())
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            existing.caa_flag.as_deref() == Some(flags.to_string().as_str())
                && existing.caa_type.as_deref() == Some(tag.as_str())
                && existing.caa_value.as_deref() == Some(value.as_str())
        }
        DnsRecord::TLSA(_) => false,
    }
}

fn record_to_dns_record(record: ClouDnsRecord) -> crate::Result<DnsRecord> {
    match record.rr_type.as_str() {
        "A" => {
            let addr = record
                .record
                .parse()
                .map_err(|err| Error::Parse(format!("invalid ClouDNS A address: {err}")))?;
            Ok(DnsRecord::A(addr))
        }
        "AAAA" => {
            let addr = record
                .record
                .parse()
                .map_err(|err| Error::Parse(format!("invalid ClouDNS AAAA address: {err}")))?;
            Ok(DnsRecord::AAAA(addr))
        }
        "CNAME" => Ok(DnsRecord::CNAME(record.record)),
        "NS" => Ok(DnsRecord::NS(record.record)),
        "TXT" => Ok(DnsRecord::TXT(record.record)),
        "MX" => {
            let priority = record
                .priority
                .as_deref()
                .ok_or_else(|| Error::Parse("ClouDNS MX missing priority".to_string()))?
                .parse()
                .map_err(|err| Error::Parse(format!("invalid ClouDNS MX priority: {err}")))?;
            Ok(DnsRecord::MX(MXRecord {
                exchange: record.record,
                priority,
            }))
        }
        "SRV" => {
            let priority = record
                .priority
                .as_deref()
                .ok_or_else(|| Error::Parse("ClouDNS SRV missing priority".to_string()))?
                .parse()
                .map_err(|err| Error::Parse(format!("invalid ClouDNS SRV priority: {err}")))?;
            let weight = record
                .weight
                .as_deref()
                .ok_or_else(|| Error::Parse("ClouDNS SRV missing weight".to_string()))?
                .parse()
                .map_err(|err| Error::Parse(format!("invalid ClouDNS SRV weight: {err}")))?;
            let port = record
                .port
                .as_deref()
                .ok_or_else(|| Error::Parse("ClouDNS SRV missing port".to_string()))?
                .parse()
                .map_err(|err| Error::Parse(format!("invalid ClouDNS SRV port: {err}")))?;
            Ok(DnsRecord::SRV(SRVRecord {
                target: record.record,
                priority,
                weight,
                port,
            }))
        }
        "CAA" => {
            let flags_str = record
                .caa_flag
                .as_deref()
                .ok_or_else(|| Error::Parse("ClouDNS CAA missing caa_flag".to_string()))?;
            let flags: u8 = flags_str
                .parse()
                .map_err(|err| Error::Parse(format!("invalid ClouDNS CAA flag: {err}")))?;
            let tag = record
                .caa_type
                .clone()
                .ok_or_else(|| Error::Parse("ClouDNS CAA missing caa_type".to_string()))?;
            let value = record
                .caa_value
                .clone()
                .ok_or_else(|| Error::Parse("ClouDNS CAA missing caa_value".to_string()))?;
            Ok(DnsRecord::CAA(build_caa(flags, &tag, value)?))
        }
        other => Err(Error::Parse(format!(
            "unsupported ClouDNS record type: {other}"
        ))),
    }
}

fn build_caa(flags: u8, tag: &str, value: String) -> crate::Result<CAARecord> {
    let issuer_critical = flags & 0x80 != 0;
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

fn reject_tlsa(record_type: DnsRecordType) -> crate::Result<()> {
    if matches!(record_type, DnsRecordType::TLSA) {
        Err(Error::Api(
            "TLSA records are not supported by ClouDNS".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn ttl_rounder(ttl: u32) -> u32 {
    const VALID: &[u32] = &[
        60, 300, 900, 1800, 3600, 21600, 43200, 86400, 172800, 259200, 604800, 1209600,
    ];
    for &v in VALID {
        if ttl <= v {
            return v;
        }
    }
    2592000
}
