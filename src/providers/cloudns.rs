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
    DnsRecord, DnsRecordType, Error, IntoFqdn, http::HttpClientBuilder,
    utils::strip_origin_from_name,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.cloudns.net/dns";

#[derive(Clone)]
pub struct ClouDnsProvider {
    client: HttpClientBuilder,
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

#[derive(Deserialize, Debug)]
struct ClouDnsRecord {
    id: String,
    #[serde(rename = "type")]
    rr_type: String,
    host: String,
}

impl ClouDnsProvider {
    pub(crate) fn new(
        auth_id: Option<impl AsRef<str>>,
        sub_auth_id: Option<impl AsRef<str>>,
        auth_password: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let auth_id = auth_id.map(|s| s.as_ref().to_string()).filter(|s| !s.is_empty());
        let sub_auth_id = sub_auth_id.map(|s| s.as_ref().to_string()).filter(|s| !s.is_empty());

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
            .with_timeout(timeout);

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
        let body = serde_urlencoded::to_string(&all).map_err(|err| {
            Error::Serialize(format!("Failed to encode ClouDNS form: {err}"))
        })?;
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
        let qs = serde_urlencoded::to_string(&all).map_err(|err| {
            Error::Serialize(format!("Failed to encode ClouDNS query: {err}"))
        })?;
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

    async fn find_record_id(
        &self,
        zone: &str,
        host: &str,
        rr_type: &str,
    ) -> crate::Result<String> {
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
            return Err(Error::Api(format!(
                "ClouDNS record {host} of type {rr_type} not found"
            )));
        }
        let records: HashMap<String, ClouDnsRecord> = serde_json::from_str(&body).map_err(|err| {
            Error::Serialize(format!("Failed to parse ClouDNS records: {err}"))
        })?;
        records
            .into_values()
            .find(|r| r.host == host && r.rr_type == rr_type)
            .map(|r| r.id)
            .ok_or_else(|| Error::Api(format!("ClouDNS record {host} of type {rr_type} not found")))
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let zone = origin.into_name().to_string();
        let host = strip_origin_from_name(name.as_ref(), &zone, Some(""));
        let mut params = build_record_params(&record)?;
        params.push(("domain-name", zone));
        params.push(("host", host));
        params.push(("ttl", ttl_rounder(ttl).to_string()));

        let body = self.post_form("add-record.json", params).await?;
        Self::check_status(&body, "add-record")
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let zone = origin.into_name().to_string();
        let host = strip_origin_from_name(name.as_ref(), &zone, Some(""));
        let rr_type = record.as_type().as_str();
        let record_id = self.find_record_id(&zone, &host, rr_type).await?;

        let mut params = build_record_params(&record)?;
        params.retain(|(k, _)| *k != "record-type");
        params.push(("domain-name", zone));
        params.push(("record-id", record_id));
        params.push(("host", host));
        params.push(("ttl", ttl_rounder(ttl).to_string()));

        let body = self.post_form("mod-record.json", params).await?;
        Self::check_status(&body, "mod-record")
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let zone = origin.into_name().to_string();
        let host = strip_origin_from_name(name.as_ref(), &zone, Some(""));
        let record_id = self
            .find_record_id(&zone, &host, record_type.as_str())
            .await?;

        let params = vec![
            ("domain-name", zone),
            ("record-id", record_id),
        ];
        let body = self.post_form("delete-record.json", params).await?;
        Self::check_status(&body, "delete-record")
    }
}

fn build_record_params(record: &DnsRecord) -> crate::Result<Vec<(&'static str, String)>> {
    let mut params: Vec<(&'static str, String)> = Vec::new();
    let rr_type = record.as_type().as_str();
    params.push(("record-type", rr_type.to_string()));
    match record {
        DnsRecord::A(addr) => params.push(("record", addr.to_string())),
        DnsRecord::AAAA(addr) => params.push(("record", addr.to_string())),
        DnsRecord::CNAME(content) => params.push(("record", content.clone())),
        DnsRecord::NS(content) => params.push(("record", content.clone())),
        DnsRecord::TXT(content) => params.push(("record", content.clone())),
        DnsRecord::MX(mx) => {
            params.push(("record", mx.exchange.clone()));
            params.push(("priority", mx.priority.to_string()));
        }
        DnsRecord::SRV(srv) => {
            params.push(("record", srv.target.clone()));
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
