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
use quick_xml::de::from_str;
use serde::Deserialize;
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.namecheap.com/xml.response";

#[derive(Clone)]
pub struct NamecheapProvider {
    client: HttpClientBuilder,
    endpoint: String,
    api_user: String,
    api_key: String,
    username: String,
    client_ip: String,
}

#[derive(Deserialize, Debug)]
struct ApiResponse {
    #[serde(rename = "@Status", default)]
    status: String,
    #[serde(rename = "Errors", default)]
    errors: ApiErrors,
    #[serde(rename = "CommandResponse", default)]
    command_response: CommandResponse,
}

#[derive(Deserialize, Debug, Default)]
struct ApiErrors {
    #[serde(rename = "Error", default)]
    items: Vec<ApiErrorItem>,
}

#[derive(Deserialize, Debug, Default)]
struct ApiErrorItem {
    #[serde(rename = "@Number", default)]
    number: String,
    #[serde(rename = "$value", default)]
    message: String,
}

#[derive(Deserialize, Debug, Default)]
struct CommandResponse {
    #[serde(rename = "DomainDNSGetHostsResult", default)]
    get_hosts: Option<GetHostsResult>,
    #[serde(rename = "DomainDNSSetHostsResult", default)]
    set_hosts: Option<SetHostsResult>,
}

#[derive(Deserialize, Debug)]
struct GetHostsResult {
    #[serde(rename = "host", default)]
    hosts: Vec<Host>,
}

#[derive(Deserialize, Debug, Default)]
struct SetHostsResult {
    #[serde(rename = "@IsSuccess", default)]
    is_success: String,
}

#[derive(Deserialize, Debug, Clone)]
struct Host {
    #[serde(rename = "@Name", default)]
    name: String,
    #[serde(rename = "@Type", default)]
    record_type: String,
    #[serde(rename = "@Address", default)]
    address: String,
    #[serde(rename = "@MXPref", default)]
    mx_pref: String,
    #[serde(rename = "@TTL", default)]
    ttl: String,
}

impl NamecheapProvider {
    pub(crate) fn new(
        api_user: impl AsRef<str>,
        api_key: impl AsRef<str>,
        client_ip: impl AsRef<str>,
        username: Option<impl AsRef<str>>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let api_user = api_user.as_ref().to_string();
        let api_key = api_key.as_ref().to_string();
        let client_ip = client_ip.as_ref().to_string();
        if api_user.is_empty() || api_key.is_empty() || client_ip.is_empty() {
            return Err(Error::Api(
                "Namecheap api_user, api_key and client_ip must not be empty".to_string(),
            ));
        }
        let username = username
            .map(|u| u.as_ref().to_string())
            .unwrap_or_else(|| api_user.clone());
        let client = HttpClientBuilder::default()
            .with_header("Accept", "application/xml")
            .with_timeout(timeout);
        Ok(Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            api_user,
            api_key,
            username,
            client_ip,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    fn base_params(&self, command: &str) -> Vec<(String, String)> {
        vec![
            ("ApiUser".to_string(), self.api_user.clone()),
            ("ApiKey".to_string(), self.api_key.clone()),
            ("UserName".to_string(), self.username.clone()),
            ("Command".to_string(), command.to_string()),
            ("ClientIp".to_string(), self.client_ip.clone()),
        ]
    }

    async fn get_hosts(&self, sld: &str, tld: &str) -> crate::Result<Vec<Host>> {
        let mut params = self.base_params("namecheap.domains.dns.getHosts");
        params.push(("SLD".to_string(), sld.to_string()));
        params.push(("TLD".to_string(), tld.to_string()));
        let query =
            serde_urlencoded::to_string(&params).map_err(|e| Error::Serialize(e.to_string()))?;
        let url = format!("{}?{}", self.endpoint, query);
        let body = self.client.get(url).send_raw().await?;
        let response: ApiResponse =
            from_str(&body).map_err(|e| Error::Parse(format!("Invalid Namecheap XML: {e}")))?;
        check_api(&response)?;
        Ok(response
            .command_response
            .get_hosts
            .map(|r| r.hosts)
            .unwrap_or_default())
    }

    async fn set_hosts(&self, sld: &str, tld: &str, hosts: &[Host]) -> crate::Result<()> {
        let mut params = self.base_params("namecheap.domains.dns.setHosts");
        params.push(("SLD".to_string(), sld.to_string()));
        params.push(("TLD".to_string(), tld.to_string()));
        for (idx, host) in hosts.iter().enumerate() {
            let i = idx + 1;
            params.push((format!("HostName{i}"), host.name.clone()));
            params.push((format!("RecordType{i}"), host.record_type.clone()));
            params.push((format!("Address{i}"), host.address.clone()));
            let mx_pref = if host.mx_pref.is_empty() {
                "10".to_string()
            } else {
                host.mx_pref.clone()
            };
            params.push((format!("MXPref{i}"), mx_pref));
            let ttl = if host.ttl.is_empty() {
                "1800".to_string()
            } else {
                host.ttl.clone()
            };
            params.push((format!("TTL{i}"), ttl));
        }
        let body =
            serde_urlencoded::to_string(&params).map_err(|e| Error::Serialize(e.to_string()))?;
        let text = self
            .client
            .post(self.endpoint.clone())
            .set_header("Content-Type", "application/x-www-form-urlencoded")
            .with_raw_body(body)
            .send_raw()
            .await?;
        let response: ApiResponse = from_str(&text)
            .map_err(|e| Error::Parse(format!("Invalid Namecheap XML: {e}")))?;
        check_api(&response)?;
        if let Some(result) = response.command_response.set_hosts
            && !result.is_success.eq_ignore_ascii_case("true")
        {
            return Err(Error::Api("Namecheap setHosts failed".to_string()));
        }
        Ok(())
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
        let (sld, tld) = split_domain(&domain)?;
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let record_type = record.as_type();
        let mx_pref = record.priority().unwrap_or(10);
        let address = render_value(record)?;

        let mut hosts = self.get_hosts(sld, tld).await?;
        hosts.push(Host {
            name: subdomain,
            record_type: record_type.as_str().to_string(),
            address,
            mx_pref: mx_pref.to_string(),
            ttl: ttl.to_string(),
        });
        self.set_hosts(sld, tld, &hosts).await
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
        let (sld, tld) = split_domain(&domain)?;
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let record_type = record.as_type();
        let mx_pref = record.priority().unwrap_or(10);
        let address = render_value(record)?;

        let mut hosts = self.get_hosts(sld, tld).await?;
        hosts.retain(|h| !(h.name == subdomain && h.record_type == record_type.as_str()));
        hosts.push(Host {
            name: subdomain,
            record_type: record_type.as_str().to_string(),
            address,
            mx_pref: mx_pref.to_string(),
            ttl: ttl.to_string(),
        });
        self.set_hosts(sld, tld, &hosts).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let (sld, tld) = split_domain(&domain)?;
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));

        let mut hosts = self.get_hosts(sld, tld).await?;
        let before = hosts.len();
        hosts.retain(|h| !(h.name == subdomain && h.record_type == record_type.as_str()));
        if hosts.len() == before {
            return Ok(());
        }
        self.set_hosts(sld, tld, &hosts).await
    }
}

fn check_api(response: &ApiResponse) -> crate::Result<()> {
    if let Some(err) = response.errors.items.first() {
        return Err(Error::Api(format!(
            "Namecheap error {}: {}",
            err.number, err.message
        )));
    }
    if !response.status.is_empty() && !response.status.eq_ignore_ascii_case("OK") {
        return Err(Error::Api(format!(
            "Namecheap returned status {}",
            response.status
        )));
    }
    Ok(())
}

fn split_domain(domain: &str) -> crate::Result<(&str, &str)> {
    domain
        .split_once('.')
        .ok_or_else(|| Error::Api(format!("Invalid Namecheap domain: {domain}")))
}

fn render_value(record: DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content,
        DnsRecord::NS(content) => content,
        DnsRecord::MX(mx) => mx.exchange,
        DnsRecord::TXT(content) => content,
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority, srv.weight, srv.port, srv.target
        ),
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Namecheap".to_string(),
            ));
        }
        DnsRecord::CAA(caa) => caa.to_string(),
    })
}
