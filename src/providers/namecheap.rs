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
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, KeyValue, MXRecord,
    http::HttpClientBuilder,
    utils::{strip_origin_from_name, txt_chunks},
};
use quick_xml::de::from_str;
use serde::Deserialize;
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.namecheap.com/xml.response";
const TTL_MIN: u32 = 60;
const TTL_MAX: u32 = 60000;

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
    hosts: Vec<RawHost>,
}

#[derive(Deserialize, Debug, Default)]
struct SetHostsResult {
    #[serde(rename = "@IsSuccess", default)]
    is_success: String,
}

#[derive(Deserialize, Debug, Clone)]
struct RawHost {
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

#[derive(Debug, Clone)]
struct Host {
    name: String,
    record_type: String,
    address: String,
    mx_pref: String,
    ttl: String,
    caa_flag: Option<u8>,
    caa_tag: Option<String>,
}

impl From<RawHost> for Host {
    fn from(raw: RawHost) -> Self {
        Self {
            name: raw.name,
            record_type: raw.record_type,
            address: raw.address,
            mx_pref: raw.mx_pref,
            ttl: raw.ttl,
            caa_flag: None,
            caa_tag: None,
        }
    }
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
            .map(|r| r.hosts.into_iter().map(Host::from).collect())
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
            if let Some(flag) = host.caa_flag {
                params.push((format!("Flag{i}"), flag.to_string()));
            }
            if let Some(tag) = &host.caa_tag {
                params.push((format!("Tag{i}"), tag.clone()));
            }
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
        let response: ApiResponse =
            from_str(&text).map_err(|e| Error::Parse(format!("Invalid Namecheap XML: {e}")))?;
        check_api(&response)?;
        if let Some(result) = response.command_response.set_hosts
            && !result.is_success.eq_ignore_ascii_case("true")
        {
            return Err(Error::Api("Namecheap setHosts failed".to_string()));
        }
        Ok(())
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
        reject_unsupported(record_type)?;

        let name = name.into_name();
        let domain = origin.into_name();
        let (sld, tld) = split_domain(&domain)?;
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let ttl = clamp_ttl(ttl);

        let mut new_hosts: Vec<Host> = Vec::new();
        for record in records {
            new_hosts.extend(build_hosts_for_record(&subdomain, record, ttl)?);
        }

        let mut hosts = self.get_hosts(sld, tld).await?;
        let before = hosts.len();
        hosts.retain(|h| !(h.name == subdomain && h.record_type == record_type.as_str()));
        let pruned = hosts.len();

        if new_hosts.is_empty() && before == pruned {
            return Ok(());
        }

        hosts.extend(new_hosts);
        self.set_hosts(sld, tld, &hosts).await
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
        reject_unsupported(record_type)?;

        let name = name.into_name();
        let domain = origin.into_name();
        let (sld, tld) = split_domain(&domain)?;
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let ttl = clamp_ttl(ttl);

        let mut new_hosts: Vec<Host> = Vec::new();
        for record in records {
            new_hosts.extend(build_hosts_for_record(&subdomain, record, ttl)?);
        }

        let mut hosts = self.get_hosts(sld, tld).await?;

        let mut to_append: Vec<Host> = Vec::new();
        for candidate in new_hosts {
            let duplicate_existing = hosts.iter().any(|h| host_identity_equal(h, &candidate));
            let duplicate_queued = to_append.iter().any(|h| host_identity_equal(h, &candidate));
            if !duplicate_existing && !duplicate_queued {
                to_append.push(candidate);
            }
        }

        if to_append.is_empty() {
            return Ok(());
        }

        hosts.extend(to_append);
        self.set_hosts(sld, tld, &hosts).await
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
        reject_unsupported(record_type)?;

        let name = name.into_name();
        let domain = origin.into_name();
        let (sld, tld) = split_domain(&domain)?;
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));

        let mut targets: Vec<Host> = Vec::new();
        for record in records {
            targets.extend(build_hosts_for_record(&subdomain, record, TTL_MIN)?);
        }

        let mut hosts = self.get_hosts(sld, tld).await?;
        let before = hosts.len();
        hosts.retain(|h| {
            !(h.name == subdomain
                && h.record_type == record_type.as_str()
                && targets.iter().any(|t| host_identity_equal(t, h)))
        });
        if hosts.len() == before {
            return Ok(());
        }
        self.set_hosts(sld, tld, &hosts).await
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        reject_unsupported(record_type)?;

        let name = name.into_name();
        let domain = origin.into_name();
        let (sld, tld) = split_domain(&domain)?;
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));

        let hosts = self.get_hosts(sld, tld).await?;
        let mut out = Vec::new();
        for host in hosts {
            if host.name != subdomain || host.record_type != record_type.as_str() {
                continue;
            }
            if let Some(record) = host_to_dns_record(&host, record_type)? {
                out.push(record);
            }
        }
        Ok(out)
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

fn clamp_ttl(ttl: u32) -> u32 {
    ttl.clamp(TTL_MIN, TTL_MAX)
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

fn reject_unsupported(record_type: DnsRecordType) -> crate::Result<()> {
    match record_type {
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by Namecheap".to_string(),
        )),
        DnsRecordType::SRV => Err(Error::Api(
            "SRV records are not supported by Namecheap".to_string(),
        )),
        _ => Ok(()),
    }
}

fn host_identity_equal(a: &Host, b: &Host) -> bool {
    a.name == b.name
        && a.record_type == b.record_type
        && a.address == b.address
        && a.mx_pref == b.mx_pref
        && a.caa_flag == b.caa_flag
        && a.caa_tag == b.caa_tag
}

fn build_hosts_for_record(
    subdomain: &str,
    record: DnsRecord,
    ttl: u32,
) -> crate::Result<Vec<Host>> {
    let record_type = record.as_type();
    let type_str = record_type.as_str().to_string();
    let ttl_str = ttl.to_string();
    let mx_pref = record.priority().unwrap_or(10).to_string();

    let mut hosts = Vec::new();
    match record {
        DnsRecord::A(addr) => hosts.push(Host {
            name: subdomain.to_string(),
            record_type: type_str,
            address: addr.to_string(),
            mx_pref,
            ttl: ttl_str,
            caa_flag: None,
            caa_tag: None,
        }),
        DnsRecord::AAAA(addr) => hosts.push(Host {
            name: subdomain.to_string(),
            record_type: type_str,
            address: addr.to_string(),
            mx_pref,
            ttl: ttl_str,
            caa_flag: None,
            caa_tag: None,
        }),
        DnsRecord::CNAME(content) => hosts.push(Host {
            name: subdomain.to_string(),
            record_type: type_str,
            address: strip_trailing_dot(&content),
            mx_pref,
            ttl: ttl_str,
            caa_flag: None,
            caa_tag: None,
        }),
        DnsRecord::NS(content) => hosts.push(Host {
            name: subdomain.to_string(),
            record_type: type_str,
            address: strip_trailing_dot(&content),
            mx_pref,
            ttl: ttl_str,
            caa_flag: None,
            caa_tag: None,
        }),
        DnsRecord::MX(mx) => hosts.push(Host {
            name: subdomain.to_string(),
            record_type: type_str,
            address: strip_trailing_dot(&mx.exchange),
            mx_pref: mx.priority.to_string(),
            ttl: ttl_str,
            caa_flag: None,
            caa_tag: None,
        }),
        DnsRecord::TXT(content) => {
            for chunk in txt_chunks(content) {
                hosts.push(Host {
                    name: subdomain.to_string(),
                    record_type: type_str.clone(),
                    address: chunk,
                    mx_pref: mx_pref.clone(),
                    ttl: ttl_str.clone(),
                    caa_flag: None,
                    caa_tag: None,
                });
            }
        }
        DnsRecord::SRV(_) => {
            return Err(Error::Api(
                "SRV records are not supported by Namecheap".to_string(),
            ));
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Namecheap".to_string(),
            ));
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.decompose();
            hosts.push(Host {
                name: subdomain.to_string(),
                record_type: type_str,
                address: value,
                mx_pref,
                ttl: ttl_str,
                caa_flag: Some(flags),
                caa_tag: Some(tag),
            });
        }
    }
    Ok(hosts)
}

fn host_to_dns_record(host: &Host, record_type: DnsRecordType) -> crate::Result<Option<DnsRecord>> {
    Ok(Some(match record_type {
        DnsRecordType::A => {
            let addr = host
                .address
                .parse()
                .map_err(|err| Error::Parse(format!("invalid A address: {err}")))?;
            DnsRecord::A(addr)
        }
        DnsRecordType::AAAA => {
            let addr = host
                .address
                .parse()
                .map_err(|err| Error::Parse(format!("invalid AAAA address: {err}")))?;
            DnsRecord::AAAA(addr)
        }
        DnsRecordType::CNAME => DnsRecord::CNAME(strip_trailing_dot(&host.address)),
        DnsRecordType::NS => DnsRecord::NS(strip_trailing_dot(&host.address)),
        DnsRecordType::MX => {
            let priority: u16 = if host.mx_pref.is_empty() {
                10
            } else {
                host.mx_pref
                    .parse()
                    .map_err(|err| Error::Parse(format!("invalid MX priority: {err}")))?
            };
            DnsRecord::MX(MXRecord {
                priority,
                exchange: strip_trailing_dot(&host.address),
            })
        }
        DnsRecordType::TXT => DnsRecord::TXT(host.address.clone()),
        DnsRecordType::CAA => DnsRecord::CAA(parse_caa_address(&host.address)?),
        DnsRecordType::SRV => {
            return Err(Error::Api(
                "SRV records are not supported by Namecheap".to_string(),
            ));
        }
        DnsRecordType::TLSA => {
            return Err(Error::Api(
                "TLSA records are not supported by Namecheap".to_string(),
            ));
        }
    }))
}

fn strip_trailing_dot(value: &str) -> String {
    value.strip_suffix('.').unwrap_or(value).to_string()
}

fn parse_caa_address(value: &str) -> crate::Result<CAARecord> {
    let trimmed = value.trim();
    let mut parts = trimmed.splitn(3, char::is_whitespace);
    let flags_token = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value: {trimmed}")))?;
    let tag_token = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid CAA value: {trimmed}")))?;
    let value_token = parts.next().unwrap_or("").trim();
    let flags: u8 = flags_token
        .parse()
        .map_err(|err| Error::Parse(format!("invalid CAA flags: {err}")))?;
    let issuer_critical = flags & 0x80 != 0;
    let unquoted = unquote_caa_value(value_token);
    match tag_token {
        "issue" => {
            let (name, options) = parse_caa_value_parts(&unquoted);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = parse_caa_value_parts(&unquoted);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: unquoted,
        }),
        other => Err(Error::Parse(format!("unknown CAA tag: {other}"))),
    }
}

fn unquote_caa_value(value: &str) -> String {
    let trimmed = value.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed)
        .to_string()
}

fn parse_caa_value_parts(value: &str) -> (Option<String>, Vec<KeyValue>) {
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
