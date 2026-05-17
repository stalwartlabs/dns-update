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
use serde::{Deserialize, Serialize};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const DEFAULT_ENDPOINT: &str =
    "https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON";
const SESSION_TTL_SECS: u64 = 10 * 60;

#[derive(Clone)]
pub struct NetcupProvider {
    client: HttpClientBuilder,
    endpoint: String,
    customer_number: String,
    api_key: String,
    api_password: String,
    session: Arc<Mutex<Option<(String, Instant)>>>,
}

#[derive(Serialize, Debug)]
struct Request<P: Serialize> {
    action: &'static str,
    param: P,
}

#[derive(Serialize, Debug)]
struct LoginParam<'a> {
    customernumber: &'a str,
    apikey: &'a str,
    apipassword: &'a str,
}

#[derive(Serialize, Debug)]
struct LogoutParam<'a> {
    customernumber: &'a str,
    apikey: &'a str,
    apisessionid: &'a str,
}

#[derive(Serialize, Debug)]
struct InfoDnsRecordsParam<'a> {
    domainname: &'a str,
    customernumber: &'a str,
    apikey: &'a str,
    apisessionid: &'a str,
}

#[derive(Serialize, Debug)]
struct UpdateDnsRecordsParam<'a> {
    domainname: &'a str,
    customernumber: &'a str,
    apikey: &'a str,
    apisessionid: &'a str,
    dnsrecordset: DnsRecordSet,
}

#[derive(Serialize, Debug)]
struct DnsRecordSet {
    dnsrecords: Vec<NetcupRecord>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct NetcupRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    hostname: String,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    priority: String,
    destination: String,
    #[serde(default, skip_serializing_if = "is_false")]
    deleterecord: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    state: String,
}

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Deserialize, Debug)]
struct ResponseMsg {
    #[serde(default)]
    status: String,
    #[serde(default, rename = "statuscode")]
    status_code: i64,
    #[serde(default, rename = "shortmessage")]
    short_message: String,
    #[serde(default, rename = "longmessage")]
    long_message: String,
    #[serde(default, rename = "responsedata")]
    response_data: serde_json::Value,
}

#[derive(Deserialize, Debug)]
struct LoginResponse {
    #[serde(default, rename = "apisessionid")]
    api_session_id: String,
}

#[derive(Deserialize, Debug)]
struct InfoDnsRecordsResponse {
    #[serde(default)]
    dnsrecords: Vec<NetcupRecord>,
}

impl NetcupProvider {
    pub(crate) fn new(
        customer_number: impl AsRef<str>,
        api_key: impl AsRef<str>,
        api_password: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default().with_timeout(timeout);
        Self {
            client,
            endpoint: DEFAULT_ENDPOINT.to_string(),
            customer_number: customer_number.as_ref().to_string(),
            api_key: api_key.as_ref().to_string(),
            api_password: api_password.as_ref().to_string(),
            session: Arc::new(Mutex::new(None)),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        _ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let hostname = strip_origin_from_name(&name, &origin, Some("@"));
        let payload = encode_record(&record, &hostname)?;
        let session = self.ensure_session().await?;

        self.update_dns_records(&origin, &session, vec![payload])
            .await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        _ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let hostname = strip_origin_from_name(&name, &origin, Some("@"));
        let record_type = record.as_type();
        let session = self.ensure_session().await?;

        let existing = self
            .find_record_by_name_type(&origin, &session, &hostname, record_type.as_str())
            .await?;

        let new = encode_record(&record, &hostname)?;
        let merged = NetcupRecord {
            id: existing.id.clone(),
            hostname: new.hostname,
            record_type: new.record_type,
            priority: new.priority,
            destination: new.destination,
            deleterecord: false,
            state: String::new(),
        };

        self.update_dns_records(&origin, &session, vec![merged])
            .await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let hostname = strip_origin_from_name(&name, &origin, Some("@"));
        let session = self.ensure_session().await?;

        let existing = self
            .find_record_by_name_type(&origin, &session, &hostname, record_type.as_str())
            .await?;

        let to_delete = NetcupRecord {
            id: existing.id.clone(),
            hostname: existing.hostname.clone(),
            record_type: existing.record_type.clone(),
            priority: existing.priority.clone(),
            destination: existing.destination.clone(),
            deleterecord: true,
            state: String::new(),
        };

        self.update_dns_records(&origin, &session, vec![to_delete])
            .await
    }

    async fn ensure_session(&self) -> crate::Result<String> {
        if let Some((ref id, expiry)) = *self.session_lock()?
            && Instant::now() < expiry
        {
            return Ok(id.clone());
        }
        let id = self.login().await?;
        let expiry = Instant::now() + Duration::from_secs(SESSION_TTL_SECS);
        *self.session_lock()? = Some((id.clone(), expiry));
        Ok(id)
    }

    fn session_lock(
        &self,
    ) -> crate::Result<std::sync::MutexGuard<'_, Option<(String, Instant)>>> {
        self.session
            .lock()
            .map_err(|_| Error::Client("Netcup session lock poisoned".into()))
    }

    async fn login(&self) -> crate::Result<String> {
        let payload = Request {
            action: "login",
            param: LoginParam {
                customernumber: &self.customer_number,
                apikey: &self.api_key,
                apipassword: &self.api_password,
            },
        };
        let response: ResponseMsg = self
            .client
            .post(&self.endpoint)
            .with_body(payload)?
            .send()
            .await?;
        check_status(&response)?;
        let parsed: LoginResponse = serde_json::from_value(response.response_data)
            .map_err(|e| Error::Serialize(format!("Failed to parse Netcup login: {e}")))?;
        Ok(parsed.api_session_id)
    }

    async fn update_dns_records(
        &self,
        domain: &str,
        session: &str,
        records: Vec<NetcupRecord>,
    ) -> crate::Result<()> {
        let payload = Request {
            action: "updateDnsRecords",
            param: UpdateDnsRecordsParam {
                domainname: domain,
                customernumber: &self.customer_number,
                apikey: &self.api_key,
                apisessionid: session,
                dnsrecordset: DnsRecordSet { dnsrecords: records },
            },
        };

        let response: ResponseMsg = self
            .client
            .post(&self.endpoint)
            .with_body(payload)?
            .send()
            .await?;
        check_status(&response)?;
        Ok(())
    }

    async fn find_record_by_name_type(
        &self,
        domain: &str,
        session: &str,
        hostname: &str,
        record_type: &str,
    ) -> crate::Result<NetcupRecord> {
        let payload = Request {
            action: "infoDnsRecords",
            param: InfoDnsRecordsParam {
                domainname: domain,
                customernumber: &self.customer_number,
                apikey: &self.api_key,
                apisessionid: session,
            },
        };
        let response: ResponseMsg = self
            .client
            .post(&self.endpoint)
            .with_body(payload)?
            .send()
            .await?;
        check_status(&response)?;
        let parsed: InfoDnsRecordsResponse = serde_json::from_value(response.response_data)
            .map_err(|e| {
                Error::Serialize(format!("Failed to parse Netcup record list: {e}"))
            })?;

        parsed
            .dnsrecords
            .into_iter()
            .find(|r| r.hostname == hostname && r.record_type.eq_ignore_ascii_case(record_type))
            .ok_or_else(|| {
                Error::Api(format!(
                    "DNS Record {} of type {} not found in Netcup zone",
                    hostname, record_type
                ))
            })
    }

    #[allow(dead_code)]
    async fn logout(&self, session: &str) -> crate::Result<()> {
        let payload = Request {
            action: "logout",
            param: LogoutParam {
                customernumber: &self.customer_number,
                apikey: &self.api_key,
                apisessionid: session,
            },
        };
        let response: ResponseMsg = self
            .client
            .post(&self.endpoint)
            .with_body(payload)?
            .send()
            .await?;
        check_status(&response)
    }
}

fn check_status(response: &ResponseMsg) -> crate::Result<()> {
    if response.status == "success" {
        Ok(())
    } else {
        Err(Error::Api(format!(
            "Netcup API error: status={} code={} short={} long={}",
            response.status,
            response.status_code,
            response.short_message,
            response.long_message
        )))
    }
}

fn encode_record(record: &DnsRecord, hostname: &str) -> crate::Result<NetcupRecord> {
    let (record_type, destination, priority) = match record {
        DnsRecord::A(addr) => ("A", addr.to_string(), String::new()),
        DnsRecord::AAAA(addr) => ("AAAA", addr.to_string(), String::new()),
        DnsRecord::CNAME(value) => ("CNAME", value.clone(), String::new()),
        DnsRecord::NS(value) => ("NS", value.clone(), String::new()),
        DnsRecord::MX(mx) => ("MX", mx.exchange.clone(), mx.priority.to_string()),
        DnsRecord::TXT(value) => ("TXT", value.clone(), String::new()),
        DnsRecord::SRV(srv) => (
            "SRV",
            format!("{} {} {}", srv.weight, srv.port, srv.target),
            srv.priority.to_string(),
        ),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            (
                "CAA",
                format!("{} {} \"{}\"", flags, tag, value.replace('"', "\\\"")),
                String::new(),
            )
        }
        DnsRecord::TLSA(tlsa) => (
            "TLSA",
            format!(
                "{} {} {} {}",
                u8::from(tlsa.cert_usage),
                u8::from(tlsa.selector),
                u8::from(tlsa.matching),
                tlsa.cert_data
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            ),
            String::new(),
        ),
    };

    Ok(NetcupRecord {
        id: None,
        hostname: hostname.to_string(),
        record_type: record_type.to_string(),
        priority,
        destination,
        deleterecord: false,
        state: String::new(),
    })
}
