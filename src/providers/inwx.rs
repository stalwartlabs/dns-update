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

use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_ENDPOINT: &str = "https://api.domrobot.com/jsonrpc/";
const SANDBOX_ENDPOINT: &str = "https://api.ote.domrobot.com/jsonrpc/";

const SESSION_TTL: Duration = Duration::from_secs(50 * 60);

#[derive(Clone)]
pub struct InwxProvider {
    client: Client,
    username: String,
    password: String,
    shared_secret: Option<String>,
    endpoint: String,
    session: Arc<Mutex<Option<SessionState>>>,
}

#[derive(Clone)]
struct SessionState {
    cookie: String,
    expires: Instant,
}

#[derive(Deserialize, Debug)]
struct RpcResponse {
    code: i64,
    #[serde(default)]
    msg: Option<String>,
    #[serde(rename = "resData", default)]
    res_data: Option<Value>,
}

#[derive(Serialize, Debug)]
struct RpcRequest<'a> {
    method: &'a str,
    params: Value,
}

#[derive(Deserialize, Debug)]
struct LoginResData {
    #[serde(default)]
    tfa: Option<String>,
}

#[derive(Deserialize, Debug)]
struct NameserverInfoResData {
    #[serde(default)]
    record: Vec<NameserverRecord>,
}

#[derive(Deserialize, Debug)]
struct NameserverRecord {
    id: i64,
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    record_type: String,
    #[serde(default)]
    content: String,
}

impl InwxProvider {
    pub(crate) fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        shared_secret: Option<String>,
        sandbox: bool,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let mut builder = Client::builder();
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        let client = builder
            .build()
            .map_err(|err| Error::Client(format!("Failed to build INWX HTTP client: {err}")))?;
        let endpoint = if sandbox {
            SANDBOX_ENDPOINT.to_string()
        } else {
            DEFAULT_ENDPOINT.to_string()
        };
        Ok(Self {
            client,
            username: username.into(),
            password: password.into(),
            shared_secret,
            endpoint,
            session: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        self.endpoint = endpoint.as_ref().to_string();
        self
    }

    #[cfg(test)]
    pub(crate) fn with_cached_session(self, cookie: impl Into<String>) -> Self {
        *self
            .session
            .lock()
            .expect("INWX test session lock") = Some(SessionState {
            cookie: cookie.into(),
            expires: Instant::now() + SESSION_TTL,
        });
        self
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name().to_string();
        let domain = origin.into_name().to_string();
        let (record_type, content, prio) = inwx_record_payload(&record)?;

        self.ensure_logged_in().await?;

        let mut params = json!({
            "domain": &domain,
            "name": &name,
            "type": record_type,
            "content": content,
            "ttl": ttl,
        });
        if let Some(prio) = prio {
            params["prio"] = json!(prio);
        }

        self.call("nameserver.createRecord", params).await.map(|_| ())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name().to_string();
        let domain = origin.into_name().to_string();
        let (record_type, content, prio) = inwx_record_payload(&record)?;

        self.ensure_logged_in().await?;

        let id = self
            .find_record_id(&domain, &name, record_type, None)
            .await?;

        let mut params = json!({
            "id": id,
            "content": content,
            "ttl": ttl,
        });
        if let Some(prio) = prio {
            params["prio"] = json!(prio);
        }

        self.call("nameserver.updateRecord", params).await.map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name().to_string();
        let domain = origin.into_name().to_string();
        let rtype = inwx_record_type(record_type);

        self.ensure_logged_in().await?;

        let id = self.find_record_id(&domain, &name, rtype, None).await?;
        self.call("nameserver.deleteRecord", json!({ "id": id }))
            .await
            .map(|_| ())
    }

    async fn find_record_id(
        &self,
        domain: &str,
        name: &str,
        record_type: &str,
        content_filter: Option<&str>,
    ) -> crate::Result<i64> {
        let params = json!({
            "domain": domain,
            "name": name,
            "type": record_type,
        });
        let resp = self.call("nameserver.info", params).await?;
        let res_data = resp.res_data.ok_or_else(|| {
            Error::Api(format!(
                "INWX nameserver.info returned no resData for {name} {record_type}"
            ))
        })?;
        let info: NameserverInfoResData = serde_json::from_value(res_data)
            .map_err(|err| Error::Api(format!("Failed to parse INWX nameserver.info: {err}")))?;

        info.record
            .into_iter()
            .find(|record| {
                record.record_type.eq_ignore_ascii_case(record_type)
                    && content_filter.is_none_or(|expected| record.content == expected)
                    && (record.name == name
                        || record.name.trim_end_matches('.') == name.trim_end_matches('.'))
            })
            .map(|record| record.id)
            .ok_or_else(|| {
                Error::Api(format!(
                    "INWX record {name} of type {record_type} not found"
                ))
            })
    }

    async fn ensure_logged_in(&self) -> crate::Result<()> {
        if let Some(state) = self.session.lock().ok().and_then(|guard| guard.clone())
            && Instant::now() < state.expires
        {
            return Ok(());
        }
        self.login().await
    }

    async fn login(&self) -> crate::Result<()> {
        let params = json!({
            "user": &self.username,
            "pass": &self.password,
        });
        let response = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .json(&RpcRequest {
                method: "account.login",
                params,
            })
            .send()
            .await
            .map_err(|err| Error::Api(format!("INWX login request failed: {err}")))?;

        let cookie = response
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|value| value.split(';').next().map(|part| part.trim().to_string()))
            .unwrap_or_default();

        let rpc: RpcResponse = response.json().await.map_err(|err| {
            Error::Api(format!("Failed to parse INWX login response: {err}"))
        })?;
        if rpc.code / 1000 != 1 {
            return Err(Error::Api(format!(
                "INWX login failed: code={} message={}",
                rpc.code,
                rpc.msg.unwrap_or_default()
            )));
        }

        let login: LoginResData = rpc
            .res_data
            .map(serde_json::from_value)
            .transpose()
            .map_err(|err| Error::Api(format!("Failed to parse INWX login resData: {err}")))?
            .unwrap_or(LoginResData { tfa: None });

        if let Some(tfa) = login.tfa.as_deref()
            && !tfa.is_empty()
            && tfa != "0"
        {
            if self.shared_secret.is_some() {
                return Err(Error::Api(
                    "INWX 2FA TOTP is not supported by this port".into(),
                ));
            }
            return Err(Error::Api(format!(
                "INWX account requires 2FA ({tfa}); not supported by this port"
            )));
        }

        if let Ok(mut guard) = self.session.lock() {
            *guard = Some(SessionState {
                cookie,
                expires: Instant::now() + SESSION_TTL,
            });
        }
        Ok(())
    }

    async fn call(&self, method: &str, params: Value) -> crate::Result<RpcResponse> {
        let cookie = self
            .session
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|state| state.cookie.clone()))
            .unwrap_or_default();

        let mut request = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .json(&RpcRequest { method, params });
        if !cookie.is_empty() {
            request = request.header(reqwest::header::COOKIE, &cookie);
        }

        let response = request.send().await.map_err(|err| {
            Error::Api(format!("INWX request to {method} failed: {err}"))
        })?;
        let status = response.status();
        let body = response.text().await.map_err(|err| {
            Error::Api(format!("Failed to read INWX response body: {err}"))
        })?;

        if !status.is_success() {
            return match status.as_u16() {
                401 => Err(Error::Unauthorized),
                404 => Err(Error::NotFound),
                400 => Err(Error::BadRequest),
                _ => Err(Error::Api(format!(
                    "INWX returned HTTP {status} for {method}: {body}"
                ))),
            };
        }

        let rpc: RpcResponse = serde_json::from_str(&body).map_err(|err| {
            Error::Api(format!("Failed to parse INWX response from {method}: {err}"))
        })?;
        if rpc.code / 1000 != 1 {
            return Err(Error::Api(format!(
                "INWX {method} failed: code={} message={}",
                rpc.code,
                rpc.msg.clone().unwrap_or_default()
            )));
        }
        Ok(rpc)
    }
}

fn inwx_record_type(record_type: DnsRecordType) -> &'static str {
    match record_type {
        DnsRecordType::A => "A",
        DnsRecordType::AAAA => "AAAA",
        DnsRecordType::CNAME => "CNAME",
        DnsRecordType::NS => "NS",
        DnsRecordType::MX => "MX",
        DnsRecordType::TXT => "TXT",
        DnsRecordType::SRV => "SRV",
        DnsRecordType::TLSA => "TLSA",
        DnsRecordType::CAA => "CAA",
    }
}

fn inwx_record_payload(
    record: &DnsRecord,
) -> crate::Result<(&'static str, String, Option<u16>)> {
    Ok(match record {
        DnsRecord::A(ip) => ("A", ip.to_string(), None),
        DnsRecord::AAAA(ip) => ("AAAA", ip.to_string(), None),
        DnsRecord::CNAME(name) => ("CNAME", name.clone(), None),
        DnsRecord::NS(name) => ("NS", name.clone(), None),
        DnsRecord::MX(mx) => ("MX", mx.exchange.clone(), Some(mx.priority)),
        DnsRecord::TXT(value) => ("TXT", value.clone(), None),
        DnsRecord::SRV(srv) => (
            "SRV",
            format!("{} {} {}", srv.weight, srv.port, srv.target),
            Some(srv.priority),
        ),
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by INWX".into(),
            ));
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            (
                "CAA",
                format!("{flags} {tag} \"{value}\""),
                None,
            )
        }
    })
}

