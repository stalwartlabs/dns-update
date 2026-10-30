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

use crate::utils::{build_caa, parse_mx, parse_srv, strip_trailing_dot, unquote_txt};
use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn,
    http::{HttpClient, HttpClientBuilder},
    utils::txt_chunks_to_text,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const DEFAULT_API_ENDPOINT: &str = "https://api.selectel.ru/domains/v2";
const DEFAULT_AUTH_ENDPOINT: &str = "https://cloud.api.selcloud.ru/identity/v3";
const SELECTEL_MIN_TTL: u32 = 60;
const ZONE_CACHE_TTL: Duration = Duration::from_secs(300);
const TOKEN_FALLBACK_TTL: Duration = Duration::from_secs(3600);
const TOKEN_EXPIRY_MARGIN: Duration = Duration::from_secs(300);
const RETRIES: u32 = 3;

#[derive(Clone)]
pub struct SelectelProvider {
    client: HttpClient,
    username: String,
    password: String,
    account_id: String,
    project_id: String,
    api_endpoint: String,
    auth_endpoint: String,
    token: Arc<Mutex<Option<(String, Instant)>>>,
    zones: Arc<Mutex<HashMap<String, (Zone, Instant)>>>,
}

#[derive(Deserialize, Debug, Clone)]
struct Zone {
    id: String,
    name: String,
}

#[derive(Deserialize, Debug)]
struct ListResponse<T> {
    #[serde(default = "Vec::new")]
    result: Vec<T>,
}

#[derive(Deserialize, Debug)]
struct RRSet {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    ttl: u32,
    #[serde(default)]
    records: Vec<RecordItem>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RecordItem {
    content: String,
    #[serde(default)]
    disabled: bool,
}

#[derive(Serialize, Debug)]
struct CreateRRSet<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    ttl: u32,
    records: Vec<RecordItem>,
}

#[derive(Serialize, Debug)]
struct UpdateRRSet {
    ttl: u32,
    records: Vec<RecordItem>,
}

#[derive(Deserialize)]
struct EmptyResponse {}

#[derive(Serialize)]
struct AuthRequest<'a> {
    auth: Auth<'a>,
}

#[derive(Serialize)]
struct Auth<'a> {
    identity: Identity<'a>,
    scope: Scope<'a>,
}

#[derive(Serialize)]
struct Identity<'a> {
    methods: [&'a str; 1],
    password: PasswordIdentity<'a>,
}

#[derive(Serialize)]
struct PasswordIdentity<'a> {
    user: User<'a>,
}

#[derive(Serialize)]
struct User<'a> {
    name: &'a str,
    domain: NamedDomain<'a>,
    password: &'a str,
}

#[derive(Serialize)]
struct NamedDomain<'a> {
    name: &'a str,
}

#[derive(Serialize)]
struct Scope<'a> {
    project: Project<'a>,
}

#[derive(Serialize)]
struct Project<'a> {
    id: &'a str,
}

#[derive(Deserialize)]
struct AuthResponse {
    token: TokenInfo,
}

#[derive(Deserialize)]
struct TokenInfo {
    #[serde(default)]
    expires_at: Option<String>,
}

impl SelectelProvider {
    pub(crate) fn new(
        username: impl AsRef<str>,
        password: impl AsRef<str>,
        account_id: impl AsRef<str>,
        project_id: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let username = username.as_ref().to_string();
        let password = password.as_ref().to_string();
        let account_id = account_id.as_ref().to_string();
        let project_id = project_id.as_ref().to_string();
        if username.is_empty()
            || password.is_empty()
            || account_id.is_empty()
            || project_id.is_empty()
        {
            return Err(Error::Api(
                "Selectel username, password, account ID and project ID must not be empty"
                    .to_string(),
            ));
        }

        let client = HttpClientBuilder::default()
            .with_header("Accept", "application/json")
            .with_timeout(timeout)
            .build();

        Ok(Self {
            client,
            username,
            password,
            account_id,
            project_id,
            api_endpoint: DEFAULT_API_ENDPOINT.to_string(),
            auth_endpoint: DEFAULT_AUTH_ENDPOINT.to_string(),
            token: Arc::new(Mutex::new(None)),
            zones: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        let base = endpoint.as_ref().trim_end_matches('/').to_string();
        Self {
            api_endpoint: format!("{base}/domains/v2"),
            auth_endpoint: format!("{base}/identity/v3"),
            ..self
        }
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let contents = build_contents(record_type, &records)?;
        let token = self.ensure_token().await?;
        let fqdn = name.into_fqdn().to_ascii_lowercase();
        let zone = self.resolve_zone(&origin.into_name(), &token).await?;
        let existing = self.find_rrset(&zone, &fqdn, record_type, &token).await?;

        match (existing, contents.is_empty()) {
            (Some(rrset), true) => self.delete_rrset(&zone, &rrset.id, &token).await,
            (None, true) => Ok(()),
            (Some(rrset), false) if rrset_matches(&rrset, record_type, ttl, &records) => Ok(()),
            (Some(rrset), false) => {
                self.update_rrset(&zone, &rrset.id, ttl, to_items(contents), &token)
                    .await
            }
            (None, false) => {
                self.create_rrset(&zone, &fqdn, record_type, ttl, to_items(contents), &token)
                    .await
            }
        }
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let contents = build_contents(record_type, &records)?;
        if contents.is_empty() {
            return Ok(());
        }
        let token = self.ensure_token().await?;
        let fqdn = name.into_fqdn().to_ascii_lowercase();
        let zone = self.resolve_zone(&origin.into_name(), &token).await?;

        let Some(rrset) = self.find_rrset(&zone, &fqdn, record_type, &token).await? else {
            return self
                .create_rrset(&zone, &fqdn, record_type, ttl, to_items(contents), &token)
                .await;
        };

        let mut items = rrset.records;
        let before = items.len();
        for (record, content) in records.iter().zip(contents) {
            if !items
                .iter()
                .any(|item| content_matches(record_type, &item.content, record))
            {
                items.push(RecordItem {
                    content,
                    disabled: false,
                });
            }
        }

        if items.len() == before {
            return Ok(());
        }

        self.update_rrset(&zone, &rrset.id, ttl, items, &token)
            .await
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        build_contents(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let token = self.ensure_token().await?;
        let fqdn = name.into_fqdn().to_ascii_lowercase();
        let zone = self.resolve_zone(&origin.into_name(), &token).await?;

        let Some(rrset) = self.find_rrset(&zone, &fqdn, record_type, &token).await? else {
            return Ok(());
        };

        let before = rrset.records.len();
        let remaining: Vec<RecordItem> = rrset
            .records
            .into_iter()
            .filter(|item| {
                !records
                    .iter()
                    .any(|record| content_matches(record_type, &item.content, record))
            })
            .collect();

        if remaining.len() == before {
            return Ok(());
        }

        if remaining.is_empty() {
            return self.delete_rrset(&zone, &rrset.id, &token).await;
        }

        self.update_rrset(&zone, &rrset.id, rrset.ttl, remaining, &token)
            .await
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let token = self.ensure_token().await?;
        let fqdn = name.into_fqdn().to_ascii_lowercase();
        let zone = self.resolve_zone(&origin.into_name(), &token).await?;

        match self.find_rrset(&zone, &fqdn, record_type, &token).await? {
            Some(rrset) => rrset
                .records
                .iter()
                .map(|item| parse_content(record_type, &item.content))
                .collect(),
            None => Ok(Vec::new()),
        }
    }

    async fn ensure_token(&self) -> crate::Result<String> {
        if let Some((token, expiry)) = self.token_lock()?.as_ref()
            && Instant::now() < *expiry
        {
            return Ok(token.clone());
        }

        let body = AuthRequest {
            auth: Auth {
                identity: Identity {
                    methods: ["password"],
                    password: PasswordIdentity {
                        user: User {
                            name: &self.username,
                            domain: NamedDomain {
                                name: &self.account_id,
                            },
                            password: &self.password,
                        },
                    },
                },
                scope: Scope {
                    project: Project {
                        id: &self.project_id,
                    },
                },
            },
        };

        let (response, headers) = self
            .client
            .post(format!("{}/auth/tokens", self.auth_endpoint))
            .with_body(body)?
            .send_raw_with_headers()
            .await?;

        let token = headers
            .get("x-subject-token")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                Error::Api("Selectel auth response is missing X-Subject-Token".to_string())
            })?
            .to_string();

        let lifetime = serde_json::from_str::<AuthResponse>(&response)
            .ok()
            .and_then(|response| response.token.expires_at)
            .and_then(|expires_at| expires_at.parse::<Timestamp>().ok())
            .and_then(|expires_at| {
                Duration::try_from(expires_at.duration_since(Timestamp::now())).ok()
            })
            .map(|lifetime| lifetime.saturating_sub(TOKEN_EXPIRY_MARGIN))
            .unwrap_or(TOKEN_FALLBACK_TTL);

        *self.token_lock()? = Some((token.clone(), Instant::now() + lifetime));
        Ok(token)
    }

    fn token_lock(&self) -> crate::Result<std::sync::MutexGuard<'_, Option<(String, Instant)>>> {
        self.token
            .lock()
            .map_err(|_| Error::Client("Selectel token lock poisoned".to_string()))
    }

    fn forget_token_on_unauthorized<T>(&self, result: crate::Result<T>) -> crate::Result<T> {
        if matches!(result, Err(Error::Unauthorized))
            && let Ok(mut guard) = self.token.lock()
        {
            *guard = None;
        }
        result
    }

    async fn resolve_zone(&self, origin: &str, token: &str) -> crate::Result<Zone> {
        let origin = origin.trim_end_matches('.').to_ascii_lowercase();

        if let Ok(guard) = self.zones.lock()
            && let Some((zone, expiry)) = guard.get(&origin)
            && Instant::now() < *expiry
        {
            return Ok(zone.clone());
        }

        let mut candidate = origin.as_str();
        loop {
            let query = serde_urlencoded::to_string([("filter", candidate)])
                .map_err(|e| Error::Serialize(e.to_string()))?;
            let response = self.forget_token_on_unauthorized(
                self.client
                    .get(format!("{}/zones?{}", self.api_endpoint, query))
                    .with_header("X-Auth-Token", token)
                    .send_with_retry::<ListResponse<Zone>>(RETRIES)
                    .await,
            )?;

            if let Some(zone) = response
                .result
                .into_iter()
                .find(|zone| strip_trailing_dot(&zone.name).eq_ignore_ascii_case(candidate))
            {
                if let Ok(mut guard) = self.zones.lock() {
                    guard.insert(
                        origin.clone(),
                        (zone.clone(), Instant::now() + ZONE_CACHE_TTL),
                    );
                }
                return Ok(zone);
            }

            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => {
                    return Err(Error::Api(format!("Selectel zone not found for {origin}")));
                }
            }
        }
    }

    async fn find_rrset(
        &self,
        zone: &Zone,
        fqdn: &str,
        record_type: DnsRecordType,
        token: &str,
    ) -> crate::Result<Option<RRSet>> {
        let query = serde_urlencoded::to_string([
            ("name", strip_trailing_dot(fqdn)),
            ("rrset_types", record_type.as_str()),
        ])
        .map_err(|e| Error::Serialize(e.to_string()))?;

        let response = match self.forget_token_on_unauthorized(
            self.client
                .get(format!(
                    "{}/zones/{}/rrset?{}",
                    self.api_endpoint, zone.id, query
                ))
                .with_header("X-Auth-Token", token)
                .send_with_retry::<ListResponse<RRSet>>(RETRIES)
                .await,
        ) {
            Ok(response) => response,
            Err(Error::NotFound) => return Ok(None),
            Err(err) => return Err(err),
        };

        Ok(response.result.into_iter().find(|rrset| {
            rrset.record_type.eq_ignore_ascii_case(record_type.as_str())
                && strip_trailing_dot(&rrset.name).eq_ignore_ascii_case(strip_trailing_dot(fqdn))
        }))
    }

    async fn create_rrset(
        &self,
        zone: &Zone,
        fqdn: &str,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<RecordItem>,
        token: &str,
    ) -> crate::Result<()> {
        self.forget_token_on_unauthorized(
            self.client
                .post(format!("{}/zones/{}/rrset", self.api_endpoint, zone.id))
                .with_header("X-Auth-Token", token)
                .with_body(CreateRRSet {
                    name: fqdn,
                    record_type: record_type.as_str(),
                    ttl: ttl.max(SELECTEL_MIN_TTL),
                    records,
                })?
                .send_with_retry::<EmptyResponse>(RETRIES)
                .await,
        )
        .map(|_| ())
    }

    async fn update_rrset(
        &self,
        zone: &Zone,
        rrset_id: &str,
        ttl: u32,
        records: Vec<RecordItem>,
        token: &str,
    ) -> crate::Result<()> {
        self.forget_token_on_unauthorized(
            self.client
                .patch(format!(
                    "{}/zones/{}/rrset/{}",
                    self.api_endpoint, zone.id, rrset_id
                ))
                .with_header("X-Auth-Token", token)
                .with_body(UpdateRRSet {
                    ttl: ttl.max(SELECTEL_MIN_TTL),
                    records,
                })?
                .send_with_retry::<EmptyResponse>(RETRIES)
                .await,
        )
        .map(|_| ())
    }

    async fn delete_rrset(&self, zone: &Zone, rrset_id: &str, token: &str) -> crate::Result<()> {
        match self.forget_token_on_unauthorized(
            self.client
                .delete(format!(
                    "{}/zones/{}/rrset/{}",
                    self.api_endpoint, zone.id, rrset_id
                ))
                .with_header("X-Auth-Token", token)
                .send_with_retry::<EmptyResponse>(RETRIES)
                .await,
        ) {
            Ok(_) | Err(Error::NotFound) => Ok(()),
            Err(err) => Err(err),
        }
    }
}

fn to_items(contents: Vec<String>) -> Vec<RecordItem> {
    contents
        .into_iter()
        .map(|content| RecordItem {
            content,
            disabled: false,
        })
        .collect()
}

fn build_contents(expected: DnsRecordType, records: &[DnsRecord]) -> crate::Result<Vec<String>> {
    if expected == DnsRecordType::TLSA {
        return Err(Error::Unsupported(
            "TLSA records are not supported by Selectel".to_string(),
        ));
    }
    records
        .iter()
        .map(|record| {
            if record.as_type() != expected {
                return Err(Error::Api(format!(
                    "RRSet record type mismatch: expected {}, got {}",
                    expected.as_str(),
                    record.as_type().as_str(),
                )));
            }
            Ok(render_content(record))
        })
        .collect()
}

fn render_content(record: &DnsRecord) -> String {
    match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(target) => target.into_fqdn().into_owned(),
        DnsRecord::NS(target) => target.into_fqdn().into_owned(),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, (&mx.exchange).into_fqdn()),
        DnsRecord::TXT(text) => {
            let mut out = String::with_capacity(text.len() + 4);
            txt_chunks_to_text(&mut out, text, " ");
            out
        }
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            (&srv.target).into_fqdn()
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    }
}

fn content_matches(record_type: DnsRecordType, content: &str, record: &DnsRecord) -> bool {
    parse_content(record_type, content).is_ok_and(|parsed| same_record(&parsed, record))
}

fn rrset_matches(
    rrset: &RRSet,
    record_type: DnsRecordType,
    ttl: u32,
    records: &[DnsRecord],
) -> bool {
    rrset.ttl == ttl.max(SELECTEL_MIN_TTL)
        && rrset.records.iter().all(|item| {
            !item.disabled
                && records
                    .iter()
                    .any(|record| content_matches(record_type, &item.content, record))
        })
        && records.iter().all(|record| {
            rrset
                .records
                .iter()
                .any(|item| content_matches(record_type, &item.content, record))
        })
}

fn same_record(a: &DnsRecord, b: &DnsRecord) -> bool {
    match (a, b) {
        (DnsRecord::CNAME(a), DnsRecord::CNAME(b)) | (DnsRecord::NS(a), DnsRecord::NS(b)) => {
            same_host(a, b)
        }
        (DnsRecord::MX(a), DnsRecord::MX(b)) => {
            a.priority == b.priority && same_host(&a.exchange, &b.exchange)
        }
        (DnsRecord::SRV(a), DnsRecord::SRV(b)) => {
            a.priority == b.priority
                && a.weight == b.weight
                && a.port == b.port
                && same_host(&a.target, &b.target)
        }
        _ => a == b,
    }
}

fn same_host(a: &str, b: &str) -> bool {
    strip_trailing_dot(a).eq_ignore_ascii_case(strip_trailing_dot(b))
}

fn parse_content(record_type: DnsRecordType, content: &str) -> crate::Result<DnsRecord> {
    let content = content.trim();
    match record_type {
        DnsRecordType::A => content
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A record '{content}': {e}"))),
        DnsRecordType::AAAA => content
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA record '{content}': {e}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(strip_trailing_dot(content).to_string())),
        DnsRecordType::NS => Ok(DnsRecord::NS(strip_trailing_dot(content).to_string())),
        DnsRecordType::MX => parse_mx(content),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(unquote_txt(content))),
        DnsRecordType::SRV => parse_srv(content),
        DnsRecordType::TLSA => Err(Error::Unsupported(
            "TLSA records are not supported by Selectel".to_string(),
        )),
        DnsRecordType::CAA => parse_caa(content),
    }
}

fn parse_caa(content: &str) -> crate::Result<DnsRecord> {
    let mut parts = content.splitn(3, char::is_whitespace);
    let (Some(flags), Some(tag), Some(value)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(Error::Parse(format!("invalid CAA record '{content}'")));
    };
    let flags: u8 = flags
        .parse()
        .map_err(|e| Error::Parse(format!("invalid CAA flags in '{content}': {e}")))?;
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    build_caa(flags, &tag.to_ascii_lowercase(), value).map(DnsRecord::CAA)
}
