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
    http::HttpClientBuilder, utils::strip_origin_from_name, utils::txt_chunks_to_text,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_API_ENDPOINT: &str = "https://dmapi.joker.com/request";
const MIN_TTL: u32 = 300;

#[derive(Clone)]
pub enum JokerAuth {
    ApiKey(String),
    UsernamePassword { username: String, password: String },
}

impl JokerAuth {
    pub fn api_key(key: impl Into<String>) -> Self {
        Self::ApiKey(key.into())
    }

    pub fn username_password(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::UsernamePassword {
            username: username.into(),
            password: password.into(),
        }
    }

    fn login_params(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::ApiKey(key) => vec![("api-key", key.clone())],
            Self::UsernamePassword { username, password } => vec![
                ("username", username.clone()),
                ("password", password.clone()),
            ],
        }
    }

    fn validate(&self) -> crate::Result<()> {
        match self {
            Self::ApiKey(key) if key.is_empty() => {
                Err(Error::Api("Joker API key must not be empty".to_string()))
            }
            Self::UsernamePassword { username, password }
                if username.is_empty() || password.is_empty() =>
            {
                Err(Error::Api(
                    "Joker username and password must not be empty".to_string(),
                ))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone)]
pub struct JokerProvider {
    auth: Arc<Mutex<AuthState>>,
    credentials: JokerAuth,
    endpoint: String,
    timeout: Option<Duration>,
}

struct AuthState {
    session: Option<(String, Instant)>,
}

impl JokerProvider {
    pub(crate) fn new(auth: JokerAuth, timeout: Option<Duration>) -> crate::Result<Self> {
        auth.validate()?;
        Ok(Self {
            auth: Arc::new(Mutex::new(AuthState { session: None })),
            credentials: auth,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            timeout,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().trim_end_matches('/').to_string(),
            ..self
        }
    }

    fn http_client(&self) -> HttpClientBuilder {
        HttpClientBuilder::default()
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_header("Accept", "text/plain")
            .with_timeout(self.timeout)
    }

    fn clear_session(&self) {
        if let Ok(mut guard) = self.auth.lock() {
            guard.session = None;
        }
    }

    async fn login(&self) -> crate::Result<String> {
        let params = self.credentials.login_params();
        let body =
            serde_urlencoded::to_string(&params).map_err(|e| Error::Serialize(e.to_string()))?;

        let response = self
            .http_client()
            .post(format!("{}/login", self.endpoint))
            .with_raw_body(body)
            .send_raw()
            .await?;

        let parsed = parse_response(&response);
        check_status(&parsed)?;
        let sid = parsed
            .auth_sid
            .ok_or_else(|| Error::Api("Joker login did not return Auth-Sid".to_string()))?;

        let expiry = Instant::now() + Duration::from_secs(50 * 60);
        let mut guard = self
            .auth
            .lock()
            .map_err(|_| Error::Client("Joker session lock poisoned".to_string()))?;
        guard.session = Some((sid.clone(), expiry));
        Ok(sid)
    }

    async fn ensure_session(&self) -> crate::Result<String> {
        {
            let guard = self
                .auth
                .lock()
                .map_err(|_| Error::Client("Joker session lock poisoned".to_string()))?;
            if let Some((sid, expiry)) = &guard.session
                && Instant::now() < *expiry
            {
                return Ok(sid.clone());
            }
        }
        self.login().await
    }

    async fn dmapi_call(
        &self,
        path: &str,
        extra: &[(&str, &str)],
    ) -> crate::Result<ParsedResponse> {
        for attempt in 0..2u8 {
            let sid = self.ensure_session().await?;
            let mut params: Vec<(&str, &str)> = vec![("auth-sid", sid.as_str())];
            params.extend_from_slice(extra);
            let body = serde_urlencoded::to_string(&params)
                .map_err(|e| Error::Serialize(e.to_string()))?;

            let response = self
                .http_client()
                .post(format!("{}/{}", self.endpoint, path))
                .with_raw_body(body)
                .send_raw()
                .await?;

            let parsed = parse_response(&response);
            if attempt == 0 && is_auth_failure(&parsed) {
                self.clear_session();
                continue;
            }
            check_status(&parsed)?;
            return Ok(parsed);
        }
        Err(Error::Api("Joker DMAPI: repeated auth failure".to_string()))
    }

    async fn get_zone(&self, domain: &str) -> crate::Result<String> {
        let parsed = self
            .dmapi_call("dns-zone-get", &[("domain", domain)])
            .await?;
        Ok(parsed.body)
    }

    async fn put_zone(&self, domain: &str, zone: String) -> crate::Result<()> {
        let trimmed = zone.trim().to_string();
        self.dmapi_call(
            "dns-zone-put",
            &[("domain", domain), ("zone", trimmed.as_str())],
        )
        .await?;
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
        reject_tlsa(record_type)?;

        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let ttl = clamp_ttl(ttl);

        let mut new_entries: Vec<String> = Vec::new();
        for record in &records {
            let rendered = render_zone_entries(&subdomain, record, ttl)?;
            new_entries.extend(rendered);
        }

        let zone = self.get_zone(&domain).await?;
        let pruned = remove_entries(&zone, &subdomain, record_type);

        if records.is_empty() {
            if pruned.trim() == zone.trim() {
                return Ok(());
            }
            return self.put_zone(&domain, pruned).await;
        }

        let mut updated = pruned;
        append_lines(&mut updated, &new_entries);
        self.put_zone(&domain, updated).await
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

        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let ttl = clamp_ttl(ttl);

        let zone = self.get_zone(&domain).await?;
        let existing_rdata = collect_rdata(&zone, &subdomain, record_type);

        let mut to_append: Vec<String> = Vec::new();
        for record in &records {
            let rendered = render_zone_entries(&subdomain, record, ttl)?;
            for line in rendered {
                let rdata = extract_rdata(&line, &subdomain, record_type);
                let already = existing_rdata
                    .iter()
                    .any(|present| rdata_equivalent(present, &rdata));
                let queued = to_append
                    .iter()
                    .map(|l| extract_rdata(l, &subdomain, record_type))
                    .any(|q| rdata_equivalent(&q, &rdata));
                if !already && !queued {
                    to_append.push(line);
                }
            }
        }

        if to_append.is_empty() {
            return Ok(());
        }

        let mut updated = zone.trim_end().to_string();
        append_lines(&mut updated, &to_append);
        self.put_zone(&domain, updated).await
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

        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));

        let mut targets: Vec<String> = Vec::new();
        for record in &records {
            let rendered = render_zone_entries(&subdomain, record, MIN_TTL)?;
            for line in rendered {
                targets.push(extract_rdata(&line, &subdomain, record_type));
            }
        }

        let zone = self.get_zone(&domain).await?;
        let updated = filter_lines(&zone, |line| {
            if !line_matches_name_and_type(line, &subdomain, record_type) {
                return true;
            }
            let rdata = extract_rdata(line, &subdomain, record_type);
            !targets.iter().any(|t| rdata_equivalent(t, &rdata))
        });

        if updated.trim() == zone.trim() {
            return Ok(());
        }
        self.put_zone(&domain, updated).await
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        reject_tlsa(record_type)?;

        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let zone = self.get_zone(&domain).await?;

        let mut out = Vec::new();
        for line in zone.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('$') {
                continue;
            }
            if !line_matches_name_and_type(line, &subdomain, record_type) {
                continue;
            }
            let fields = tokenize_zone_line(trimmed);
            if let Some(record) = parse_zone_record(record_type, &fields)? {
                out.push(record);
            }
        }
        Ok(out)
    }
}

#[derive(Default, Debug)]
struct ParsedResponse {
    status_code: Option<i64>,
    status_text: String,
    auth_sid: Option<String>,
    body: String,
}

fn parse_response(message: &str) -> ParsedResponse {
    let mut parsed = ParsedResponse::default();
    let (head, body) = match message.split_once("\n\n") {
        Some(parts) => parts,
        None => (message, ""),
    };
    for line in head.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let value = v.trim();
            match key {
                "Status-Code" => parsed.status_code = value.parse().ok(),
                "Status-Text" => parsed.status_text = value.to_string(),
                "Auth-Sid" => parsed.auth_sid = Some(value.to_string()),
                _ => {}
            }
        }
    }
    parsed.body = body.to_string();
    parsed
}

fn check_status(parsed: &ParsedResponse) -> crate::Result<()> {
    match parsed.status_code {
        Some(0) | None => Ok(()),
        Some(code) => Err(Error::Api(format!(
            "Joker DMAPI error {}: {}",
            code, parsed.status_text
        ))),
    }
}

fn is_auth_failure(parsed: &ParsedResponse) -> bool {
    match parsed.status_code {
        Some(code) if code != 0 => {
            let text = parsed.status_text.to_ascii_lowercase();
            text.contains("auth")
                || text.contains("session")
                || text.contains("login")
                || text.contains("not logged")
                || text.contains("sid")
        }
        _ => false,
    }
}

fn clamp_ttl(ttl: u32) -> u32 {
    ttl.max(MIN_TTL)
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
            "TLSA records are not supported by Joker.com".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn render_zone_entries(host: &str, record: &DnsRecord, ttl: u32) -> crate::Result<Vec<String>> {
    let (label, priority, values) = match record {
        DnsRecord::A(addr) => ("A", 0u16, vec![addr.to_string()]),
        DnsRecord::AAAA(addr) => ("AAAA", 0, vec![addr.to_string()]),
        DnsRecord::CNAME(content) => ("CNAME", 0, vec![ensure_dot(content)]),
        DnsRecord::NS(content) => ("NS", 0, vec![ensure_dot(content)]),
        DnsRecord::MX(mx) => ("MX", mx.priority, vec![ensure_dot(&mx.exchange)]),
        DnsRecord::TXT(content) => {
            let mut quoted = String::new();
            txt_chunks_to_text(&mut quoted, content, " ");
            ("TXT", 0, vec![quoted])
        }
        DnsRecord::SRV(srv) => (
            "SRV",
            srv.priority,
            vec![format!(
                "{} {} {}",
                srv.weight,
                srv.port,
                ensure_dot(&srv.target)
            )],
        ),
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Joker.com".to_string(),
            ));
        }
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            ("CAA", 0, vec![format!("{flags} {tag} \"{value}\"")])
        }
    };

    Ok(values
        .into_iter()
        .map(|value| format!("{host} {label} {priority} {value} {ttl}"))
        .collect())
}

fn ensure_dot(value: &str) -> String {
    if value.ends_with('.') {
        value.to_string()
    } else {
        format!("{value}.")
    }
}

fn append_lines(zone: &mut String, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    if !zone.is_empty() && !zone.ends_with('\n') {
        zone.push('\n');
    }
    for line in lines {
        zone.push_str(line);
        zone.push('\n');
    }
    while zone.ends_with("\n\n") {
        zone.pop();
    }
}

fn filter_lines<F>(zone: &str, mut keep: F) -> String
where
    F: FnMut(&str) -> bool,
{
    let mut out = String::new();
    for line in zone.lines() {
        if keep(line) {
            out.push_str(line);
            out.push('\n');
        }
    }
    out.trim_end().to_string()
}

fn line_matches_name_and_type(line: &str, host: &str, record_type: DnsRecordType) -> bool {
    let trimmed = line.trim_start();
    let prefix = format!("{} {}", host, record_type.as_str());
    if !trimmed.starts_with(&prefix) {
        return false;
    }
    let rest = &trimmed[prefix.len()..];
    rest.starts_with([' ', '\t'])
}

fn remove_entries(zone: &str, host: &str, record_type: DnsRecordType) -> String {
    filter_lines(zone, |line| {
        !line_matches_name_and_type(line, host, record_type)
    })
}

fn collect_rdata(zone: &str, host: &str, record_type: DnsRecordType) -> Vec<String> {
    let mut out = Vec::new();
    for line in zone.lines() {
        if line_matches_name_and_type(line, host, record_type) {
            out.push(extract_rdata(line, host, record_type));
        }
    }
    out
}

fn extract_rdata(line: &str, host: &str, record_type: DnsRecordType) -> String {
    let trimmed = line.trim();
    let fields = tokenize_zone_line(trimmed);
    if fields.len() < 5 {
        return String::new();
    }
    let label_matches = fields[0] == host;
    let type_matches = fields[1].eq_ignore_ascii_case(record_type.as_str());
    if !label_matches || !type_matches {
        return String::new();
    }
    let priority = &fields[2];
    let value_tokens: &[String] = match record_type {
        DnsRecordType::MX | DnsRecordType::SRV => &fields[3..fields.len().saturating_sub(1)],
        _ => &fields[3..fields.len().saturating_sub(1)],
    };
    let value = value_tokens.join(" ");
    format!("{priority} {value}")
}

fn rdata_equivalent(a: &str, b: &str) -> bool {
    a == b
}

fn tokenize_zone_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => {
                current.push(ch);
                escaped = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn parse_zone_record(
    record_type: DnsRecordType,
    fields: &[String],
) -> crate::Result<Option<DnsRecord>> {
    if fields.len() < 5 {
        return Ok(None);
    }
    let priority_str = &fields[2];
    let trailing_meta = fields.len().saturating_sub(1);
    let value_tokens = &fields[3..trailing_meta];
    if value_tokens.is_empty() {
        return Ok(None);
    }

    Ok(Some(match record_type {
        DnsRecordType::A => {
            let addr = value_tokens[0]
                .parse()
                .map_err(|err| Error::Parse(format!("invalid A address: {err}")))?;
            DnsRecord::A(addr)
        }
        DnsRecordType::AAAA => {
            let addr = value_tokens[0]
                .parse()
                .map_err(|err| Error::Parse(format!("invalid AAAA address: {err}")))?;
            DnsRecord::AAAA(addr)
        }
        DnsRecordType::CNAME => DnsRecord::CNAME(strip_trailing_dot(&value_tokens[0])),
        DnsRecordType::NS => DnsRecord::NS(strip_trailing_dot(&value_tokens[0])),
        DnsRecordType::MX => {
            let priority: u16 = priority_str
                .parse()
                .map_err(|err| Error::Parse(format!("invalid MX priority: {err}")))?;
            DnsRecord::MX(MXRecord {
                priority,
                exchange: strip_trailing_dot(&value_tokens[0]),
            })
        }
        DnsRecordType::TXT => DnsRecord::TXT(unquote_txt_tokens(value_tokens)),
        DnsRecordType::SRV => {
            if value_tokens.len() < 3 {
                return Err(Error::Parse(
                    "SRV record requires weight port target".to_string(),
                ));
            }
            let priority: u16 = priority_str
                .parse()
                .map_err(|err| Error::Parse(format!("invalid SRV priority: {err}")))?;
            let weight: u16 = value_tokens[0]
                .parse()
                .map_err(|err| Error::Parse(format!("invalid SRV weight: {err}")))?;
            let port: u16 = value_tokens[1]
                .parse()
                .map_err(|err| Error::Parse(format!("invalid SRV port: {err}")))?;
            DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target: strip_trailing_dot(&value_tokens[2]),
            })
        }
        DnsRecordType::CAA => {
            if value_tokens.len() < 3 {
                return Err(Error::Parse(
                    "CAA record requires flags tag value".to_string(),
                ));
            }
            let flags: u8 = value_tokens[0]
                .parse()
                .map_err(|err| Error::Parse(format!("invalid CAA flags: {err}")))?;
            let tag = value_tokens[1].clone();
            let raw_value = value_tokens[2..].join(" ");
            let value = strip_quotes(&raw_value);
            DnsRecord::CAA(build_caa(flags, &tag, &value)?)
        }
        DnsRecordType::TLSA => {
            return Err(Error::Api(
                "TLSA records are not supported by Joker.com".to_string(),
            ));
        }
    }))
}

fn strip_trailing_dot(value: &str) -> String {
    value.strip_suffix('.').unwrap_or(value).to_string()
}

fn strip_quotes(value: &str) -> String {
    let trimmed = value.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .map(|s| s.replace("\\\"", "\"").replace("\\\\", "\\"))
        .unwrap_or_else(|| trimmed.to_string())
}

fn unquote_txt_tokens(tokens: &[String]) -> String {
    let mut out = String::new();
    for token in tokens {
        out.push_str(&strip_quotes(token));
    }
    out
}

fn build_caa(flags: u8, tag: &str, value: &str) -> crate::Result<CAARecord> {
    let issuer_critical = flags & 0x80 != 0;
    match tag {
        "issue" => {
            let (name, options) = parse_caa_value(value);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(value);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: value.to_string(),
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
