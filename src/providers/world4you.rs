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

use crate::utils::{
    build_caa, parse_mx, parse_srv, parse_tlsa, strip_origin_from_name, strip_trailing_dot,
};
use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn,
    http::{HttpClient, HttpClientBuilder},
};
use serde::{Deserialize, Deserializer};
use std::{
    fmt::{Display, Formatter},
    sync::{Arc, Mutex},
    time::Duration,
};

const DEFAULT_API_ENDPOINT: &str = "https://my.world4you.com/en";

#[derive(Clone)]
pub struct World4YouProvider {
    client: HttpClient,
    endpoint: String,
    username: String,
    password: String,
    session: Arc<Mutex<Option<String>>>,
}

#[derive(Deserialize)]
struct PackageList {
    #[serde(default)]
    items: Vec<PackageItem>,
}

#[derive(Deserialize)]
struct PackageItem {
    id: World4YouId,
    fqdn: String,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(untagged)]
enum World4YouId {
    Text(String),
    Number(u64),
}

impl Display for World4YouId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            World4YouId::Text(value) => f.write_str(value),
            World4YouId::Number(value) => write!(f, "{value}"),
        }
    }
}

#[derive(Clone, Debug)]
struct Package {
    id: String,
    fqdn: String,
}

#[derive(Deserialize, Debug, Clone)]
struct RecordEntry {
    id: World4YouId,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default)]
    value: String,
    #[serde(default, deserialize_with = "deserialize_optional_u16")]
    prio: Option<u16>,
}

#[derive(Debug)]
struct FormTokens {
    unique_form_id: String,
    token: String,
}

#[derive(Debug)]
struct WireRecord {
    record_type: &'static str,
    priority: Option<u16>,
    value: String,
}

type RecordKey = (String, Option<u16>, String);

#[derive(Deserialize)]
struct LoginResponse {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    message: Option<String>,
}

impl World4YouProvider {
    pub(crate) fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default()
            .without_header("content-type")
            .with_header(
                "User-Agent",
                concat!("dns-update/", env!("CARGO_PKG_VERSION")),
            )
            .with_timeout(timeout)
            .build();

        Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            username: username.into(),
            password: password.into(),
            session: Arc::new(Mutex::new(None)),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().trim_end_matches('/').to_string(),
            ..self
        }
    }

    fn cached_session(&self) -> Option<String> {
        self.session.lock().ok().and_then(|session| session.clone())
    }

    fn store_session(&self, session_id: String) {
        if let Ok(mut session) = self.session.lock() {
            *session = Some(session_id);
        }
    }

    fn clear_session(&self) {
        if let Ok(mut session) = self.session.lock() {
            *session = None;
        }
    }

    async fn ensure_session(&self) -> crate::Result<String> {
        if let Some(session_id) = self.cached_session() {
            return Ok(session_id);
        }

        self.login().await
    }

    async fn login(&self) -> crate::Result<String> {
        let login_url = format!("{}/login", self.endpoint);
        let (status, page, headers) = self
            .client
            .get(login_url.clone())
            .send_raw_with_status()
            .await?;

        let mut session_id = extract_session_cookie(&headers).ok_or_else(|| {
            Error::Api("World4You login did not return a W4YSESSID cookie".to_string())
        })?;

        if status != 200 {
            self.store_session(session_id.clone());
            return Ok(session_id);
        }

        let csrf_token = input_value(&page, "_csrf_token").ok_or_else(|| {
            Error::Parse("World4You login form is missing the _csrf_token input".to_string())
        })?;

        let body = encode_form(&[
            ("_username", self.username.as_str()),
            ("_password", self.password.as_str()),
            ("_csrf_token", csrf_token.as_str()),
        ])?;

        let (status, response, headers) = self
            .client
            .post(login_url)
            .set_header("Content-Type", "application/x-www-form-urlencoded")
            .with_header("X-Requested-With", "XMLHttpRequest")
            .with_header("Cookie", format!("W4YSESSID={session_id}"))
            .with_raw_body(body)
            .send_raw_with_status()
            .await?;

        if let Some(refreshed) = extract_session_cookie(&headers) {
            session_id = refreshed;
        }

        if status == 302 || status == 303 {
            self.store_session(session_id.clone());
            return Ok(session_id);
        }

        let response: LoginResponse = serde_json::from_str(&response).map_err(|err| {
            Error::Parse(format!(
                "Failed to parse the World4You login response: {err}"
            ))
        })?;

        if !response.success {
            return Err(Error::Api(match response.message {
                Some(message) => format!("World4You login failed: {message}"),
                None => "World4You login failed".to_string(),
            }));
        }

        self.store_session(session_id.clone());
        Ok(session_id)
    }

    async fn get_page(&self, path: &str) -> crate::Result<String> {
        let initial_url = format!("{}{}", self.endpoint, path);
        let mut url = initial_url.clone();
        let mut relogged = false;

        for _ in 0..6 {
            let session_id = self.ensure_session().await?;
            let (status, body, headers) = self
                .client
                .get(url.clone())
                .with_header("Cookie", format!("W4YSESSID={session_id}"))
                .send_raw_with_status()
                .await?;

            if let Some(refreshed) = extract_session_cookie(&headers) {
                self.store_session(refreshed);
            }

            if (300..400).contains(&status) {
                let location = headers
                    .get("location")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default();

                if location.contains("/login") {
                    if relogged {
                        return Err(Error::Api(format!(
                            "World4You redirected {path} to the login page after re-authenticating"
                        )));
                    }

                    relogged = true;
                    self.clear_session();
                    url = initial_url.clone();
                    continue;
                }

                url = same_origin_url(&self.endpoint, location).ok_or_else(|| {
                    Error::Api(format!(
                        "World4You redirected {path} to an unsupported location: {location}"
                    ))
                })?;
                continue;
            }

            if status != 200 {
                return Err(Error::Api(format!(
                    "World4You request to {path} returned HTTP {status}"
                )));
            }

            return Ok(body);
        }

        Err(Error::Api(format!(
            "Too many redirects while loading World4You page {path}"
        )))
    }

    async fn post_form(&self, path: &str, body: String) -> crate::Result<()> {
        let url = format!("{}{}", self.endpoint, path);
        let session_id = self.ensure_session().await?;
        let (status, text, headers) = self
            .client
            .post(url)
            .set_header("Content-Type", "application/x-www-form-urlencoded")
            .with_header("X-Requested-With", "XMLHttpRequest")
            .with_header("Cookie", format!("W4YSESSID={session_id}"))
            .with_raw_body(body)
            .send_raw_with_status()
            .await?;

        if let Some(refreshed) = extract_session_cookie(&headers) {
            self.store_session(refreshed);
        }

        match status {
            302 | 303 => {
                let redirected_to_login = headers
                    .get("location")
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.contains("/login"))
                    .unwrap_or(false);

                if redirected_to_login {
                    self.clear_session();
                    return Err(Error::Api(format!(
                        "World4You redirected the request to {path} to the login page"
                    )));
                }

                Ok(())
            }
            200 => Err(Error::Api(extract_form_error(&text).unwrap_or_else(|| {
                "World4You rejected the DNS change".to_string()
            }))),
            _ => Err(Error::Api(format!(
                "World4You request to {path} returned HTTP {status}"
            ))),
        }
    }

    async fn fetch_packages(&self) -> crate::Result<Vec<Package>> {
        let page = self.get_page("/").await?;
        let marker = "id=\"paketListData\"";
        let marker_pos = page.find(marker).ok_or_else(|| {
            Error::Parse("World4You package overview is missing paketListData".to_string())
        })?;
        let data_start = page[marker_pos..]
            .find('>')
            .map(|offset| marker_pos + offset + 1)
            .ok_or_else(|| {
                Error::Parse("World4You package overview is missing paketListData".to_string())
            })?;
        let data_end = page[data_start..]
            .find("</script>")
            .map(|offset| data_start + offset)
            .ok_or_else(|| {
                Error::Parse("World4You package overview is missing paketListData".to_string())
            })?;

        let list: PackageList =
            serde_json::from_str(&page[data_start..data_end]).map_err(|err| {
                Error::Parse(format!("Failed to parse the World4You package list: {err}"))
            })?;

        Ok(list
            .items
            .into_iter()
            .map(|item| Package {
                id: item.id.to_string(),
                fqdn: item.fqdn.trim_end_matches('.').to_ascii_lowercase(),
            })
            .collect())
    }

    async fn resolve_package(&self, name: &str, origin: &str) -> crate::Result<Package> {
        let packages = self.fetch_packages().await?;
        let mut candidate = origin.trim_end_matches('.');

        loop {
            if let Some(package) = packages.iter().find(|package| package.fqdn == candidate) {
                return Ok(package.clone());
            }

            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => break,
            }
        }

        packages
            .into_iter()
            .filter(|package| name == package.fqdn || name.ends_with(&format!(".{}", package.fqdn)))
            .max_by_key(|package| package.fqdn.len())
            .ok_or_else(|| Error::Api(format!("No World4You package found for {name}")))
    }

    async fn fetch_records(&self, package: &Package) -> crate::Result<Vec<RecordEntry>> {
        let page = self.get_page(&format!("/{}/dns", package.id)).await?;
        let marker = "id=\"currentDns\"";
        let marker_pos = page.find(marker).ok_or_else(|| {
            Error::Parse("World4You DNS page is missing the currentDns data".to_string())
        })?;
        let tag_start = page[..marker_pos].rfind('<').ok_or_else(|| {
            Error::Parse("World4You DNS page is missing the currentDns data".to_string())
        })?;
        let tag_end = page[marker_pos..]
            .find('>')
            .map(|offset| marker_pos + offset)
            .ok_or_else(|| {
                Error::Parse("World4You DNS page is missing the currentDns data".to_string())
            })?;
        let raw_records =
            attr_value(&page[tag_start..tag_end], "data-records").ok_or_else(|| {
                Error::Parse("World4You DNS page is missing the currentDns data".to_string())
            })?;

        serde_json::from_str(&raw_records).map_err(|err| {
            Error::Parse(format!(
                "Failed to parse the World4You DNS record list: {err}"
            ))
        })
    }

    async fn fetch_form(&self, package: &Package, form_name: &str) -> crate::Result<FormTokens> {
        let page = self.get_page(&format!("/{}/dns", package.id)).await?;
        let form = find_form(&page, form_name).ok_or_else(|| {
            Error::Parse(format!(
                "World4You DNS page is missing the {form_name} form"
            ))
        })?;

        let unique_form_id = input_value(form, &format!("{form_name}[uniqueFormIdDP]"))
            .ok_or_else(|| {
                Error::Parse(format!(
                    "World4You {form_name} form is missing uniqueFormIdDP"
                ))
            })?;
        let token = input_value(form, &format!("{form_name}[_token]"))
            .ok_or_else(|| Error::Parse(format!("World4You {form_name} form is missing _token")))?;

        Ok(FormTokens {
            unique_form_id,
            token,
        })
    }

    async fn add_record(
        &self,
        package: &Package,
        name: &str,
        record: &WireRecord,
    ) -> crate::Result<()> {
        let form = self.fetch_form(package, "AddDnsRecordForm").await?;
        let relative_name = strip_origin_from_name(name, &package.fqdn, Some(""));
        let priority = record
            .priority
            .map(|priority| priority.to_string())
            .unwrap_or_default();

        let body = encode_form(&[
            ("AddDnsRecordForm[name]", relative_name.as_str()),
            ("AddDnsRecordForm[dnsType][type]", record.record_type),
            ("AddDnsRecordForm[dnsType][prio]", priority.as_str()),
            ("AddDnsRecordForm[value]", record.value.as_str()),
            (
                "AddDnsRecordForm[uniqueFormIdDP]",
                form.unique_form_id.as_str(),
            ),
            ("AddDnsRecordForm[_token]", form.token.as_str()),
        ])?;

        self.post_form(&format!("/{}/dns", package.id), body).await
    }

    async fn delete_record(&self, package: &Package, record_id: &str) -> crate::Result<()> {
        let form = self.fetch_form(package, "DeleteDnsRecordForm").await?;

        let body = encode_form(&[
            ("DeleteDnsRecordForm[id]", record_id),
            (
                "DeleteDnsRecordForm[uniqueFormIdDP]",
                form.unique_form_id.as_str(),
            ),
            ("DeleteDnsRecordForm[_token]", form.token.as_str()),
        ])?;

        self.post_form(&format!("/{}/dns/record/delete", package.id), body)
            .await
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name().to_ascii_lowercase();
        let origin = origin.into_name().to_ascii_lowercase();
        let mut desired = build_desired(record_type, records)?;
        let package = self.resolve_package(&name, &origin).await?;
        let existing = self.fetch_records(&package).await?;
        let mut to_delete = Vec::new();

        for entry in matching_entries(existing, &name, record_type) {
            let key = record_key(&parse_record(&entry)?)?;

            if let Some(index) = desired
                .iter()
                .position(|(_, desired_key)| desired_key == &key)
            {
                desired.remove(index);
            } else {
                to_delete.push(entry.id.to_string());
            }
        }

        for record_id in to_delete {
            self.delete_record(&package, &record_id).await?;
        }

        for (record, _) in desired {
            self.add_record(&package, &name, &record).await?;
        }

        Ok(())
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let name = name.into_name().to_ascii_lowercase();
        let origin = origin.into_name().to_ascii_lowercase();
        let desired = build_desired(record_type, records)?;
        let package = self.resolve_package(&name, &origin).await?;
        let existing = self.fetch_records(&package).await?;
        let existing_keys = matching_entries(existing, &name, record_type)
            .into_iter()
            .map(|entry| record_key(&parse_record(&entry)?))
            .collect::<crate::Result<Vec<_>>>()?;

        for (record, key) in desired {
            if !existing_keys.contains(&key) {
                self.add_record(&package, &name, &record).await?;
            }
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
        if records.is_empty() {
            return Ok(());
        }

        let name = name.into_name().to_ascii_lowercase();
        let origin = origin.into_name().to_ascii_lowercase();
        let unwanted = build_desired(record_type, records)?
            .into_iter()
            .map(|(_, key)| key)
            .collect::<Vec<_>>();
        let package = self.resolve_package(&name, &origin).await?;
        let existing = self.fetch_records(&package).await?;

        for entry in matching_entries(existing, &name, record_type) {
            if unwanted.contains(&record_key(&parse_record(&entry)?)?) {
                self.delete_record(&package, &entry.id.to_string()).await?;
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
        let name = name.into_name().to_ascii_lowercase();
        let origin = origin.into_name().to_ascii_lowercase();
        let package = self.resolve_package(&name, &origin).await?;
        let existing = self.fetch_records(&package).await?;

        matching_entries(existing, &name, record_type)
            .into_iter()
            .map(|entry| parse_record(&entry))
            .collect()
    }
}

fn matching_entries(
    entries: Vec<RecordEntry>,
    name: &str,
    record_type: DnsRecordType,
) -> Vec<RecordEntry> {
    entries
        .into_iter()
        .filter(|entry| {
            entry.name.trim_end_matches('.').eq_ignore_ascii_case(name)
                && entry.record_type.eq_ignore_ascii_case(record_type.as_str())
        })
        .collect()
}

fn build_desired(
    record_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<(WireRecord, RecordKey)>> {
    let mut desired: Vec<(WireRecord, RecordKey)> = Vec::with_capacity(records.len());

    for record in records {
        if record.as_type() != record_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                record_type.as_str(),
                record.as_type().as_str()
            )));
        }

        let wire = to_wire(&record)?;
        let key = wire_key(&wire);

        if !desired.iter().any(|(_, existing)| existing == &key) {
            desired.push((wire, key));
        }
    }

    Ok(desired)
}

fn wire_key(record: &WireRecord) -> RecordKey {
    (
        record.record_type.to_string(),
        record.priority,
        record.value.clone(),
    )
}

fn record_key(record: &DnsRecord) -> crate::Result<RecordKey> {
    Ok(wire_key(&to_wire(record)?))
}

fn to_wire(record: &DnsRecord) -> crate::Result<WireRecord> {
    match record {
        DnsRecord::A(address) => Ok(WireRecord {
            record_type: "A",
            priority: None,
            value: address.to_string(),
        }),
        DnsRecord::AAAA(address) => Ok(WireRecord {
            record_type: "AAAA",
            priority: None,
            value: address.to_string(),
        }),
        DnsRecord::CNAME(target) => Ok(WireRecord {
            record_type: "CNAME",
            priority: None,
            value: strip_trailing_dot(target).to_string(),
        }),
        DnsRecord::NS(_) => Err(Error::Unsupported(
            "NS records are not supported by World4You".to_string(),
        )),
        DnsRecord::MX(mx) => Ok(WireRecord {
            record_type: "MX",
            priority: Some(mx.priority),
            value: strip_trailing_dot(&mx.exchange).to_string(),
        }),
        DnsRecord::TXT(text) => Ok(WireRecord {
            record_type: "TXT",
            priority: None,
            value: text.clone(),
        }),
        DnsRecord::SRV(srv) => Ok(WireRecord {
            record_type: "SRV",
            priority: Some(srv.priority),
            value: format!(
                "{} {} {}",
                srv.weight,
                srv.port,
                strip_trailing_dot(&srv.target)
            ),
        }),
        DnsRecord::TLSA(tlsa) => Ok(WireRecord {
            record_type: "TLSA",
            priority: None,
            value: tlsa.to_string(),
        }),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            Ok(WireRecord {
                record_type: "CAA",
                priority: None,
                value: format!("{flags} {tag} {value}"),
            })
        }
    }
}

fn parse_record(entry: &RecordEntry) -> crate::Result<DnsRecord> {
    let value = entry.value.trim();

    match entry.record_type.to_ascii_uppercase().as_str() {
        "A" => value.parse().map(DnsRecord::A).map_err(|err| {
            Error::Parse(format!("Invalid World4You A record value '{value}': {err}"))
        }),
        "AAAA" => value.parse().map(DnsRecord::AAAA).map_err(|err| {
            Error::Parse(format!(
                "Invalid World4You AAAA record value '{value}': {err}"
            ))
        }),
        "CNAME" => Ok(DnsRecord::CNAME(strip_trailing_dot(value).to_string())),
        "NS" => Ok(DnsRecord::NS(strip_trailing_dot(value).to_string())),
        "MX" => {
            let priority = entry.prio.ok_or_else(|| {
                Error::Parse("World4You MX record is missing its priority".to_string())
            })?;
            parse_mx(&format!("{priority} {value}"))
        }
        "TXT" => Ok(DnsRecord::TXT(entry.value.clone())),
        "SRV" => {
            let priority = entry.prio.ok_or_else(|| {
                Error::Parse("World4You SRV record is missing its priority".to_string())
            })?;
            parse_srv(&format!("{priority} {value}"))
        }
        "TLSA" => parse_tlsa(value),
        "CAA" => parse_caa(value),
        other => Err(Error::Unsupported(format!(
            "World4You record type '{other}' is not supported"
        ))),
    }
}

fn parse_caa(value: &str) -> crate::Result<DnsRecord> {
    let (flags, rest) = value
        .split_once(char::is_whitespace)
        .ok_or_else(|| Error::Parse(format!("Invalid World4You CAA record value '{value}'")))?;
    let rest = rest.trim_start();
    let (tag, raw_value) = rest
        .split_once(char::is_whitespace)
        .ok_or_else(|| Error::Parse(format!("Invalid World4You CAA record value '{value}'")))?;
    let flags = flags
        .parse::<u8>()
        .map_err(|err| Error::Parse(format!("Invalid World4You CAA flags '{flags}': {err}")))?;
    let raw_value = raw_value.trim();
    let raw_value = raw_value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(raw_value);

    Ok(DnsRecord::CAA(build_caa(
        flags,
        &tag.to_ascii_lowercase(),
        raw_value,
    )?))
}

fn deserialize_optional_u16<'de, D>(deserializer: D) -> Result<Option<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;

    Ok(match value {
        Some(serde_json::Value::String(value)) => value.trim().parse().ok(),
        Some(serde_json::Value::Number(value)) => {
            value.as_u64().and_then(|value| u16::try_from(value).ok())
        }
        _ => None,
    })
}

fn encode_form(pairs: &[(&str, &str)]) -> crate::Result<String> {
    serde_urlencoded::to_string(pairs)
        .map_err(|err| Error::Serialize(format!("Failed to encode form body: {err}")))
}

fn extract_session_cookie(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let mut session_id = None;

    for header in headers.get_all("set-cookie") {
        let Ok(header) = header.to_str() else {
            continue;
        };

        for part in header.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else {
                continue;
            };

            if name.eq_ignore_ascii_case("W4YSESSID") {
                let value = value.trim();
                let value = value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .unwrap_or(value);
                session_id = Some(value.to_string());
            }
        }
    }

    session_id
}

fn same_origin_url(endpoint: &str, location: &str) -> Option<String> {
    let origin = origin_of(endpoint);

    if location.starts_with("http://") || location.starts_with("https://") {
        if location.starts_with(origin)
            && (location.len() == origin.len() || location[origin.len()..].starts_with('/'))
        {
            return Some(location.to_string());
        }

        return None;
    }

    if location.starts_with('/') {
        return Some(format!("{origin}{location}"));
    }

    None
}

fn origin_of(endpoint: &str) -> &str {
    let scheme_end = match endpoint.find("://") {
        Some(index) => index + 3,
        None => return endpoint,
    };

    match endpoint[scheme_end..].find('/') {
        Some(index) => &endpoint[..scheme_end + index],
        None => endpoint,
    }
}

fn find_form<'a>(page: &'a str, form_name: &str) -> Option<&'a str> {
    let marker = format!("name=\"{form_name}\"");
    let marker_pos = page.find(&marker)?;
    let form_start = page[..marker_pos].rfind("<form")?;
    let form_end = page[marker_pos..].find("</form>")? + marker_pos + "</form>".len();

    page.get(form_start..form_end)
}

fn input_value(html: &str, input_name: &str) -> Option<String> {
    let mut rest = html;

    loop {
        let input_start = rest.find("<input")?;
        rest = &rest[input_start..];
        let input_end = rest.find('>')?;
        let tag = &rest[..=input_end];

        if attr_value(tag, "name").as_deref() == Some(input_name) {
            return Some(attr_value(tag, "value").unwrap_or_default());
        }

        rest = &rest[input_end + 1..];
    }
}

fn attr_value(tag: &str, attr_name: &str) -> Option<String> {
    let bytes = tag.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        while index < bytes.len() && !is_attr_name_byte(bytes[index]) {
            index += 1;
        }

        let name_start = index;
        while index < bytes.len() && is_attr_name_byte(bytes[index]) {
            index += 1;
        }
        let name = &tag[name_start..index];

        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }

        if index < bytes.len() && bytes[index] == b'=' {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }

            let value = if index < bytes.len() && (bytes[index] == b'"' || bytes[index] == b'\'') {
                let quote = bytes[index];
                index += 1;
                let value_start = index;
                while index < bytes.len() && bytes[index] != quote {
                    index += 1;
                }
                let value = &tag[value_start..index];
                index += 1;
                value
            } else {
                let value_start = index;
                while index < bytes.len()
                    && !bytes[index].is_ascii_whitespace()
                    && bytes[index] != b'>'
                {
                    index += 1;
                }
                &tag[value_start..index]
            };

            if name.eq_ignore_ascii_case(attr_name) {
                return Some(unescape_html(value));
            }
        } else if name.eq_ignore_ascii_case(attr_name) {
            return Some(String::new());
        }
    }

    None
}

fn is_attr_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'[' | b']' | b'.')
}

fn unescape_html(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(offset) = rest.find('&') {
        output.push_str(&rest[..offset]);
        let entity = &rest[offset..];

        if let Some((decoded, length)) = decode_html_entity(entity) {
            output.push(decoded);
            rest = &entity[length..];
        } else {
            output.push('&');
            rest = &entity[1..];
        }
    }

    output.push_str(rest);
    output
}

fn decode_html_entity(input: &str) -> Option<(char, usize)> {
    let end = input[1..].find(';')? + 1;
    let name = &input[1..end];
    let decoded = match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => ' ',
        _ => {
            let code =
                if let Some(hex) = name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
                    u32::from_str_radix(hex, 16).ok()?
                } else {
                    name.strip_prefix('#')?.parse::<u32>().ok()?
                };
            char::from_u32(code)?
        }
    };

    Some((decoded, end + 1))
}

fn extract_form_error(page: &str) -> Option<String> {
    let marker = "class=\"form-error-message\"";
    let marker_pos = page.find(marker)?;
    let text_start = page[marker_pos..].find('>')? + marker_pos + 1;
    let text_end = page[text_start..].find("</div>")? + text_start;
    let message = unescape_html(&strip_tags(&page[text_start..text_end]));
    let message = message.trim();

    if message.is_empty() {
        None
    } else {
        Some(message.to_string())
    }
}

fn strip_tags(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut in_tag = false;

    for character in input.chars() {
        match character {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => output.push(character),
            _ => {}
        }
    }

    output.split_whitespace().collect::<Vec<_>>().join(" ")
}
