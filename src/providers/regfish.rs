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
    DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord, TLSARecord, TlsaCertUsage,
    TlsaMatching, TlsaSelector,
    http::{HttpClient, HttpClientBuilder, HttpRequest},
    utils::{
        build_caa, decode_hex, strip_trailing_dot, tlsa_cert_usage_from_u8, tlsa_matching_from_u8,
        tlsa_selector_from_u8, unquote_txt,
    },
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, net::AddrParseError, time::Duration};

const DEFAULT_API_ENDPOINT: &str = "https://api.regfish.com";
const RETRIES: u32 = 3;
const APEX: &str = "@";
const MIN_TTL: u32 = 60;
const MAX_TTL: u32 = 86400;
const MAX_MX_PRIORITY: u16 = 10000;
const MAX_TXT_LEN: usize = 4096;
const CAA_CRITICAL: u8 = 0x80;

#[derive(Clone)]
pub struct RegfishProvider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Deserialize)]
struct Envelope<T> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    response: Option<T>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct Record {
    id: u64,
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    #[serde(default)]
    data: String,
    #[serde(default)]
    ttl: Option<u32>,
    #[serde(default)]
    priority: Option<u16>,
    #[serde(default)]
    weight: Option<u16>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    flags: Option<u8>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    usage: Option<u8>,
    #[serde(default)]
    selector: Option<u8>,
    #[serde(default)]
    matching_type: Option<u8>,
}

#[derive(Serialize)]
struct RecordBody<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    name: &'a str,
    data: Cow<'a, str>,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flags: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selector: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matching_type: Option<u8>,
}

struct RecordSet {
    fqdn: String,
    records: Vec<(u64, Option<u32>, Option<DnsRecord>)>,
}

impl RegfishProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        if api_key.is_empty() {
            return Err(Error::Api("Regfish API key must not be empty".to_string()));
        }

        Ok(Self {
            client: HttpClientBuilder::default()
                .with_header("x-api-key", api_key)
                .with_timeout(timeout)
                .build(),
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().trim_end_matches('/').to_string(),
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
        check_record_types(record_type, &records)?;
        let ttl = ttl.clamp(MIN_TTL, MAX_TTL);
        let set = self.record_set(name, record_type, origin).await?;

        let mut missing: Vec<(&DnsRecord, RecordBody<'_>)> = Vec::with_capacity(records.len());
        for record in &records {
            if !missing.iter().any(|(want, _)| *want == record) {
                missing.push((record, RecordBody::new(&set.fqdn, ttl, record)?));
            }
        }

        let mut patch = Vec::new();
        let mut stale = Vec::new();
        for (id, current_ttl, current) in &set.records {
            let found = current
                .as_ref()
                .and_then(|current| missing.iter().position(|(want, _)| *want == current));
            match found {
                Some(idx) => {
                    let (_, body) = missing.swap_remove(idx);
                    if *current_ttl != Some(ttl) {
                        patch.push((*id, body));
                    }
                }
                None => stale.push(*id),
            }
        }

        let mut stale = stale.into_iter();
        let mut create = Vec::new();
        for (_, body) in missing {
            match stale.next() {
                Some(id) => patch.push((id, body)),
                None => create.push(body),
            }
        }

        for (id, body) in patch {
            self.update_record(id, body).await?;
        }
        for body in create {
            self.create_record(body).await?;
        }
        for id in stale {
            self.delete_record(id).await?;
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
        let ttl = ttl.clamp(MIN_TTL, MAX_TTL);
        let set = self.record_set(name, record_type, origin).await?;

        let mut known = set
            .records
            .iter()
            .filter_map(|(_, _, current)| current.as_ref())
            .collect::<Vec<_>>();
        let mut create = Vec::with_capacity(records.len());
        for record in &records {
            if !known.contains(&record) {
                create.push(RecordBody::new(&set.fqdn, ttl, record)?);
                known.push(record);
            }
        }

        for body in create {
            self.create_record(body).await?;
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
        let set = self.record_set(name, record_type, origin).await?;

        for (id, _, current) in &set.records {
            if current
                .as_ref()
                .is_some_and(|current| records.contains(current))
            {
                self.delete_record(*id).await?;
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
        let name = name.into_name();
        let origin = origin.into_name();
        self.list_records(&origin)
            .await?
            .iter()
            .filter(|record| record.is(&name, record_type, &origin))
            .map(|record| record.decode(record_type))
            .collect()
    }

    async fn record_set(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<RecordSet> {
        if record_type == DnsRecordType::NS {
            return Err(Error::Unsupported(
                "NS records are not supported by Regfish".to_string(),
            ));
        }
        let name = name.into_name();
        let origin = origin.into_name();
        let records = self
            .list_records(&origin)
            .await?
            .iter()
            .filter(|record| record.is(&name, record_type, &origin))
            .map(|record| (record.id, record.ttl, record.decode(record_type).ok()))
            .collect();
        Ok(RecordSet {
            fqdn: format!("{name}."),
            records,
        })
    }

    async fn list_records(&self, origin: &str) -> crate::Result<Vec<Record>> {
        self.client
            .get(format!("{}/dns/{origin}/rr", self.endpoint))
            .send_with_retry::<Envelope<Vec<Record>>>(RETRIES)
            .await?
            .into_result()
            .map(Option::unwrap_or_default)
    }

    async fn create_record(&self, body: RecordBody<'_>) -> crate::Result<()> {
        self.send_write(
            self.client
                .post(format!("{}/dns/rr", self.endpoint))
                .with_body(body)?,
        )
        .await
    }

    async fn update_record(&self, id: u64, body: RecordBody<'_>) -> crate::Result<()> {
        self.send_write(
            self.client
                .patch(format!("{}/dns/rr/{id}", self.endpoint))
                .with_body(body)?,
        )
        .await
    }

    async fn delete_record(&self, id: u64) -> crate::Result<()> {
        match self
            .send_write(self.client.delete(format!("{}/dns/rr/{id}", self.endpoint)))
            .await
        {
            Err(Error::NotFound) => Ok(()),
            result => result,
        }
    }

    async fn send_write(&self, request: HttpRequest) -> crate::Result<()> {
        request
            .send_with_retry::<Envelope<serde_json::Value>>(RETRIES)
            .await?
            .into_result()
            .map(|_| ())
    }
}

impl<T> Envelope<T> {
    fn into_result(self) -> crate::Result<Option<T>> {
        if self.success {
            return Ok(self.response);
        }
        Err(Error::Api(match (self.message, self.error) {
            (Some(message), Some(error)) if message != error => {
                format!("Regfish API error: {message}: {error}")
            }
            (Some(text), _) | (None, Some(text)) => format!("Regfish API error: {text}"),
            (None, None) => "Regfish API error".to_string(),
        }))
    }
}

impl Record {
    fn is(&self, name: &str, record_type: DnsRecordType, origin: &str) -> bool {
        self.record_type.eq_ignore_ascii_case(record_type.as_str())
            && match strip_trailing_dot(&self.name) {
                "" | APEX => name.eq_ignore_ascii_case(origin),
                listed => listed.eq_ignore_ascii_case(name),
            }
    }

    fn decode(&self, record_type: DnsRecordType) -> crate::Result<DnsRecord> {
        let data = self.data.trim();
        let missing = |field: &str| {
            Error::Parse(format!(
                "Regfish {} record {} is missing {field}",
                record_type.as_str(),
                self.id
            ))
        };
        Ok(match record_type {
            DnsRecordType::A => DnsRecord::A(data.parse().map_err(|e: AddrParseError| {
                Error::Parse(format!("invalid Regfish A value '{data}': {e}"))
            })?),
            DnsRecordType::AAAA => DnsRecord::AAAA(data.parse().map_err(|e: AddrParseError| {
                Error::Parse(format!("invalid Regfish AAAA value '{data}': {e}"))
            })?),
            DnsRecordType::CNAME => DnsRecord::CNAME(strip_trailing_dot(data).to_string()),
            DnsRecordType::NS => DnsRecord::NS(strip_trailing_dot(data).to_string()),
            DnsRecordType::MX => DnsRecord::MX(MXRecord {
                exchange: strip_trailing_dot(data).to_string(),
                priority: self.priority.ok_or_else(|| missing("priority"))?,
            }),
            DnsRecordType::TXT => DnsRecord::TXT(unquote_txt(&self.data)),
            DnsRecordType::SRV => DnsRecord::SRV(SRVRecord {
                target: strip_trailing_dot(data).to_string(),
                priority: self.priority.ok_or_else(|| missing("priority"))?,
                weight: self.weight.ok_or_else(|| missing("weight"))?,
                port: self.port.ok_or_else(|| missing("port"))?,
            }),
            DnsRecordType::TLSA => DnsRecord::TLSA(TLSARecord {
                cert_usage: tlsa_cert_usage_from_u8(self.usage.ok_or_else(|| missing("usage"))?)?,
                selector: tlsa_selector_from_u8(self.selector.ok_or_else(|| missing("selector"))?)?,
                matching: tlsa_matching_from_u8(
                    self.matching_type.ok_or_else(|| missing("matching_type"))?,
                )?,
                cert_data: decode_hex(data)?,
            }),
            DnsRecordType::CAA => {
                let flags = if self.flags.unwrap_or(0) != 0 {
                    CAA_CRITICAL
                } else {
                    0
                };
                let tag = self.tag.as_deref().ok_or_else(|| missing("tag"))?;
                DnsRecord::CAA(build_caa(flags, &tag.to_ascii_lowercase(), data)?)
            }
        })
    }
}

impl<'a> RecordBody<'a> {
    fn new(fqdn: &'a str, ttl: u32, record: &'a DnsRecord) -> crate::Result<Self> {
        let mut body = RecordBody {
            record_type: record.as_type().as_str(),
            name: fqdn,
            data: Cow::Borrowed(""),
            ttl,
            priority: None,
            weight: None,
            port: None,
            flags: None,
            tag: None,
            usage: None,
            selector: None,
            matching_type: None,
        };
        match record {
            DnsRecord::A(addr) => body.data = Cow::Owned(addr.to_string()),
            DnsRecord::AAAA(addr) => body.data = Cow::Owned(addr.to_string()),
            DnsRecord::CNAME(target) => body.data = target.into_fqdn(),
            DnsRecord::NS(_) => {
                return Err(Error::Unsupported(
                    "NS records are not supported by Regfish".to_string(),
                ));
            }
            DnsRecord::MX(mx) => {
                if mx.priority > MAX_MX_PRIORITY {
                    return Err(Error::Unsupported(format!(
                        "Regfish MX priority must be 0 to {MAX_MX_PRIORITY}, got {}",
                        mx.priority
                    )));
                }
                body.data = (&mx.exchange).into_fqdn();
                body.priority = Some(mx.priority);
            }
            DnsRecord::TXT(text) => {
                if text.len() > MAX_TXT_LEN || text.chars().any(char::is_control) {
                    return Err(Error::Unsupported(format!(
                        "Regfish TXT values must be at most {MAX_TXT_LEN} characters without control characters"
                    )));
                }
                body.data = Cow::Borrowed(text);
            }
            DnsRecord::SRV(srv) => {
                body.data = (&srv.target).into_fqdn();
                body.priority = Some(srv.priority);
                body.weight = Some(srv.weight);
                body.port = Some(srv.port);
            }
            DnsRecord::TLSA(tlsa) => {
                if tlsa.cert_usage == TlsaCertUsage::Private
                    || tlsa.selector == TlsaSelector::Private
                    || tlsa.matching == TlsaMatching::Private
                {
                    return Err(Error::Unsupported(
                        "Regfish does not accept private TLSA usage, selector or matching types"
                            .to_string(),
                    ));
                }
                body.data = Cow::Owned(hex::encode(&tlsa.cert_data));
                body.usage = Some(tlsa.cert_usage.into());
                body.selector = Some(tlsa.selector.into());
                body.matching_type = Some(tlsa.matching.into());
            }
            DnsRecord::CAA(caa) => {
                let (flags, tag, value) = caa.clone().decompose();
                body.data = Cow::Owned(value);
                body.flags = Some(u8::from(flags & CAA_CRITICAL != 0));
                body.tag = Some(tag);
            }
        }
        Ok(body)
    }
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> crate::Result<()> {
    match records.iter().find(|r| r.as_type() != expected) {
        Some(r) => Err(Error::Api(format!(
            "RRSet record type mismatch: expected {}, got {}",
            expected.as_str(),
            r.as_type().as_str(),
        ))),
        None => Ok(()),
    }
}
