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

use crate::utils::strip_trailing_dot;
use crate::utils::{
    build_caa, decode_hex, tlsa_cert_usage_from_u8, tlsa_matching_from_u8, tlsa_selector_from_u8,
};
use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord, TLSARecord,
    http::{HttpClient, HttpClientBuilder},
};
use encodify::base64::STANDARD as BASE64;
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    borrow::Cow,
    collections::HashMap,
    fmt::{Display, Formatter},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const DEFAULT_API_ENDPOINT: &str = "https://api.zone.eu/v2";
const ZONE_CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct ZoneEuProvider {
    client: HttpClient,
    endpoint: Cow<'static, str>,
    zones: Arc<Mutex<HashMap<String, (String, Instant)>>>,
}

#[derive(Deserialize, Debug)]
pub struct ZoneRecord {
    id: RecordId,
    name: String,
    destination: String,
    #[serde(default, deserialize_with = "number_from_any")]
    priority: Option<u16>,
    #[serde(default, deserialize_with = "number_from_any")]
    weight: Option<u16>,
    #[serde(default, deserialize_with = "number_from_any")]
    port: Option<u16>,
    #[serde(default, deserialize_with = "number_from_any")]
    flag: Option<u8>,
    tag: Option<String>,
    #[serde(default, deserialize_with = "number_from_any")]
    certificate_usage: Option<u8>,
    #[serde(default, deserialize_with = "number_from_any")]
    selector: Option<u8>,
    #[serde(default, deserialize_with = "number_from_any")]
    matching_type: Option<u8>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RecordId {
    Text(String),
    Number(u64),
}

#[derive(Serialize, Debug, Default, PartialEq, Eq)]
pub struct RecordData {
    destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flag: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate_usage: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selector: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matching_type: Option<u8>,
}

#[derive(Serialize, Debug)]
pub struct CreateRecord<'a> {
    name: &'a str,
    #[serde(flatten)]
    data: &'a RecordData,
}

#[derive(Deserialize, Debug)]
pub struct ZoneEuEmptyResponse {}

impl ZoneEuProvider {
    pub(crate) fn new(
        username: impl AsRef<str>,
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let credentials = format!("{}:{}", username.as_ref(), api_key.as_ref());
        let mut authorization = String::from("Basic ");
        BASE64.encode_append(credentials, &mut authorization);
        let client = HttpClientBuilder::default()
            .with_header("Authorization", authorization)
            .with_timeout(timeout)
            .build();
        Self {
            client,
            endpoint: Cow::Borrowed(DEFAULT_API_ENDPOINT),
            zones: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl Into<Cow<'static, str>>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..self
        }
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let zone = self.resolve_zone(&origin).await?;
        let desired = build_record_data(record_type, records)?;
        let existing = self.list_at(&zone, record_type, &name).await?;

        let mut existing_pool: Vec<(RecordId, RecordData)> = existing
            .into_iter()
            .map(|(id, record)| (id, RecordData::from(record)))
            .collect();
        let mut to_add: Vec<RecordData> = Vec::new();

        for data in desired {
            if let Some(idx) = existing_pool
                .iter()
                .position(|(_, existing)| *existing == data)
            {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(data);
            }
        }

        for (id, _) in existing_pool {
            self.delete_record(&zone, record_type, &id).await?;
        }
        for data in to_add {
            self.create_record(&zone, record_type, &name, &data).await?;
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
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let zone = self.resolve_zone(&origin).await?;
        let desired = build_record_data(record_type, records)?;
        let existing: Vec<RecordData> = self
            .list_at(&zone, record_type, &name)
            .await?
            .into_iter()
            .map(|(_, record)| RecordData::from(record))
            .collect();

        for data in desired {
            if existing.contains(&data) {
                continue;
            }
            self.create_record(&zone, record_type, &name, &data).await?;
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
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let zone = self.resolve_zone(&origin).await?;
        let to_remove = build_record_data(record_type, records)?;
        let existing: Vec<(RecordId, RecordData)> = self
            .list_at(&zone, record_type, &name)
            .await?
            .into_iter()
            .map(|(id, record)| (id, RecordData::from(record)))
            .collect();

        for data in to_remove {
            if let Some((id, _)) = existing.iter().find(|(_, existing)| *existing == data) {
                self.delete_record(&zone, record_type, id).await?;
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
        let name = name.into_name().into_owned();
        let origin = origin.into_name().into_owned();
        let zone = self.resolve_zone(&origin).await?;
        let listed = self.list_at(&zone, record_type, &name).await?;
        Ok(listed.into_iter().map(|(_, record)| record).collect())
    }

    async fn list_at(
        &self,
        zone: &str,
        record_type: DnsRecordType,
        name: &str,
    ) -> crate::Result<Vec<(RecordId, DnsRecord)>> {
        let segment = path_segment(record_type);
        let listed: Vec<ZoneRecord> = self
            .client
            .get(format!("{}/dns/{zone}/{segment}", self.endpoint))
            .send_with_retry(3)
            .await?;

        let mut out: Vec<(RecordId, DnsRecord)> = Vec::new();
        for record in listed {
            if record.name != name {
                continue;
            }
            let parsed = parse_record(record_type, &record)?;
            out.push((record.id, parsed));
        }
        Ok(out)
    }

    async fn create_record(
        &self,
        zone: &str,
        record_type: DnsRecordType,
        name: &str,
        data: &RecordData,
    ) -> crate::Result<()> {
        let segment = path_segment(record_type);
        self.client
            .post(format!("{}/dns/{zone}/{segment}", self.endpoint))
            .with_body(CreateRecord { name, data })?
            .send_with_retry::<Vec<ZoneRecord>>(3)
            .await
            .map(|_| ())
    }

    async fn delete_record(
        &self,
        zone: &str,
        record_type: DnsRecordType,
        id: &RecordId,
    ) -> crate::Result<()> {
        let segment = path_segment(record_type);
        self.client
            .delete(format!("{}/dns/{zone}/{segment}/{id}", self.endpoint))
            .send_with_retry::<ZoneEuEmptyResponse>(3)
            .await
            .map(|_| ())
    }

    async fn resolve_zone(&self, origin: &str) -> crate::Result<String> {
        let origin = strip_trailing_dot(origin);

        if let Ok(guard) = self.zones.lock()
            && let Some((resolved, expiry)) = guard.get(origin)
            && Instant::now() < *expiry
        {
            return Ok(resolved.clone());
        }

        let resolved = self.discover_zone(origin).await;

        if let Ok(mut guard) = self.zones.lock() {
            guard.insert(
                origin.to_string(),
                (resolved.clone(), Instant::now() + ZONE_CACHE_TTL),
            );
        }

        Ok(resolved)
    }

    async fn discover_zone(&self, origin: &str) -> String {
        let mut candidate = origin;
        loop {
            let zone_url = format!("{}/dns/{candidate}", self.endpoint);

            if self
                .client
                .get(zone_url)
                .send_with_retry::<Vec<ZoneEuEmptyResponse>>(3)
                .await
                .is_ok()
            {
                return candidate.to_string();
            }

            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => return origin.to_string(),
            }
        }
    }
}

fn number_from_any<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + std::str::FromStr,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumberOrText<T> {
        Number(T),
        Text(String),
    }

    Ok(
        match Option::<NumberOrText<T>>::deserialize(deserializer)? {
            Some(NumberOrText::Number(value)) => Some(value),
            Some(NumberOrText::Text(value)) => value.parse().ok(),
            None => None,
        },
    )
}

fn path_segment(record_type: DnsRecordType) -> &'static str {
    match record_type {
        DnsRecordType::A => "a",
        DnsRecordType::AAAA => "aaaa",
        DnsRecordType::CNAME => "cname",
        DnsRecordType::NS => "ns",
        DnsRecordType::MX => "mx",
        DnsRecordType::TXT => "txt",
        DnsRecordType::SRV => "srv",
        DnsRecordType::TLSA => "tlsa",
        DnsRecordType::CAA => "caa",
    }
}

fn build_record_data(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<RecordData>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(RecordData::from(record));
    }
    Ok(out)
}

fn parse_record(record_type: DnsRecordType, record: &ZoneRecord) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => {
            record.destination.parse().map(DnsRecord::A).map_err(|err| {
                Error::Parse(format!("A record value {}: {err}", record.destination))
            })
        }
        DnsRecordType::AAAA => record
            .destination
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|err| {
                Error::Parse(format!("AAAA record value {}: {err}", record.destination))
            }),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(record.destination.clone())),
        DnsRecordType::NS => Ok(DnsRecord::NS(record.destination.clone())),
        DnsRecordType::MX => Ok(DnsRecord::MX(MXRecord {
            exchange: record.destination.clone(),
            priority: record.priority.unwrap_or_default(),
        })),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(record.destination.clone())),
        DnsRecordType::SRV => Ok(DnsRecord::SRV(SRVRecord {
            target: record.destination.clone(),
            priority: record.priority.unwrap_or_default(),
            weight: record.weight.unwrap_or_default(),
            port: record.port.unwrap_or_default(),
        })),
        DnsRecordType::TLSA => Ok(DnsRecord::TLSA(TLSARecord {
            cert_usage: tlsa_cert_usage_from_u8(record.certificate_usage.unwrap_or_default())?,
            selector: tlsa_selector_from_u8(record.selector.unwrap_or_default())?,
            matching: tlsa_matching_from_u8(record.matching_type.unwrap_or_default())?,
            cert_data: decode_hex(&record.destination)?,
        })),
        DnsRecordType::CAA => build_caa(
            record.flag.unwrap_or_default(),
            record.tag.as_deref().unwrap_or_default(),
            &record.destination,
        )
        .map(DnsRecord::CAA),
    }
}

impl Display for RecordId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordId::Text(id) => f.write_str(id),
            RecordId::Number(id) => write!(f, "{id}"),
        }
    }
}

impl From<DnsRecord> for RecordData {
    fn from(record: DnsRecord) -> Self {
        match record {
            DnsRecord::A(content) => RecordData {
                destination: content.to_string(),
                ..Default::default()
            },
            DnsRecord::AAAA(content) => RecordData {
                destination: content.to_string(),
                ..Default::default()
            },
            DnsRecord::CNAME(content) => RecordData {
                destination: strip_trailing_dot(&content).to_string(),
                ..Default::default()
            },
            DnsRecord::NS(content) => RecordData {
                destination: strip_trailing_dot(&content).to_string(),
                ..Default::default()
            },
            DnsRecord::MX(mx) => RecordData {
                destination: strip_trailing_dot(&mx.exchange).to_string(),
                priority: Some(mx.priority),
                ..Default::default()
            },
            DnsRecord::TXT(content) => RecordData {
                destination: content,
                ..Default::default()
            },
            DnsRecord::SRV(srv) => RecordData {
                destination: strip_trailing_dot(&srv.target).to_string(),
                priority: Some(srv.priority),
                weight: Some(srv.weight),
                port: Some(srv.port),
                ..Default::default()
            },
            DnsRecord::TLSA(tlsa) => RecordData {
                destination: hex::encode(&tlsa.cert_data),
                certificate_usage: Some(u8::from(tlsa.cert_usage)),
                selector: Some(u8::from(tlsa.selector)),
                matching_type: Some(u8::from(tlsa.matching)),
                ..Default::default()
            },
            DnsRecord::CAA(caa) => {
                let (flags, tag, value) = caa.decompose();
                RecordData {
                    destination: value,
                    flag: Some(flags),
                    tag: Some(tag),
                    ..Default::default()
                }
            }
        }
    }
}
