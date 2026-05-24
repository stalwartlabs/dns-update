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
    DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord,
    http::{HttpClient, HttpClientBuilder},
};
use serde::Deserialize;
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.dreamhost.com";

#[derive(Clone)]
pub struct DreamhostProvider {
    client: HttpClient,
    endpoint: String,
    api_key: String,
}

#[derive(Deserialize, Debug)]
struct ApiResponse {
    result: String,
    #[serde(default)]
    data: serde_json::Value,
}

#[derive(Deserialize, Debug)]
struct ListResponse {
    result: String,
    #[serde(default)]
    data: Vec<DreamhostRecord>,
}

#[derive(Deserialize, Debug, Clone)]
struct DreamhostRecord {
    record: String,
    #[serde(rename = "type")]
    rr_type: String,
    value: String,
    #[serde(default)]
    editable: String,
}

impl DreamhostProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default().with_timeout(timeout).build();
        Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            api_key: api_key.as_ref().to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    fn build_query(&self, params: &[(&str, &str)]) -> String {
        let mut all: Vec<(&str, &str)> = Vec::with_capacity(params.len() + 2);
        all.push(("key", self.api_key.as_str()));
        all.push(("format", "json"));
        all.extend_from_slice(params);
        serde_urlencoded::to_string(all).unwrap_or_default()
    }

    async fn add_record(&self, name: &str, rr_type: &str, value: &str) -> crate::Result<()> {
        let qs = self.build_query(&[
            ("cmd", "dns-add_record"),
            ("record", name),
            ("type", rr_type),
            ("value", value),
            ("comment", "Managed By dns-update"),
        ]);
        let body = self
            .client
            .get(format!("{}/?{qs}", self.endpoint))
            .send_raw()
            .await?;
        let parsed: ApiResponse = serde_json::from_str(&body).map_err(|err| {
            Error::Serialize(format!("Failed to parse Dreamhost response: {err}"))
        })?;
        if parsed.result == "success" || data_is(&parsed.data, "record_already_exists_remove_first")
        {
            Ok(())
        } else {
            Err(Error::Api(format!(
                "Dreamhost add record failed: {}",
                parsed.data
            )))
        }
    }

    async fn remove_record(&self, name: &str, rr_type: &str, value: &str) -> crate::Result<()> {
        let qs = self.build_query(&[
            ("cmd", "dns-remove_record"),
            ("record", name),
            ("type", rr_type),
            ("value", value),
        ]);
        let body = self
            .client
            .get(format!("{}/?{qs}", self.endpoint))
            .send_raw()
            .await?;
        let parsed: ApiResponse = serde_json::from_str(&body).map_err(|err| {
            Error::Serialize(format!("Failed to parse Dreamhost response: {err}"))
        })?;
        if parsed.result == "success" || data_is(&parsed.data, "no_record") {
            Ok(())
        } else {
            Err(Error::Api(format!(
                "Dreamhost remove record failed: {}",
                parsed.data
            )))
        }
    }

    async fn list_all(&self) -> crate::Result<Vec<DreamhostRecord>> {
        let qs = self.build_query(&[("cmd", "dns-list_records")]);
        let body = self
            .client
            .get(format!("{}/?{qs}", self.endpoint))
            .send_raw()
            .await?;
        let parsed: ListResponse = serde_json::from_str(&body).map_err(|err| {
            Error::Serialize(format!("Failed to parse Dreamhost list response: {err}"))
        })?;
        if parsed.result != "success" {
            return Err(Error::Api("Dreamhost list records failed".to_string()));
        }
        Ok(parsed.data)
    }

    async fn list_filtered(
        &self,
        name: &str,
        rr_type: &str,
    ) -> crate::Result<Vec<DreamhostRecord>> {
        let all = self.list_all().await?;
        Ok(all
            .into_iter()
            .filter(|r| r.record == name && r.rr_type == rr_type && r.editable != "0")
            .collect())
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _ttl: u32,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        ensure_supported_type(record_type)?;
        let desired = build_values(record_type, records)?;
        let fqdn = name.into_name().to_string();
        let rr_type = record_type.as_str();
        let existing = self.list_filtered(&fqdn, rr_type).await?;

        let mut existing_pool: Vec<DreamhostRecord> = existing;
        let mut to_add: Vec<String> = Vec::new();

        for value in desired {
            if let Some(idx) = existing_pool.iter().position(|r| r.value == value) {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(value);
            }
        }

        for entry in existing_pool {
            self.remove_record(&fqdn, rr_type, &entry.value).await?;
        }
        for value in to_add {
            self.add_record(&fqdn, rr_type, &value).await?;
        }
        Ok(())
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _ttl: u32,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        ensure_supported_type(record_type)?;
        let desired = build_values(record_type, records)?;
        let fqdn = name.into_name().to_string();
        let rr_type = record_type.as_str();
        let existing = self.list_filtered(&fqdn, rr_type).await?;

        for value in desired {
            if existing.iter().any(|r| r.value == value) {
                continue;
            }
            self.add_record(&fqdn, rr_type, &value).await?;
        }
        Ok(())
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        ensure_supported_type(record_type)?;
        let to_remove = build_values(record_type, records)?;
        let fqdn = name.into_name().to_string();
        let rr_type = record_type.as_str();
        let existing = self.list_filtered(&fqdn, rr_type).await?;

        for value in to_remove {
            if existing.iter().any(|r| r.value == value) {
                self.remove_record(&fqdn, rr_type, &value).await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        ensure_supported_type(record_type)?;
        let fqdn = name.into_name().to_string();
        let rr_type = record_type.as_str();
        let listed = self.list_filtered(&fqdn, rr_type).await?;
        listed
            .into_iter()
            .map(|r| parse_value(record_type, &r.value))
            .collect()
    }
}

fn ensure_supported_type(record_type: DnsRecordType) -> crate::Result<()> {
    match record_type {
        DnsRecordType::TLSA => Err(Error::Api(
            "TLSA records are not supported by Dreamhost".to_string(),
        )),
        DnsRecordType::CAA => Err(Error::Api(
            "CAA records are not supported by Dreamhost".to_string(),
        )),
        _ => Ok(()),
    }
}

fn build_values(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<String>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(render_value(&record)?);
    }
    Ok(out)
}

fn render_value(record: &DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content.clone(),
        DnsRecord::NS(content) => content.clone(),
        DnsRecord::TXT(content) => content.clone(),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, mx.exchange),
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority, srv.weight, srv.port, srv.target
        ),
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Dreamhost".to_string(),
            ));
        }
        DnsRecord::CAA(_) => {
            return Err(Error::Api(
                "CAA records are not supported by Dreamhost".to_string(),
            ));
        }
    })
}

fn parse_value(record_type: DnsRecordType, value: &str) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => value
            .parse()
            .map(DnsRecord::A)
            .map_err(|err| Error::Parse(format!("invalid Dreamhost A value {value}: {err}"))),
        DnsRecordType::AAAA => value
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|err| Error::Parse(format!("invalid Dreamhost AAAA value {value}: {err}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(value.to_string())),
        DnsRecordType::NS => Ok(DnsRecord::NS(value.to_string())),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(value.to_string())),
        DnsRecordType::MX => {
            let (priority_str, exchange) = value
                .split_once(' ')
                .ok_or_else(|| Error::Parse(format!("invalid Dreamhost MX value: {value}")))?;
            let priority = priority_str
                .parse::<u16>()
                .map_err(|err| Error::Parse(format!("invalid MX priority: {err}")))?;
            Ok(DnsRecord::MX(MXRecord {
                priority,
                exchange: exchange.to_string(),
            }))
        }
        DnsRecordType::SRV => {
            let parts: Vec<&str> = value.split_whitespace().collect();
            if parts.len() != 4 {
                return Err(Error::Parse(format!(
                    "invalid Dreamhost SRV value: {value}"
                )));
            }
            let priority = parts[0]
                .parse::<u16>()
                .map_err(|err| Error::Parse(format!("invalid SRV priority: {err}")))?;
            let weight = parts[1]
                .parse::<u16>()
                .map_err(|err| Error::Parse(format!("invalid SRV weight: {err}")))?;
            let port = parts[2]
                .parse::<u16>()
                .map_err(|err| Error::Parse(format!("invalid SRV port: {err}")))?;
            Ok(DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target: parts[3].to_string(),
            }))
        }
        DnsRecordType::TLSA | DnsRecordType::CAA => Err(Error::Api(format!(
            "{} records are not supported by Dreamhost",
            record_type.as_str()
        ))),
    }
}

fn data_is(data: &serde_json::Value, expected: &str) -> bool {
    data.as_str().map(|s| s == expected).unwrap_or(false)
}
