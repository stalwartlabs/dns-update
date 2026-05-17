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
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone)]
pub struct CpanelProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Deserialize, Debug)]
struct ApiResponse<T> {
    #[serde(default)]
    status: i32,
    #[serde(default)]
    errors: Option<Vec<String>>,
    #[serde(default)]
    messages: Option<Vec<String>>,
    data: Option<T>,
}

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct ZoneRecord {
    #[serde(default, rename = "line_index")]
    line_index: i64,
    #[serde(default, rename = "type")]
    record_class: String,
    #[serde(default, rename = "record_type")]
    record_type: String,
    #[serde(default, rename = "dname_b64")]
    dname_b64: String,
    #[serde(default, rename = "data_b64")]
    data_b64: Vec<String>,
    #[serde(default)]
    ttl: u32,
}

#[derive(Serialize, Debug)]
struct AddRecord<'a> {
    dname: &'a str,
    ttl: u32,
    record_type: &'a str,
    data: Vec<String>,
}

impl CpanelProvider {
    pub(crate) fn new(
        base_url: impl AsRef<str>,
        username: impl AsRef<str>,
        token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let auth = format!("cpanel {}:{}", username.as_ref(), token.as_ref());
        let client = HttpClientBuilder::default()
            .with_header("Authorization", auth)
            .with_timeout(timeout);
        Self {
            client,
            endpoint: base_url.as_ref().trim_end_matches('/').to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().trim_end_matches('/').to_string(),
            ..self
        }
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_fqdn();
        let domain = origin.into_name();
        let zone_info = self.fetch_zone_information(&domain).await?;
        let serial = extract_zone_serial(&zone_info, name.as_ref(), &domain)?;
        let data = encode_record_data(&record)?;
        let record_type = dns_record_type_str(&record);

        let payload = AddRecord {
            dname: name.as_ref(),
            ttl,
            record_type,
            data,
        };
        let payload = serde_json::to_string(&payload)
            .map_err(|err| Error::Serialize(err.to_string()))?;

        let query = serde_urlencoded::to_string([
            ("zone", domain.as_ref()),
            ("serial", serial.to_string().as_str()),
            ("add", payload.as_str()),
        ])
        .map_err(|err| Error::Serialize(err.to_string()))?;

        self.client
            .get(format!(
                "{}/execute/DNS/mass_edit_zone?{}",
                self.endpoint, query
            ))
            .send_with_retry::<ApiResponse<serde_json::Value>>(3)
            .await
            .and_then(|r| r.unwrap_response("add record"))
            .map(|_| ())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_fqdn();
        let domain = origin.into_name();
        let zone_info = self.fetch_zone_information(&domain).await?;
        let serial = extract_zone_serial(&zone_info, name.as_ref(), &domain)?;
        let record_type_str = dns_record_type_str(&record);

        let existing = zone_info
            .iter()
            .find(|r| {
                r.record_class == "record"
                    && r.record_type.eq_ignore_ascii_case(record_type_str)
                    && BASE64
                        .decode(&r.dname_b64)
                        .map(|bytes| {
                            String::from_utf8(bytes)
                                .map(|s| s.trim_end_matches('.').eq_ignore_ascii_case(
                                    name.as_ref().trim_end_matches('.'),
                                ))
                                .unwrap_or(false)
                        })
                        .unwrap_or(false)
            })
            .ok_or(Error::NotFound)?
            .clone();

        let data = encode_record_data(&record)?;
        let edit = serde_json::json!({
            "line_index": existing.line_index,
            "dname": name.as_ref(),
            "ttl": ttl,
            "record_type": record_type_str,
            "data": data,
        });
        let edit_str =
            serde_json::to_string(&edit).map_err(|err| Error::Serialize(err.to_string()))?;

        let query = serde_urlencoded::to_string([
            ("zone", domain.as_ref()),
            ("serial", serial.to_string().as_str()),
            ("edit", edit_str.as_str()),
        ])
        .map_err(|err| Error::Serialize(err.to_string()))?;

        self.client
            .get(format!(
                "{}/execute/DNS/mass_edit_zone?{}",
                self.endpoint, query
            ))
            .send_with_retry::<ApiResponse<serde_json::Value>>(3)
            .await
            .and_then(|r| r.unwrap_response("edit record"))
            .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_fqdn();
        let domain = origin.into_name();
        let zone_info = self.fetch_zone_information(&domain).await?;
        let serial = extract_zone_serial(&zone_info, name.as_ref(), &domain)?;
        let type_str = record_type.as_str();

        let existing = zone_info
            .iter()
            .find(|r| {
                r.record_class == "record"
                    && r.record_type.eq_ignore_ascii_case(type_str)
                    && BASE64
                        .decode(&r.dname_b64)
                        .map(|bytes| {
                            String::from_utf8(bytes)
                                .map(|s| s.trim_end_matches('.').eq_ignore_ascii_case(
                                    name.as_ref().trim_end_matches('.'),
                                ))
                                .unwrap_or(false)
                        })
                        .unwrap_or(false)
            })
            .ok_or(Error::NotFound)?;

        let query = serde_urlencoded::to_string([
            ("zone", domain.as_ref()),
            ("serial", serial.to_string().as_str()),
            ("remove", existing.line_index.to_string().as_str()),
        ])
        .map_err(|err| Error::Serialize(err.to_string()))?;

        self.client
            .get(format!(
                "{}/execute/DNS/mass_edit_zone?{}",
                self.endpoint, query
            ))
            .send_with_retry::<ApiResponse<serde_json::Value>>(3)
            .await
            .and_then(|r| r.unwrap_response("remove record"))
            .map(|_| ())
    }

    async fn fetch_zone_information(&self, domain: &str) -> crate::Result<Vec<ZoneRecord>> {
        let query = serde_urlencoded::to_string([("zone", domain)])
            .map_err(|err| Error::Serialize(err.to_string()))?;
        self.client
            .get(format!(
                "{}/execute/DNS/parse_zone?{}",
                self.endpoint, query
            ))
            .send_with_retry::<ApiResponse<Vec<ZoneRecord>>>(3)
            .await
            .and_then(|r| r.unwrap_response("parse zone"))
    }
}

impl<T> ApiResponse<T> {
    fn unwrap_response(self, action: &str) -> crate::Result<T> {
        if self.status == 0 {
            let errs = self.errors.unwrap_or_default().join(", ");
            let msgs = self.messages.unwrap_or_default().join(", ");
            return Err(Error::Api(format!(
                "cPanel failed to {action}: {errs} {msgs}"
            )));
        }
        self.data
            .ok_or_else(|| Error::Api(format!("cPanel missing data for {action}")))
    }
}

fn dns_record_type_str(record: &DnsRecord) -> &'static str {
    match record {
        DnsRecord::A(_) => "A",
        DnsRecord::AAAA(_) => "AAAA",
        DnsRecord::CNAME(_) => "CNAME",
        DnsRecord::NS(_) => "NS",
        DnsRecord::MX(_) => "MX",
        DnsRecord::TXT(_) => "TXT",
        DnsRecord::SRV(_) => "SRV",
        DnsRecord::TLSA(_) => "TLSA",
        DnsRecord::CAA(_) => "CAA",
    }
}

fn encode_record_data(record: &DnsRecord) -> crate::Result<Vec<String>> {
    Ok(match record {
        DnsRecord::A(addr) => vec![addr.to_string()],
        DnsRecord::AAAA(addr) => vec![addr.to_string()],
        DnsRecord::CNAME(value) => vec![value.clone()],
        DnsRecord::NS(value) => vec![value.clone()],
        DnsRecord::MX(mx) => vec![mx.priority.to_string(), mx.exchange.clone()],
        DnsRecord::TXT(value) => vec![value.clone()],
        DnsRecord::SRV(srv) => vec![
            srv.priority.to_string(),
            srv.weight.to_string(),
            srv.port.to_string(),
            srv.target.clone(),
        ],
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            vec![flags.to_string(), tag, value]
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by cPanel".to_string(),
            ));
        }
    })
}

fn extract_zone_serial(zone: &[ZoneRecord], _name: &str, domain: &str) -> crate::Result<u32> {
    let target = BASE64.encode(domain.trim_end_matches('.').as_bytes());
    let target_with_dot = BASE64.encode(format!("{}.", domain.trim_end_matches('.')).as_bytes());

    for record in zone {
        if record.record_class != "record" || record.record_type != "SOA" {
            continue;
        }
        if record.dname_b64 != target && record.dname_b64 != target_with_dot {
            continue;
        }
        if record.data_b64.len() < 3 {
            continue;
        }
        let decoded = BASE64
            .decode(&record.data_b64[2])
            .map_err(|err| Error::Parse(format!("Failed to decode SOA serial: {err}")))?;
        let serial_str = String::from_utf8(decoded)
            .map_err(|err| Error::Parse(format!("Failed to parse SOA serial: {err}")))?;
        return serial_str
            .trim()
            .parse::<u32>()
            .map_err(|err| Error::Parse(format!("Failed to parse SOA serial value: {err}")));
    }

    Err(Error::Api(format!(
        "cPanel zone serial not found for {domain}"
    )))
}
