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
    DnsRecord, DnsRecordType, Error, IntoFqdn,
    http::{HttpClient, HttpClientBuilder},
    utils::{build_caa, parse_mx, parse_srv, strip_trailing_dot, txt_chunks_to_text, unquote_txt},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone)]
pub struct EnumProvider {
    client: HttpClient,
    endpoint: String,
    project_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GetZoneByNameRequest<'a> {
    project_id: &'a str,
    name: &'a str,
}

#[derive(Deserialize)]
struct GetZoneByNameResponse {
    zone: Zone,
}

#[derive(Deserialize)]
struct Zone {
    id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordSetKey<'a> {
    project_id: &'a str,
    zone_id: &'a str,
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
}

#[derive(Serialize)]
struct RecordSetRequest<'a> {
    #[serde(flatten)]
    key: RecordSetKey<'a>,
    ttl: u32,
    records: Vec<RecordValue>,
}

#[derive(Serialize)]
struct AddRecordSetValueRequest<'a> {
    #[serde(flatten)]
    key: RecordSetKey<'a>,
    ttl: u32,
    value: RecordValue,
}

#[derive(Serialize)]
struct RemoveRecordSetValueRequest<'a> {
    #[serde(flatten)]
    key: RecordSetKey<'a>,
    content: String,
}

#[derive(Serialize, Deserialize)]
struct RecordValue {
    content: String,
    #[serde(default, skip_serializing)]
    disabled: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetRecordSetResponse {
    record_set: RecordSet,
}

#[derive(Deserialize)]
struct RecordSet {
    #[serde(default)]
    records: Vec<RecordValue>,
}

#[derive(Deserialize)]
struct EmptyResponse {}

const DEFAULT_API_ENDPOINT: &str = "https://api.enum.co/enum.api.v1.DnsService";

impl EnumProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        project_id: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", api_key.as_ref()))
            .with_timeout(timeout)
            .build();

        Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            project_id: project_id.as_ref().to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
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
        let contents = build_contents(record_type, records)?;
        let name = name.into_name().to_ascii_lowercase();
        let zone_id = self.obtain_zone_id(origin).await?;
        let key = || self.record_set_key(&zone_id, &name, record_type);

        if contents.is_empty() {
            return self
                .call::<EmptyResponse>("DeleteRecordSet", key())
                .await
                .map(|_| ())
                .or_else(|err| match err {
                    Error::NotFound => Ok(()),
                    err => Err(err),
                });
        }

        let request = |contents: Vec<String>| RecordSetRequest {
            key: key(),
            ttl,
            records: contents
                .into_iter()
                .map(|content| RecordValue {
                    content,
                    disabled: false,
                })
                .collect(),
        };

        match self
            .call::<EmptyResponse>("UpdateRecordSet", request(contents.clone()))
            .await
        {
            Err(Error::NotFound) => self
                .call::<EmptyResponse>("CreateRecordSet", request(contents))
                .await
                .map(|_| ()),
            result => result.map(|_| ()),
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
        let contents = build_contents(record_type, records)?;
        if contents.is_empty() {
            return Ok(());
        }

        let name = name.into_name().to_ascii_lowercase();
        let zone_id = self.obtain_zone_id(origin).await?;

        for content in contents {
            self.call::<EmptyResponse>(
                "AddRecordSetValue",
                AddRecordSetValueRequest {
                    key: self.record_set_key(&zone_id, &name, record_type),
                    ttl,
                    value: RecordValue {
                        content,
                        disabled: false,
                    },
                },
            )
            .await?;
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
        let contents = build_contents(record_type, records)?;
        if contents.is_empty() {
            return Ok(());
        }

        let name = name.into_name().to_ascii_lowercase();
        let zone_id = self.obtain_zone_id(origin).await?;

        for content in contents {
            self.call::<EmptyResponse>(
                "RemoveRecordSetValue",
                RemoveRecordSetValueRequest {
                    key: self.record_set_key(&zone_id, &name, record_type),
                    content,
                },
            )
            .await?;
        }

        Ok(())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        reject_unsupported(record_type)?;

        let name = name.into_name().to_ascii_lowercase();
        let zone_id = self.obtain_zone_id(origin).await?;

        let response = match self
            .call::<GetRecordSetResponse>(
                "GetRecordSet",
                self.record_set_key(&zone_id, &name, record_type),
            )
            .await
        {
            Ok(response) => response,
            Err(Error::NotFound) => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };

        response
            .record_set
            .records
            .into_iter()
            .filter(|record| !record.disabled)
            .map(|record| parse_record(record_type, &record.content))
            .collect()
    }

    async fn obtain_zone_id(&self, origin: impl IntoFqdn<'_>) -> crate::Result<String> {
        let origin = origin.into_name().to_ascii_lowercase();
        let mut candidate: &str = &origin;
        loop {
            match self
                .call::<GetZoneByNameResponse>(
                    "GetZoneByName",
                    GetZoneByNameRequest {
                        project_id: &self.project_id,
                        name: candidate,
                    },
                )
                .await
            {
                Ok(response) => return Ok(response.zone.id),
                Err(Error::NotFound) => {}
                Err(err) => return Err(err),
            }
            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => return Err(Error::Api(format!("No enum zone found for {origin}"))),
            }
        }
    }

    fn record_set_key<'a>(
        &'a self,
        zone_id: &'a str,
        name: &'a str,
        record_type: DnsRecordType,
    ) -> RecordSetKey<'a> {
        RecordSetKey {
            project_id: &self.project_id,
            zone_id,
            name,
            record_type: record_type.as_str(),
        }
    }

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        body: impl Serialize,
    ) -> crate::Result<T> {
        self.client
            .post(format!("{}/{method}", self.endpoint))
            .with_body(body)?
            .send_with_retry::<T>(3)
            .await
    }
}

fn reject_unsupported(record_type: DnsRecordType) -> crate::Result<()> {
    if record_type == DnsRecordType::TLSA {
        return Err(Error::Unsupported(
            "TLSA records are not supported by enum".to_string(),
        ));
    }
    Ok(())
}

fn build_contents(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<String>> {
    reject_unsupported(expected_type)?;

    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        out.push(record_content(record));
    }
    Ok(out)
}

fn record_content(record: DnsRecord) -> String {
    match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(target) => target.into_fqdn().into_owned(),
        DnsRecord::NS(target) => target.into_fqdn().into_owned(),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, mx.exchange.into_fqdn()),
        DnsRecord::TXT(text) => {
            let mut content = String::with_capacity(text.len() + 2);
            txt_chunks_to_text(&mut content, &text, " ");
            content
        }
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            srv.target.into_fqdn()
        ),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    }
}

fn parse_record(record_type: DnsRecordType, content: &str) -> crate::Result<DnsRecord> {
    match record_type {
        DnsRecordType::A => content
            .parse()
            .map(DnsRecord::A)
            .map_err(|e| Error::Parse(format!("invalid A record: {e}"))),
        DnsRecordType::AAAA => content
            .parse()
            .map(DnsRecord::AAAA)
            .map_err(|e| Error::Parse(format!("invalid AAAA record: {e}"))),
        DnsRecordType::CNAME => Ok(DnsRecord::CNAME(strip_trailing_dot(content).to_string())),
        DnsRecordType::NS => Ok(DnsRecord::NS(strip_trailing_dot(content).to_string())),
        DnsRecordType::MX => parse_mx(content),
        DnsRecordType::TXT => Ok(DnsRecord::TXT(unquote_txt(content))),
        DnsRecordType::SRV => parse_srv(content),
        DnsRecordType::CAA => parse_caa(content),
        DnsRecordType::TLSA => Err(Error::Unsupported(
            "TLSA records are not supported by enum".to_string(),
        )),
    }
}

fn parse_caa(content: &str) -> crate::Result<DnsRecord> {
    let mut parts = content.splitn(3, ' ');
    let (Some(flags), Some(tag), Some(value)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(Error::Parse(format!("invalid CAA record: {content}")));
    };
    let flags = flags
        .parse::<u8>()
        .map_err(|e| Error::Parse(format!("invalid CAA flags: {e}")))?;
    build_caa(flags, &tag.to_ascii_lowercase(), &unquote_txt(value)).map(DnsRecord::CAA)
}
