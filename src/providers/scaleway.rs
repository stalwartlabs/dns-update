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

use crate::{DnsRecord, DnsRecordType, IntoFqdn, http::HttpClientBuilder};
use serde::Serialize;
use std::{borrow::Cow, time::Duration};

const DEFAULT_API_ENDPOINT: &str = "https://api.scaleway.com/domain/v2beta1";

#[derive(Clone)]
pub struct ScalewayProvider {
    client: HttpClientBuilder,
    endpoint: Cow<'static, str>,
}

#[derive(Serialize, Debug)]
struct ZoneRecordsRequest<'a> {
    return_all_records: bool,
    disallow_new_zone_creation: bool,
    changes: Vec<RecordChange<'a>>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
enum RecordChange<'a> {
    Add { records: Vec<RecordEntry<'a>> },
    Set { id_fields: RecordIdentifier<'a>, records: Vec<RecordEntry<'a>> },
    Delete { id_fields: RecordIdentifier<'a> },
}

#[derive(Serialize, Debug)]
struct RecordEntry<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'static str,
    data: String,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
}

#[derive(Serialize, Debug)]
struct RecordIdentifier<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    record_type: &'static str,
}

impl ScalewayProvider {
    pub(crate) fn new(api_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("X-Auth-Token", api_token.as_ref())
            .with_timeout(timeout);
        Self {
            client,
            endpoint: Cow::Borrowed(DEFAULT_API_ENDPOINT),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl Into<Cow<'static, str>>) -> Self {
        Self {
            endpoint: endpoint.into(),
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
        let zone = origin.into_name();
        let fqdn = name.into_name();
        let entry = build_entry(&fqdn, record, ttl)?;
        self.patch_zone(
            &zone,
            ZoneRecordsRequest {
                return_all_records: false,
                disallow_new_zone_creation: true,
                changes: vec![RecordChange::Add {
                    records: vec![entry],
                }],
            },
        )
        .await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let zone = origin.into_name();
        let fqdn = name.into_name();
        let record_type = record.as_type().as_str();
        let entry = build_entry(&fqdn, record, ttl)?;
        self.patch_zone(
            &zone,
            ZoneRecordsRequest {
                return_all_records: false,
                disallow_new_zone_creation: true,
                changes: vec![RecordChange::Set {
                    id_fields: RecordIdentifier {
                        name: &fqdn,
                        record_type,
                    },
                    records: vec![entry],
                }],
            },
        )
        .await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let zone = origin.into_name();
        let fqdn = name.into_name();
        self.patch_zone(
            &zone,
            ZoneRecordsRequest {
                return_all_records: false,
                disallow_new_zone_creation: true,
                changes: vec![RecordChange::Delete {
                    id_fields: RecordIdentifier {
                        name: &fqdn,
                        record_type: record_type.as_str(),
                    },
                }],
            },
        )
        .await
    }

    async fn patch_zone<'a>(
        &self,
        zone: &str,
        body: ZoneRecordsRequest<'a>,
    ) -> crate::Result<()> {
        self.client
            .patch(format!("{}/dns-zones/{}/records", self.endpoint, zone))
            .with_body(body)?
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn build_entry<'a>(
    fqdn: &'a str,
    record: DnsRecord,
    ttl: u32,
) -> crate::Result<RecordEntry<'a>> {
    let record_type = record.as_type().as_str();
    let priority = match &record {
        DnsRecord::MX(mx) => Some(mx.priority),
        DnsRecord::SRV(srv) => Some(srv.priority),
        _ => None,
    };
    let data = match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content,
        DnsRecord::NS(content) => content,
        DnsRecord::MX(mx) => mx.exchange,
        DnsRecord::TXT(content) => format!("\"{}\"", content.replace('"', "\\\"")),
        DnsRecord::SRV(srv) => format!("{} {} {}", srv.weight, srv.port, srv.target),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    };
    Ok(RecordEntry {
        name: fqdn,
        record_type,
        data,
        ttl,
        priority,
    })
}
