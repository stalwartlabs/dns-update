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
};
use serde::Serialize;
use std::time::Duration;

#[derive(Clone)]
pub struct PebbleProvider {
    client: HttpClient,
    base_url: String,
}

#[derive(Serialize)]
struct HostOnly {
    host: String,
}

#[derive(Serialize)]
struct AddA {
    host: String,
    addresses: Vec<String>,
}

#[derive(Serialize)]
struct SetTxt {
    host: String,
    value: String,
}

#[derive(Serialize)]
struct SetCname {
    host: String,
    target: String,
}

#[derive(Serialize)]
struct AddCaa {
    host: String,
    policies: Vec<CaaPolicy>,
}

#[derive(Serialize)]
struct CaaPolicy {
    tag: String,
    value: String,
}

impl PebbleProvider {
    pub(crate) fn new(base_url: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let base_url = base_url.as_ref().trim_end_matches('/').to_string();
        let client = HttpClientBuilder::default().with_timeout(timeout).build();
        Self { client, base_url }
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _ttl: u32,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        let host = name.into_fqdn().into_owned();
        self.clear_record(&host, record_type).await?;
        if records.is_empty() {
            return Ok(());
        }
        match record_type {
            DnsRecordType::A | DnsRecordType::AAAA => {
                let addresses = records
                    .iter()
                    .map(|r| match r {
                        DnsRecord::A(addr) => addr.to_string(),
                        DnsRecord::AAAA(addr) => addr.to_string(),
                        _ => unreachable!(),
                    })
                    .collect();
                self.add_addresses(&host, record_type, addresses).await
            }
            DnsRecordType::CAA => {
                let policies = records
                    .iter()
                    .map(|r| match r {
                        DnsRecord::CAA(caa) => {
                            let (_, tag, value) = caa.clone().decompose();
                            CaaPolicy { tag, value }
                        }
                        _ => unreachable!(),
                    })
                    .collect();
                self.client
                    .post(format!("{}/add-caa", self.base_url))
                    .with_body(AddCaa { host, policies })?
                    .send_raw()
                    .await
                    .map(|_| ())
            }
            DnsRecordType::TXT | DnsRecordType::CNAME => {
                if records.len() > 1 {
                    return Err(Error::Api(format!(
                        "Pebble only supports a single {record_type} record per owner"
                    )));
                }
                self.set_singular(&host, records.into_iter().next().unwrap())
                    .await
            }
            other => Err(Error::Api(format!(
                "{other} records are not supported by Pebble"
            ))),
        }
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _ttl: u32,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let host = name.into_fqdn().into_owned();
        match record_type {
            DnsRecordType::A | DnsRecordType::AAAA => {
                let addresses = records
                    .into_iter()
                    .map(|r| match r {
                        DnsRecord::A(addr) => addr.to_string(),
                        DnsRecord::AAAA(addr) => addr.to_string(),
                        _ => unreachable!(),
                    })
                    .collect();
                self.add_addresses(&host, record_type, addresses).await
            }
            DnsRecordType::CAA => {
                let policies = records
                    .into_iter()
                    .map(|r| match r {
                        DnsRecord::CAA(caa) => {
                            let (_, tag, value) = caa.decompose();
                            CaaPolicy { tag, value }
                        }
                        _ => unreachable!(),
                    })
                    .collect();
                self.client
                    .post(format!("{}/add-caa", self.base_url))
                    .with_body(AddCaa { host, policies })?
                    .send_raw()
                    .await
                    .map(|_| ())
            }
            DnsRecordType::TXT | DnsRecordType::CNAME => {
                if records.len() > 1 {
                    return Err(Error::Api(format!(
                        "Pebble only supports a single {record_type} record per owner"
                    )));
                }
                self.set_singular(&host, records.into_iter().next().unwrap())
                    .await
            }
            other => Err(Error::Api(format!(
                "{other} records are not supported by Pebble"
            ))),
        }
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let host = name.into_fqdn().into_owned();
        self.clear_record(&host, record_type).await
    }

    pub(crate) async fn list_rrset(
        &self,
        _name: impl IntoFqdn<'_>,
        _record_type: DnsRecordType,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        Err(Error::Api(
            "Pebble does not support listing records".to_string(),
        ))
    }

    async fn add_addresses(
        &self,
        host: &str,
        record_type: DnsRecordType,
        addresses: Vec<String>,
    ) -> crate::Result<()> {
        let endpoint = match record_type {
            DnsRecordType::A => "add-a",
            DnsRecordType::AAAA => "add-aaaa",
            _ => unreachable!(),
        };
        self.client
            .post(format!("{}/{endpoint}", self.base_url))
            .with_body(AddA {
                host: host.to_string(),
                addresses,
            })?
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn set_singular(&self, host: &str, record: DnsRecord) -> crate::Result<()> {
        match record {
            DnsRecord::CNAME(target) => self
                .client
                .post(format!("{}/set-cname", self.base_url))
                .with_body(SetCname {
                    host: host.to_string(),
                    target,
                })?
                .send_raw()
                .await
                .map(|_| ()),
            DnsRecord::TXT(value) => self
                .client
                .post(format!("{}/set-txt", self.base_url))
                .with_body(SetTxt {
                    host: host.to_string(),
                    value,
                })?
                .send_raw()
                .await
                .map(|_| ()),
            other => Err(Error::Api(format!(
                "{} records are not supported by Pebble",
                other.as_type()
            ))),
        }
    }

    async fn clear_record(&self, host: &str, record_type: DnsRecordType) -> crate::Result<()> {
        let endpoint = match record_type {
            DnsRecordType::A => "clear-a",
            DnsRecordType::AAAA => "clear-aaaa",
            DnsRecordType::CNAME => "clear-cname",
            DnsRecordType::TXT => "clear-txt",
            DnsRecordType::CAA => "clear-caa",
            other => {
                return Err(Error::Api(format!(
                    "{other} records are not supported by Pebble"
                )));
            }
        };

        self.client
            .post(format!("{}/{endpoint}", self.base_url))
            .with_body(HostOnly {
                host: host.to_string(),
            })?
            .send_raw()
            .await
            .map(|_| ())
    }
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
