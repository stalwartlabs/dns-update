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

use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, http::HttpClientBuilder};
use serde::Serialize;
use std::time::Duration;

#[derive(Clone)]
pub struct PebbleProvider {
    client: HttpClientBuilder,
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
        let client = HttpClientBuilder::default().with_timeout(timeout);
        Self { client, base_url }
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        _ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let host = name.into_fqdn().into_owned();
        self.set_record(&host, record).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        _ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let host = name.into_fqdn().into_owned();
        // Clear existing record first, then set the new one
        self.clear_record(&host, record.as_type()).await?;
        self.set_record(&host, record).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        _origin: impl IntoFqdn<'_>,
        record: DnsRecordType,
    ) -> crate::Result<()> {
        let host = name.into_fqdn().into_owned();
        self.clear_record(&host, record).await
    }

    async fn set_record(&self, host: &str, record: DnsRecord) -> crate::Result<()> {
        match record {
            DnsRecord::A(addr) => {
                self.client
                    .post(format!("{}/add-a", self.base_url))
                    .with_body(AddA {
                        host: host.to_string(),
                        addresses: vec![addr.to_string()],
                    })?
                    .send_raw()
                    .await
                    .map(|_| ())
            }
            DnsRecord::AAAA(addr) => {
                self.client
                    .post(format!("{}/add-aaaa", self.base_url))
                    .with_body(AddA {
                        host: host.to_string(),
                        addresses: vec![addr.to_string()],
                    })?
                    .send_raw()
                    .await
                    .map(|_| ())
            }
            DnsRecord::CNAME(target) => {
                self.client
                    .post(format!("{}/set-cname", self.base_url))
                    .with_body(SetCname {
                        host: host.to_string(),
                        target,
                    })?
                    .send_raw()
                    .await
                    .map(|_| ())
            }
            DnsRecord::TXT(value) => {
                self.client
                    .post(format!("{}/set-txt", self.base_url))
                    .with_body(SetTxt {
                        host: host.to_string(),
                        value,
                    })?
                    .send_raw()
                    .await
                    .map(|_| ())
            }
            DnsRecord::CAA(caa) => {
                let (_, tag, value) = caa.decompose();
                self.client
                    .post(format!("{}/add-caa", self.base_url))
                    .with_body(AddCaa {
                        host: host.to_string(),
                        policies: vec![CaaPolicy { tag, value }],
                    })?
                    .send_raw()
                    .await
                    .map(|_| ())
            }
            DnsRecord::NS(_) => Err(Error::Api(
                "NS records are not supported by Pebble".to_string(),
            )),
            DnsRecord::MX(_) => Err(Error::Api(
                "MX records are not supported by Pebble".to_string(),
            )),
            DnsRecord::SRV(_) => Err(Error::Api(
                "SRV records are not supported by Pebble".to_string(),
            )),
            DnsRecord::TLSA(_) => Err(Error::Api(
                "TLSA records are not supported by Pebble".to_string(),
            )),
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
