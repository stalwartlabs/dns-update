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
    utils::strip_origin_from_name,
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

const DEFAULT_API_ENDPOINT: &str = "https://api.dynu.com/v2";

#[derive(Clone)]
pub struct DynuProvider {
    client: HttpClientBuilder,
    endpoint: Cow<'static, str>,
}

#[derive(Deserialize, Debug)]
struct RootDomain {
    id: i64,
    #[serde(rename = "domainName")]
    domain_name: String,
    #[serde(rename = "statusCode", default)]
    status_code: u16,
}

#[derive(Deserialize, Debug)]
struct RecordsResponse {
    #[serde(rename = "statusCode", default)]
    status_code: u16,
    #[serde(rename = "dnsRecords", default)]
    dns_records: Vec<DynuRecord>,
}

#[derive(Deserialize, Debug)]
struct DynuRecord {
    id: i64,
    #[serde(rename = "recordType", default)]
    record_type: String,
    #[serde(default)]
    hostname: String,
}

#[derive(Serialize, Debug)]
struct CreateRecord<'a> {
    #[serde(rename = "recordType")]
    record_type: &'static str,
    #[serde(rename = "domainName")]
    domain_name: &'a str,
    #[serde(rename = "nodeName")]
    node_name: &'a str,
    #[serde(rename = "hostname")]
    hostname: &'a str,
    state: bool,
    ttl: u32,
    #[serde(flatten)]
    payload: CreatePayload,
}

#[derive(Serialize, Debug)]
#[serde(untagged)]
enum CreatePayload {
    Txt {
        #[serde(rename = "textData")]
        text_data: String,
    },
    A {
        #[serde(rename = "ipv4Address")]
        ipv4_address: Ipv4Addr,
    },
    Aaaa {
        #[serde(rename = "ipv6Address")]
        ipv6_address: Ipv6Addr,
    },
    Cname {
        host: String,
    },
    Ns {
        host: String,
    },
    Mx {
        host: String,
        priority: u16,
    },
    Srv {
        host: String,
        priority: u16,
        weight: u16,
        port: u16,
    },
}

impl DynuProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        if api_key.is_empty() {
            return Err(Error::Api("Dynu API key is empty".to_string()));
        }
        let client = HttpClientBuilder::default()
            .with_header("Api-Key", api_key)
            .with_header("Accept", "application/json")
            .with_timeout(timeout);
        Ok(Self {
            client,
            endpoint: Cow::Borrowed(DEFAULT_API_ENDPOINT),
        })
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
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let (record_type, payload) = record_type_and_payload(record)?;
        let hostname = name.into_name().into_owned();
        let root = self.get_root_domain(&hostname).await?;
        let node = strip_origin_from_name(&hostname, &root.domain_name, Some(""));

        let body = CreateRecord {
            record_type,
            domain_name: &root.domain_name,
            node_name: &node,
            hostname: &hostname,
            state: true,
            ttl,
            payload,
        };

        self.client
            .post(format!("{}/dns/{}/record", self.endpoint, root.id))
            .with_body(body)?
            .send_raw()
            .await
            .map(|_| ())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let hostname = name.into_name().into_owned();
        let record_type = record.as_type();
        let _ = self
            .delete(hostname.as_str(), origin.into_name().into_owned(), record_type)
            .await;
        self.create(hostname, record, ttl, "").await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        _origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let hostname = name.into_name().into_owned();
        let root = self.get_root_domain(&hostname).await?;
        let records = self.get_records(&hostname, record_type.as_str()).await?;
        let target_type = record_type.as_str();
        let mut deleted_any = false;
        for record in records {
            if record.hostname == hostname && record.record_type == target_type {
                self.client
                    .delete(format!(
                        "{}/dns/{}/record/{}",
                        self.endpoint, root.id, record.id
                    ))
                    .send_raw()
                    .await?;
                deleted_any = true;
            }
        }
        if deleted_any {
            Ok(())
        } else {
            Err(Error::Api(format!(
                "Dynu record {hostname} of type {target_type} not found"
            )))
        }
    }

    async fn get_root_domain(&self, hostname: &str) -> crate::Result<RootDomain> {
        let response: RootDomain = self
            .client
            .get(format!("{}/dns/getroot/{}", self.endpoint, hostname))
            .send()
            .await?;
        if response.status_code != 0 && !(200..300).contains(&response.status_code) {
            return Err(Error::Api(format!(
                "Dynu getroot returned status {}",
                response.status_code
            )));
        }
        Ok(response)
    }

    async fn get_records(
        &self,
        hostname: &str,
        record_type: &str,
    ) -> crate::Result<Vec<DynuRecord>> {
        let response: RecordsResponse = self
            .client
            .get(format!(
                "{}/dns/record/{}?recordType={}",
                self.endpoint, hostname, record_type
            ))
            .send()
            .await?;
        if response.status_code != 0 && !(200..300).contains(&response.status_code) {
            return Err(Error::Api(format!(
                "Dynu getrecords returned status {}",
                response.status_code
            )));
        }
        Ok(response.dns_records)
    }
}

fn record_type_and_payload(record: DnsRecord) -> crate::Result<(&'static str, CreatePayload)> {
    match record {
        DnsRecord::TXT(text_data) => Ok(("TXT", CreatePayload::Txt { text_data })),
        DnsRecord::A(ipv4_address) => Ok(("A", CreatePayload::A { ipv4_address })),
        DnsRecord::AAAA(ipv6_address) => Ok(("AAAA", CreatePayload::Aaaa { ipv6_address })),
        DnsRecord::CNAME(host) => Ok(("CNAME", CreatePayload::Cname { host })),
        DnsRecord::NS(host) => Ok(("NS", CreatePayload::Ns { host })),
        DnsRecord::MX(mx) => Ok((
            "MX",
            CreatePayload::Mx {
                host: mx.exchange,
                priority: mx.priority,
            },
        )),
        DnsRecord::SRV(srv) => Ok((
            "SRV",
            CreatePayload::Srv {
                host: srv.target,
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
            },
        )),
        DnsRecord::TLSA(_) => Err(Error::Api(
            "TLSA records are not supported by Dynu".to_string(),
        )),
        DnsRecord::CAA(_) => Err(Error::Api(
            "CAA records are not supported by Dynu".to_string(),
        )),
    }
}
