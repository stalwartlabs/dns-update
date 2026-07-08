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

use crate::utils::build_caa;
use crate::utils::{
    decode_hex, tlsa_cert_usage_from_u8, tlsa_matching_from_u8, tlsa_selector_from_u8,
};
use crate::{
    DnsRecord, DnsRecordType, Error, IntoFqdn, MXRecord, SRVRecord, TLSARecord,
    http::{HttpClient, HttpClientBuilder},
    utils::strip_origin_from_name,
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

const DEFAULT_API_ENDPOINT: &str = "https://api.dynu.com/v2";
const RETRY_ATTEMPTS: u32 = 3;

#[derive(Clone)]
pub struct DynuProvider {
    client: HttpClient,
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
    dns_records: Vec<ListedRecord>,
}

#[derive(Deserialize, Debug, Clone)]
struct ListedRecord {
    id: i64,
    #[serde(rename = "recordType", default)]
    record_type: String,
    #[serde(default)]
    hostname: String,
    #[serde(rename = "ipv4Address", default)]
    ipv4_address: Option<Ipv4Addr>,
    #[serde(rename = "ipv6Address", default)]
    ipv6_address: Option<Ipv6Addr>,
    #[serde(default)]
    host: Option<String>,
    #[serde(rename = "textData", default)]
    text_data: Option<String>,
    #[serde(default)]
    priority: Option<u16>,
    #[serde(default)]
    weight: Option<u16>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    flag: Option<u8>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(rename = "caaValue", default)]
    caa_value: Option<String>,
    #[serde(rename = "certificateUsage", default)]
    certificate_usage: Option<u8>,
    #[serde(default)]
    selector: Option<u8>,
    #[serde(rename = "matchingType", default)]
    matching_type: Option<u8>,
    #[serde(default)]
    certificate: Option<String>,
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
    payload: Payload,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
enum Payload {
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
    Caa {
        flag: u8,
        tag: String,
        #[serde(rename = "caaValue")]
        caa_value: String,
    },
    Tlsa {
        #[serde(rename = "certificateUsage")]
        certificate_usage: u8,
        selector: u8,
        #[serde(rename = "matchingType")]
        matching_type: u8,
        certificate: String,
    },
}

impl DynuProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        if api_key.is_empty() {
            return Err(Error::Api("Dynu API key is empty".to_string()));
        }
        let client = HttpClientBuilder::default()
            .with_header("API-Key", api_key)
            .with_header("Accept", "application/json")
            .with_timeout(timeout)
            .build();
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

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let _ = origin;
        let hostname = name.into_name().into_owned();
        let desired = build_payloads(record_type, records)?;
        let root = self.get_root_domain(&hostname).await?;
        let node = strip_origin_from_name(&hostname, &root.domain_name, Some(""));
        let existing = self.list_at(root.id, &hostname, record_type).await?;

        let mut existing_pool: Vec<ListedRecord> = existing;
        let mut to_add: Vec<Payload> = Vec::new();

        for payload in desired {
            if let Some(idx) = existing_pool
                .iter()
                .position(|r| matches_payload(r, &payload))
            {
                existing_pool.swap_remove(idx);
            } else {
                to_add.push(payload);
            }
        }

        for entry in existing_pool {
            self.delete_by_id(root.id, entry.id).await?;
        }
        let record_type_str = record_type.as_str();
        for payload in to_add {
            self.post_record(
                root.id,
                record_type_str,
                &root.domain_name,
                &node,
                &hostname,
                ttl,
                payload,
            )
            .await?;
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
        let _ = origin;
        if records.is_empty() {
            return Ok(());
        }
        let hostname = name.into_name().into_owned();
        let desired = build_payloads(record_type, records)?;
        let root = self.get_root_domain(&hostname).await?;
        let node = strip_origin_from_name(&hostname, &root.domain_name, Some(""));
        let existing = self.list_at(root.id, &hostname, record_type).await?;
        let record_type_str = record_type.as_str();

        for payload in desired {
            if existing.iter().any(|r| matches_payload(r, &payload)) {
                continue;
            }
            self.post_record(
                root.id,
                record_type_str,
                &root.domain_name,
                &node,
                &hostname,
                ttl,
                payload,
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
        let _ = origin;
        if records.is_empty() {
            return Ok(());
        }
        let hostname = name.into_name().into_owned();
        let to_remove = build_payloads(record_type, records)?;
        let root = self.get_root_domain(&hostname).await?;
        let existing = self.list_at(root.id, &hostname, record_type).await?;

        for payload in to_remove {
            if let Some(entry) = existing.iter().find(|r| matches_payload(r, &payload)) {
                self.delete_by_id(root.id, entry.id).await?;
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
        let _ = origin;
        let hostname = name.into_name().into_owned();
        let root = self.get_root_domain(&hostname).await?;
        let listed = self.list_at(root.id, &hostname, record_type).await?;
        listed
            .into_iter()
            .map(|r| listed_to_dns_record(r, record_type))
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    async fn post_record(
        &self,
        domain_id: i64,
        record_type: &'static str,
        domain_name: &str,
        node_name: &str,
        hostname: &str,
        ttl: u32,
        payload: Payload,
    ) -> crate::Result<()> {
        let body = CreateRecord {
            record_type,
            domain_name,
            node_name,
            hostname,
            state: true,
            ttl,
            payload,
        };
        self.client
            .post(format!("{}/dns/{}/record", self.endpoint, domain_id))
            .with_body(body)?
            .send_with_retry::<serde_json::Value>(RETRY_ATTEMPTS)
            .await
            .map(|_| ())
    }

    async fn delete_by_id(&self, domain_id: i64, record_id: i64) -> crate::Result<()> {
        self.client
            .delete(format!(
                "{}/dns/{}/record/{}",
                self.endpoint, domain_id, record_id
            ))
            .send_with_retry::<serde_json::Value>(RETRY_ATTEMPTS)
            .await
            .map(|_| ())
    }

    async fn get_root_domain(&self, hostname: &str) -> crate::Result<RootDomain> {
        let response: RootDomain = self
            .client
            .get(format!("{}/dns/getroot/{}", self.endpoint, hostname))
            .send_with_retry(RETRY_ATTEMPTS)
            .await?;
        if response.status_code != 0 && !(200..300).contains(&response.status_code) {
            return Err(Error::Api(format!(
                "Dynu getroot returned status {}",
                response.status_code
            )));
        }
        Ok(response)
    }

    async fn list_at(
        &self,
        domain_id: i64,
        hostname: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Vec<ListedRecord>> {
        let response: RecordsResponse = self
            .client
            .get(format!(
                "{}/dns/record/{}?recordType={}",
                self.endpoint,
                hostname,
                record_type.as_str()
            ))
            .send_with_retry(RETRY_ATTEMPTS)
            .await?;
        if response.status_code != 0 && !(200..300).contains(&response.status_code) {
            return Err(Error::Api(format!(
                "Dynu getrecords returned status {}",
                response.status_code
            )));
        }
        let _ = domain_id;
        let target_type = record_type.as_str();
        let target_host = hostname.trim_end_matches('.');
        Ok(response
            .dns_records
            .into_iter()
            .filter(|r| {
                r.record_type.eq_ignore_ascii_case(target_type)
                    && r.hostname
                        .trim_end_matches('.')
                        .eq_ignore_ascii_case(target_host)
            })
            .collect())
    }
}

fn build_payloads(
    expected_type: DnsRecordType,
    records: Vec<DnsRecord>,
) -> crate::Result<Vec<Payload>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if record.as_type() != expected_type {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected_type.as_str(),
                record.as_type().as_str(),
            )));
        }
        let (_, payload) = record_type_and_payload(record)?;
        out.push(payload);
    }
    Ok(out)
}

fn record_type_and_payload(record: DnsRecord) -> crate::Result<(&'static str, Payload)> {
    match record {
        DnsRecord::TXT(text_data) => Ok(("TXT", Payload::Txt { text_data })),
        DnsRecord::A(ipv4_address) => Ok(("A", Payload::A { ipv4_address })),
        DnsRecord::AAAA(ipv6_address) => Ok(("AAAA", Payload::Aaaa { ipv6_address })),
        DnsRecord::CNAME(host) => Ok((
            "CNAME",
            Payload::Cname {
                host: host.into_name().into_owned(),
            },
        )),
        DnsRecord::NS(host) => Ok((
            "NS",
            Payload::Ns {
                host: host.into_name().into_owned(),
            },
        )),
        DnsRecord::MX(mx) => Ok((
            "MX",
            Payload::Mx {
                host: mx.exchange.into_name().into_owned(),
                priority: mx.priority,
            },
        )),
        DnsRecord::SRV(srv) => Ok((
            "SRV",
            Payload::Srv {
                host: srv.target.into_name().into_owned(),
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
            },
        )),
        DnsRecord::CAA(caa) => {
            let (flag, tag, caa_value) = caa.decompose();
            Ok((
                "CAA",
                Payload::Caa {
                    flag,
                    tag,
                    caa_value,
                },
            ))
        }
        DnsRecord::TLSA(tlsa) => Ok((
            "TLSA",
            Payload::Tlsa {
                certificate_usage: u8::from(tlsa.cert_usage),
                selector: u8::from(tlsa.selector),
                matching_type: u8::from(tlsa.matching),
                certificate: tlsa.cert_data.iter().map(|b| format!("{b:02x}")).collect(),
            },
        )),
    }
}

fn matches_payload(listed: &ListedRecord, payload: &Payload) -> bool {
    match payload {
        Payload::Txt { text_data } => listed
            .text_data
            .as_deref()
            .map(|s| s == text_data)
            .unwrap_or(false),
        Payload::A { ipv4_address } => listed.ipv4_address.as_ref() == Some(ipv4_address),
        Payload::Aaaa { ipv6_address } => listed.ipv6_address.as_ref() == Some(ipv6_address),
        Payload::Cname { host } | Payload::Ns { host } => listed
            .host
            .as_deref()
            .map(|h| {
                h.trim_end_matches('.')
                    .eq_ignore_ascii_case(host.trim_end_matches('.'))
            })
            .unwrap_or(false),
        Payload::Mx { host, priority } => {
            listed.priority == Some(*priority)
                && listed
                    .host
                    .as_deref()
                    .map(|h| {
                        h.trim_end_matches('.')
                            .eq_ignore_ascii_case(host.trim_end_matches('.'))
                    })
                    .unwrap_or(false)
        }
        Payload::Srv {
            host,
            priority,
            weight,
            port,
        } => {
            listed.priority == Some(*priority)
                && listed.weight == Some(*weight)
                && listed.port == Some(*port)
                && listed
                    .host
                    .as_deref()
                    .map(|h| {
                        h.trim_end_matches('.')
                            .eq_ignore_ascii_case(host.trim_end_matches('.'))
                    })
                    .unwrap_or(false)
        }
        Payload::Caa {
            flag,
            tag,
            caa_value,
        } => {
            listed.flag == Some(*flag)
                && listed.tag.as_deref() == Some(tag.as_str())
                && listed.caa_value.as_deref() == Some(caa_value.as_str())
        }
        Payload::Tlsa {
            certificate_usage,
            selector,
            matching_type,
            certificate,
        } => {
            listed.certificate_usage == Some(*certificate_usage)
                && listed.selector == Some(*selector)
                && listed.matching_type == Some(*matching_type)
                && listed
                    .certificate
                    .as_deref()
                    .map(|c| c.eq_ignore_ascii_case(certificate))
                    .unwrap_or(false)
        }
    }
}

fn listed_to_dns_record(listed: ListedRecord, expected: DnsRecordType) -> crate::Result<DnsRecord> {
    match expected {
        DnsRecordType::A => listed
            .ipv4_address
            .map(DnsRecord::A)
            .ok_or_else(|| Error::Parse("missing ipv4Address in Dynu A record".to_string())),
        DnsRecordType::AAAA => listed
            .ipv6_address
            .map(DnsRecord::AAAA)
            .ok_or_else(|| Error::Parse("missing ipv6Address in Dynu AAAA record".to_string())),
        DnsRecordType::CNAME => listed
            .host
            .map(DnsRecord::CNAME)
            .ok_or_else(|| Error::Parse("missing host in Dynu CNAME record".to_string())),
        DnsRecordType::NS => listed
            .host
            .map(DnsRecord::NS)
            .ok_or_else(|| Error::Parse("missing host in Dynu NS record".to_string())),
        DnsRecordType::MX => {
            let exchange = listed
                .host
                .ok_or_else(|| Error::Parse("missing host in Dynu MX record".to_string()))?;
            let priority = listed
                .priority
                .ok_or_else(|| Error::Parse("missing priority in Dynu MX record".to_string()))?;
            Ok(DnsRecord::MX(MXRecord { exchange, priority }))
        }
        DnsRecordType::TXT => listed
            .text_data
            .map(DnsRecord::TXT)
            .ok_or_else(|| Error::Parse("missing textData in Dynu TXT record".to_string())),
        DnsRecordType::SRV => {
            let target = listed
                .host
                .ok_or_else(|| Error::Parse("missing host in Dynu SRV record".to_string()))?;
            let priority = listed
                .priority
                .ok_or_else(|| Error::Parse("missing priority in Dynu SRV record".to_string()))?;
            let weight = listed
                .weight
                .ok_or_else(|| Error::Parse("missing weight in Dynu SRV record".to_string()))?;
            let port = listed
                .port
                .ok_or_else(|| Error::Parse("missing port in Dynu SRV record".to_string()))?;
            Ok(DnsRecord::SRV(SRVRecord {
                priority,
                weight,
                port,
                target,
            }))
        }
        DnsRecordType::CAA => {
            let flag = listed
                .flag
                .ok_or_else(|| Error::Parse("missing flag in Dynu CAA record".to_string()))?;
            let tag = listed
                .tag
                .ok_or_else(|| Error::Parse("missing tag in Dynu CAA record".to_string()))?;
            let value = listed
                .caa_value
                .ok_or_else(|| Error::Parse("missing caaValue in Dynu CAA record".to_string()))?;
            Ok(DnsRecord::CAA(build_caa(flag, &tag, &value)?))
        }
        DnsRecordType::TLSA => {
            let usage = listed.certificate_usage.ok_or_else(|| {
                Error::Parse("missing certificateUsage in Dynu TLSA record".to_string())
            })?;
            let selector = listed
                .selector
                .ok_or_else(|| Error::Parse("missing selector in Dynu TLSA record".to_string()))?;
            let matching = listed.matching_type.ok_or_else(|| {
                Error::Parse("missing matchingType in Dynu TLSA record".to_string())
            })?;
            let hex = listed.certificate.ok_or_else(|| {
                Error::Parse("missing certificate in Dynu TLSA record".to_string())
            })?;
            Ok(DnsRecord::TLSA(TLSARecord {
                cert_usage: tlsa_cert_usage_from_u8(usage)?,
                selector: tlsa_selector_from_u8(selector)?,
                matching: tlsa_matching_from_u8(matching)?,
                cert_data: decode_hex(&hex)?,
            }))
        }
    }
}
