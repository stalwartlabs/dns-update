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
    DnsRecord, DnsRecordType, IntoFqdn,
    http::HttpClientBuilder,
    utils::{strip_origin_from_name, txt_chunks_to_text},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://api.hetzner.cloud/v1";

#[derive(Clone)]
pub struct HetznerProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

pub struct HetznerDnsRecordRepresentation {
    pub record_type: String,
    pub value: String,
}

#[derive(Serialize, Debug)]
pub struct CreateRRSetRequest<'a> {
    pub name: &'a str,
    #[serde(rename = "type")]
    pub rr_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    pub records: Vec<RRSetRecord>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RRSetRecord {
    pub value: String,
}

#[derive(Serialize, Debug)]
pub struct SetRecordsRequest {
    pub records: Vec<RRSetRecord>,
}

#[derive(Serialize, Debug)]
pub struct ChangeTtlRequest {
    pub ttl: u32,
}

#[derive(Deserialize, Debug)]
struct EmptyResponse {}

impl HetznerProvider {
    pub(crate) fn new(api_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", api_token.as_ref()))
            .with_timeout(timeout);
        Self {
            client,
            endpoint: DEFAULT_ENDPOINT.to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
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
        let subdomain = strip_origin_from_name(&name.into_name(), &zone, None);
        let hetzner_record = HetznerDnsRecordRepresentation::from(record);

        self.client
            .post(format!(
                "{endpoint}/zones/{zone}/rrsets",
                endpoint = self.endpoint,
                zone = &zone,
            ))
            .with_body(CreateRRSetRequest {
                name: &subdomain,
                rr_type: &hetzner_record.record_type,
                ttl: Some(ttl),
                records: vec![RRSetRecord {
                    value: hetzner_record.value,
                }],
            })?
            .send_with_retry::<serde_json::Value>(3)
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
        let zone = origin.into_name();
        let subdomain = strip_origin_from_name(&name.into_name(), &zone, None);
        let hetzner_record = HetznerDnsRecordRepresentation::from(record);

        self.client
            .post(format!(
                "{endpoint}/zones/{zone}/rrsets/{rr_name}/{rr_type}/actions/set_records",
                endpoint = self.endpoint,
                zone = &zone,
                rr_name = &subdomain,
                rr_type = &hetzner_record.record_type,
            ))
            .with_body(SetRecordsRequest {
                records: vec![RRSetRecord {
                    value: hetzner_record.value,
                }],
            })?
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())?;

        self.client
            .post(format!(
                "{endpoint}/zones/{zone}/rrsets/{rr_name}/{rr_type}/actions/change_ttl",
                endpoint = self.endpoint,
                zone = &zone,
                rr_name = &subdomain,
                rr_type = &hetzner_record.record_type,
            ))
            .with_body(ChangeTtlRequest { ttl })?
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let zone = origin.into_name();
        let subdomain = strip_origin_from_name(&name.into_name(), &zone, None);

        self.client
            .delete(format!(
                "{endpoint}/zones/{zone}/rrsets/{rr_name}/{rr_type}",
                endpoint = self.endpoint,
                zone = &zone,
                rr_name = &subdomain,
                rr_type = record_type.as_str(),
            ))
            .send_with_retry::<EmptyResponse>(3)
            .await
            .map(|_| ())
    }
}

fn ensure_fqdn(name: String) -> String {
    if name.ends_with('.') {
        name
    } else {
        format!("{name}.")
    }
}

/// Converts a DNS record into a representation that can be sent to the
/// Hetzner Cloud DNS API. Values are encoded in standard DNS zone-file
/// format, as accepted by the Zone RRSets endpoints.
impl From<DnsRecord> for HetznerDnsRecordRepresentation {
    fn from(record: DnsRecord) -> Self {
        match record {
            DnsRecord::A(content) => HetznerDnsRecordRepresentation {
                record_type: "A".to_string(),
                value: content.to_string(),
            },
            DnsRecord::AAAA(content) => HetznerDnsRecordRepresentation {
                record_type: "AAAA".to_string(),
                value: content.to_string(),
            },
            DnsRecord::CNAME(content) => HetznerDnsRecordRepresentation {
                record_type: "CNAME".to_string(),
                value: ensure_fqdn(content),
            },
            DnsRecord::NS(content) => HetznerDnsRecordRepresentation {
                record_type: "NS".to_string(),
                value: ensure_fqdn(content),
            },
            DnsRecord::MX(mx) => HetznerDnsRecordRepresentation {
                record_type: "MX".to_string(),
                value: format!("{} {}", mx.priority, ensure_fqdn(mx.exchange)),
            },
            DnsRecord::TXT(content) => {
                let mut value = String::new();
                txt_chunks_to_text(&mut value, &content, " ");
                HetznerDnsRecordRepresentation {
                    record_type: "TXT".to_string(),
                    value,
                }
            }
            DnsRecord::SRV(srv) => HetznerDnsRecordRepresentation {
                record_type: "SRV".to_string(),
                value: format!(
                    "{} {} {} {}",
                    srv.priority,
                    srv.weight,
                    srv.port,
                    ensure_fqdn(srv.target)
                ),
            },
            DnsRecord::TLSA(tlsa) => HetznerDnsRecordRepresentation {
                record_type: "TLSA".to_string(),
                value: tlsa.to_string(),
            },
            DnsRecord::CAA(caa) => HetznerDnsRecordRepresentation {
                record_type: "CAA".to_string(),
                value: caa.to_string(),
            },
        }
    }
}
