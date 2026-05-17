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
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.nsone.net/v1";

#[derive(Clone)]
pub struct Ns1Provider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct RecordBody<'a> {
    zone: &'a str,
    domain: &'a str,
    #[serde(rename = "type")]
    rr_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    answers: Vec<Answer>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Answer {
    answer: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct EmptyResponse {}

impl Ns1Provider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("X-NSONE-Key", api_key.as_ref())
            .with_timeout(timeout);
        Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
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
        let zone = origin.into_name().to_string();
        let domain = name.into_name().to_string();
        let rr_type = record.as_type().as_str();
        let answers = record_to_answers(record)?;

        self.client
            .put(format!(
                "{endpoint}/zones/{zone}/{domain}/{rr_type}",
                endpoint = self.endpoint,
            ))
            .with_body(RecordBody {
                zone: &zone,
                domain: &domain,
                rr_type,
                ttl: Some(ttl),
                answers,
            })?
            .send_with_retry::<EmptyResponse>(3)
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
        let zone = origin.into_name().to_string();
        let domain = name.into_name().to_string();
        let rr_type = record.as_type().as_str();
        let answers = record_to_answers(record)?;

        self.client
            .post(format!(
                "{endpoint}/zones/{zone}/{domain}/{rr_type}",
                endpoint = self.endpoint,
            ))
            .with_body(RecordBody {
                zone: &zone,
                domain: &domain,
                rr_type,
                ttl: Some(ttl),
                answers,
            })?
            .send_with_retry::<EmptyResponse>(3)
            .await
            .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let zone = origin.into_name().to_string();
        let domain = name.into_name().to_string();
        let rr_type = record_type.as_str();

        self.client
            .delete(format!(
                "{endpoint}/zones/{zone}/{domain}/{rr_type}",
                endpoint = self.endpoint,
            ))
            .send_raw()
            .await
            .map(|_| ())
    }
}

fn record_to_answers(record: DnsRecord) -> crate::Result<Vec<Answer>> {
    let parts: Vec<String> = match record {
        DnsRecord::A(addr) => vec![addr.to_string()],
        DnsRecord::AAAA(addr) => vec![addr.to_string()],
        DnsRecord::CNAME(content) => vec![content],
        DnsRecord::NS(content) => vec![content],
        DnsRecord::TXT(content) => vec![content],
        DnsRecord::MX(mx) => vec![mx.priority.to_string(), mx.exchange],
        DnsRecord::SRV(srv) => vec![
            srv.priority.to_string(),
            srv.weight.to_string(),
            srv.port.to_string(),
            srv.target,
        ],
        DnsRecord::TLSA(tlsa) => vec![
            u8::from(tlsa.cert_usage).to_string(),
            u8::from(tlsa.selector).to_string(),
            u8::from(tlsa.matching).to_string(),
            tlsa.cert_data.iter().map(|b| format!("{b:02x}")).collect(),
        ],
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.decompose();
            vec![flags.to_string(), tag, value]
        }
    };

    if parts.is_empty() {
        return Err(Error::Api("Empty record data for NS1".to_string()));
    }
    Ok(vec![Answer { answer: parts }])
}
