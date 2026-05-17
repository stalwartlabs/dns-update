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
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://rest.easydns.net";

#[derive(Clone)]
pub struct EasyDnsProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct ZoneRecordPayload<'a> {
    domain: &'a str,
    host: &'a str,
    ttl: String,
    prio: String,
    #[serde(rename = "type")]
    record_type: &'a str,
    rdata: String,
}

#[derive(Deserialize, Debug, Default)]
#[allow(dead_code)]
struct ZoneRecord {
    #[serde(default)]
    id: String,
    #[serde(default)]
    host: String,
    #[serde(default, rename = "type")]
    record_type: String,
    #[serde(default)]
    rdata: String,
    #[serde(default)]
    ttl: String,
    #[serde(default)]
    prio: String,
}

#[derive(Deserialize, Debug)]
struct ApiEnvelope<T> {
    #[serde(default)]
    data: Option<T>,
    #[serde(default)]
    error: Option<ApiError>,
}

#[derive(Deserialize, Debug)]
struct ApiError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

impl EasyDnsProvider {
    pub(crate) fn new(
        token: impl AsRef<str>,
        key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let token = token.as_ref();
        let key = key.as_ref();
        if token.is_empty() || key.is_empty() {
            return Err(Error::Api(
                "EasyDNS API token and key must not be empty".to_string(),
            ));
        }

        let credentials = STANDARD.encode(format!("{token}:{key}"));
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {credentials}"))
            .with_header("Accept", "application/json")
            .with_timeout(timeout);

        Ok(Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
        })
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
        let name = name.into_name();
        let domain = origin.into_name();
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let record_type = record.as_type();
        let priority = record.priority().unwrap_or(0);
        let rdata = render_value(record)?;

        let payload = ZoneRecordPayload {
            domain: domain.as_ref(),
            host: &subdomain,
            ttl: ttl.to_string(),
            prio: priority.to_string(),
            record_type: record_type.as_str(),
            rdata,
        };

        let body = self
            .client
            .put(format!(
                "{}/zones/records/add/{}/{}?format=json",
                self.endpoint,
                domain,
                record_type.as_str(),
            ))
            .with_body(payload)?
            .send_raw()
            .await?;

        let envelope: ApiEnvelope<ZoneRecord> = serde_json::from_str(&body)
            .map_err(|e| Error::Parse(format!("Invalid EasyDNS response: {e}")))?;
        check_error(envelope.error)?;
        Ok(())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let record_type = record.as_type();
        let record_id = self.obtain_record_id(&name, &domain, record_type).await?;
        let subdomain = strip_origin_from_name(&name, &domain, Some("@"));
        let priority = record.priority().unwrap_or(0);
        let rdata = render_value(record)?;

        let payload = ZoneRecordPayload {
            domain: domain.as_ref(),
            host: &subdomain,
            ttl: ttl.to_string(),
            prio: priority.to_string(),
            record_type: record_type.as_str(),
            rdata,
        };

        let body = self
            .client
            .post(format!(
                "{}/zones/records/{}/{}?format=json",
                self.endpoint, domain, record_id,
            ))
            .with_body(payload)?
            .send_raw()
            .await?;

        let envelope: ApiEnvelope<ZoneRecord> = serde_json::from_str(&body)
            .map_err(|e| Error::Parse(format!("Invalid EasyDNS response: {e}")))?;
        check_error(envelope.error)?;
        Ok(())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let record_id = self.obtain_record_id(&name, &domain, record_type).await?;

        self.client
            .delete(format!(
                "{}/zones/records/{}/{}?format=json",
                self.endpoint, domain, record_id,
            ))
            .send_raw()
            .await
            .map(|_| ())
    }

    async fn obtain_record_id(
        &self,
        name: &str,
        domain: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<String> {
        let body = self
            .client
            .get(format!(
                "{}/zones/records/all/{}?format=json",
                self.endpoint, domain,
            ))
            .send_raw()
            .await?;

        let envelope: ApiEnvelope<Vec<ZoneRecord>> = serde_json::from_str(&body)
            .map_err(|e| Error::Parse(format!("Invalid EasyDNS response: {e}")))?;
        check_error(envelope.error)?;

        let records = envelope.data.unwrap_or_default();
        let subdomain = strip_origin_from_name(name, domain, Some("@"));

        records
            .into_iter()
            .find(|r| r.record_type == record_type.as_str() && r.host == subdomain)
            .map(|r| r.id)
            .ok_or_else(|| {
                Error::Api(format!(
                    "DNS Record {} of type {} not found",
                    name,
                    record_type.as_str()
                ))
            })
    }
}

fn check_error(error: Option<ApiError>) -> crate::Result<()> {
    if let Some(err) = error {
        Err(Error::Api(format!(
            "EasyDNS error {}: {}",
            err.code, err.message
        )))
    } else {
        Ok(())
    }
}

fn render_value(record: DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content,
        DnsRecord::NS(content) => content,
        DnsRecord::MX(mx) => mx.exchange,
        DnsRecord::TXT(content) => content,
        DnsRecord::SRV(srv) => format!("{} {} {}", srv.weight, srv.port, srv.target),
        DnsRecord::CAA(caa) => caa.to_string(),
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by EasyDNS".to_string(),
            ));
        }
    })
}
