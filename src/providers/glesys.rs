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
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.glesys.com";

#[derive(Clone)]
pub struct GlesysProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct AddRecordRequest<'a> {
    domainname: &'a str,
    host: &'a str,
    #[serde(rename = "type")]
    rr_type: &'a str,
    data: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u16>,
}

#[derive(Serialize, Debug)]
struct UpdateRecordRequest<'a> {
    recordid: i64,
    data: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

#[derive(Serialize, Debug)]
struct DeleteRecordRequest {
    recordid: i64,
}

#[derive(Serialize, Debug)]
struct ListRecordsRequest<'a> {
    domainname: &'a str,
}

#[derive(Deserialize, Debug)]
struct ApiEnvelope<T> {
    response: T,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct AddRecordResponse {
    record: AddedRecord,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct AddedRecord {
    recordid: i64,
}

#[derive(Deserialize, Debug)]
struct ListRecordsResponse {
    records: Vec<ListedRecord>,
}

#[derive(Deserialize, Debug)]
struct ListedRecord {
    recordid: i64,
    #[serde(rename = "type")]
    rr_type: String,
    host: String,
}

#[derive(Deserialize, Debug)]
struct GenericResponse {
    #[allow(dead_code)]
    #[serde(default)]
    status: Option<serde_json::Value>,
}

impl GlesysProvider {
    pub(crate) fn new(
        api_user: impl AsRef<str>,
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> Self {
        let raw = format!("{}:{}", api_user.as_ref(), api_key.as_ref());
        let encoded = B64.encode(raw);
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {encoded}"))
            .with_header("Accept", "application/json")
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

    async fn list_records(&self, domain: &str) -> crate::Result<Vec<ListedRecord>> {
        let envelope: ApiEnvelope<ListRecordsResponse> = self
            .client
            .post(format!("{}/domain/listrecords", self.endpoint))
            .with_body(ListRecordsRequest { domainname: domain })?
            .send_with_retry(3)
            .await?;
        Ok(envelope.response.records)
    }

    async fn find_record_id(
        &self,
        domain: &str,
        host: &str,
        rr_type: &str,
    ) -> crate::Result<i64> {
        let records = self.list_records(domain).await?;
        records
            .into_iter()
            .find(|r| r.host == host && r.rr_type == rr_type)
            .map(|r| r.recordid)
            .ok_or_else(|| {
                Error::Api(format!(
                    "Glesys record {host} of type {rr_type} not found"
                ))
            })
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let zone = origin.into_name().to_string();
        let host = strip_origin_from_name(name.into_name().as_ref(), &zone, Some("@"));
        let rr_type = record.as_type().as_str();
        let priority = record.priority();
        let data = render_data(&record)?;
        let _: ApiEnvelope<AddRecordResponse> = self
            .client
            .post(format!("{}/domain/addrecord", self.endpoint))
            .with_body(AddRecordRequest {
                domainname: &zone,
                host: &host,
                rr_type,
                data: &data,
                ttl: Some(ttl),
                priority,
            })?
            .send_with_retry(3)
            .await?;
        Ok(())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let zone = origin.into_name().to_string();
        let host = strip_origin_from_name(name.into_name().as_ref(), &zone, Some("@"));
        let rr_type = record.as_type().as_str();
        let record_id = self.find_record_id(&zone, &host, rr_type).await?;
        let data = render_data(&record)?;
        let _: GenericResponse = self
            .client
            .post(format!("{}/domain/updaterecord", self.endpoint))
            .with_body(UpdateRecordRequest {
                recordid: record_id,
                data: &data,
                ttl: Some(ttl),
            })?
            .send_with_retry(3)
            .await?;
        Ok(())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let zone = origin.into_name().to_string();
        let host = strip_origin_from_name(name.into_name().as_ref(), &zone, Some("@"));
        let record_id = self
            .find_record_id(&zone, &host, record_type.as_str())
            .await?;
        let _: GenericResponse = self
            .client
            .post(format!("{}/domain/deleterecord", self.endpoint))
            .with_body(DeleteRecordRequest { recordid: record_id })?
            .send_with_retry(3)
            .await?;
        Ok(())
    }
}

fn render_data(record: &DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(content) => content.clone(),
        DnsRecord::NS(content) => content.clone(),
        DnsRecord::TXT(content) => content.clone(),
        DnsRecord::MX(mx) => mx.exchange.clone(),
        DnsRecord::SRV(srv) => srv.target.clone(),
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Glesys".to_string(),
            ));
        }
        DnsRecord::CAA(caa) => caa.to_string(),
    })
}
