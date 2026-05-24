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
use std::{collections::HashMap, time::Duration};

const DEFAULT_ENDPOINT: &str = "https://dyn.dns.he.net/nic/update";

#[derive(Clone)]
pub struct HurricaneProvider {
    client: HttpClient,
    credentials: HashMap<String, String>,
    endpoint: String,
}

impl HurricaneProvider {
    pub(crate) fn new(
        credentials: HashMap<String, String>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        if credentials.is_empty() {
            return Err(Error::Api(
                "Hurricane Electric credentials map is empty".to_string(),
            ));
        }
        let client = HttpClientBuilder::default()
            .set_header("Content-Type", "application/x-www-form-urlencoded")
            .with_timeout(timeout)
            .build();
        Ok(Self {
            client,
            credentials,
            endpoint: DEFAULT_ENDPOINT.to_string(),
        })
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
        _ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        if record_type != DnsRecordType::TXT {
            return Err(Error::Api(
                "Only TXT records are supported by Hurricane Electric".to_string(),
            ));
        }
        let hostname = name.into_name().into_owned();
        let zone = origin.into_name().into_owned();

        match records.len() {
            0 => self.update_txt(&hostname, &zone, ".").await,
            1 => {
                let txt = extract_txt(&records[0])?;
                self.update_txt(&hostname, &zone, &txt).await
            }
            _ => Err(Error::Api(
                "Hurricane Electric only supports one TXT record per host".to_string(),
            )),
        }
    }

    pub(crate) async fn add_to_rrset(
        &self,
        _name: impl IntoFqdn<'_>,
        _record_type: DnsRecordType,
        _ttl: u32,
        _records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        Err(Error::Api(
            "Hurricane Electric does not support add_to_rrset (no list endpoint)".to_string(),
        ))
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        _name: impl IntoFqdn<'_>,
        _record_type: DnsRecordType,
        _records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        Err(Error::Api(
            "Hurricane Electric does not support remove_from_rrset (no list endpoint)".to_string(),
        ))
    }

    pub(crate) async fn list_rrset(
        &self,
        _name: impl IntoFqdn<'_>,
        _record_type: DnsRecordType,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        Err(Error::Api(
            "Hurricane Electric does not support listing records".to_string(),
        ))
    }

    async fn update_txt(&self, hostname: &str, zone: &str, txt: &str) -> crate::Result<()> {
        let token = self.credentials.get(zone).ok_or_else(|| {
            Error::Api(format!(
                "Domain {zone} not found in Hurricane Electric credentials"
            ))
        })?;

        let body = serde_urlencoded::to_string([
            ("password", token.as_str()),
            ("hostname", hostname),
            ("txt", txt),
        ])
        .map_err(|err| Error::Serialize(format!("Failed to encode form body: {err}")))?;

        let response = self
            .client
            .post(self.endpoint.clone())
            .with_raw_body(body)
            .send_raw()
            .await?;

        evaluate_body(response.trim(), hostname)
    }
}

fn extract_txt(record: &DnsRecord) -> crate::Result<String> {
    match record {
        DnsRecord::TXT(content) => Ok(content.clone()),
        other => Err(Error::Api(format!(
            "{} records are not supported by Hurricane Electric",
            other.as_type().as_str()
        ))),
    }
}

fn evaluate_body(body: &str, hostname: &str) -> crate::Result<()> {
    let code = body.split_whitespace().next().unwrap_or("");
    match code {
        "good" | "nochg" => Ok(()),
        "abuse" => Err(Error::Api(format!(
            "{body}: blocked hostname for abuse: {hostname}"
        ))),
        "badagent" => Err(Error::Api(format!(
            "{body}: user agent not sent or HTTP method not recognized"
        ))),
        "badauth" => Err(Error::Unauthorized),
        "interval" => Err(Error::Api(format!(
            "{body}: TXT records update exceeded API rate limit"
        ))),
        "nohost" => Err(Error::NotFound),
        "notfqdn" => Err(Error::Api(format!(
            "{body}: the record provided isn't an FQDN: {hostname}"
        ))),
        _ => Err(Error::Api(format!(
            "Attempt to change TXT record {hostname} returned {body}"
        ))),
    }
}
