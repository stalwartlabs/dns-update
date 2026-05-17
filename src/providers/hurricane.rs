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
use std::{collections::HashMap, time::Duration};

const DEFAULT_ENDPOINT: &str = "https://dyn.dns.he.net/nic/update";

#[derive(Clone)]
pub struct HurricaneProvider {
    client: HttpClientBuilder,
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
            .with_timeout(timeout);
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

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        _ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let txt = extract_txt(&record)?;
        self.update_txt(name.into_name().as_ref(), origin.into_name().as_ref(), &txt)
            .await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        _ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let txt = extract_txt(&record)?;
        self.update_txt(name.into_name().as_ref(), origin.into_name().as_ref(), &txt)
            .await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        if record_type != DnsRecordType::TXT {
            return Err(Error::Api(format!(
                "{} records are not supported by Hurricane Electric",
                record_type.as_str()
            )));
        }
        self.update_txt(name.into_name().as_ref(), origin.into_name().as_ref(), ".")
            .await
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
