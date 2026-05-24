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
use std::{borrow::Cow, time::Duration};

const DEFAULT_API_ENDPOINT: &str = "https://www.duckdns.org/update";

const DUCKDNS_SUFFIX: &str = "duckdns.org";

#[derive(Clone)]
pub struct DuckDnsProvider {
    client: HttpClientBuilder,
    token: String,
    endpoint: Cow<'static, str>,
}

impl DuckDnsProvider {
    pub(crate) fn new(token: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        let token = token.as_ref();
        if token.is_empty() {
            return Err(Error::Api("DuckDNS token is empty".to_string()));
        }
        Ok(Self {
            client: HttpClientBuilder::default().with_timeout(timeout),
            token: token.to_string(),
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
        _ttl: u32,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        if record_type != DnsRecordType::TXT {
            return Err(Error::Api(
                "Only TXT records are supported by DuckDNS".to_string(),
            ));
        }
        let domain = main_domain(name.into_name().as_ref())?;
        match records.len() {
            0 => self.update_txt(&domain, "", true).await,
            1 => match records.into_iter().next() {
                Some(DnsRecord::TXT(value)) => self.update_txt(&domain, &value, false).await,
                _ => Err(Error::Api(
                    "Only TXT records are supported by DuckDNS".to_string(),
                )),
            },
            _ => Err(Error::Api(
                "DuckDNS only supports one TXT record per host".to_string(),
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
            "DuckDNS does not support add_to_rrset (no list endpoint)".to_string(),
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
            "DuckDNS does not support remove_from_rrset (no list endpoint)".to_string(),
        ))
    }

    pub(crate) async fn list_rrset(
        &self,
        _name: impl IntoFqdn<'_>,
        _record_type: DnsRecordType,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        Err(Error::Api(
            "DuckDNS does not support listing records".to_string(),
        ))
    }

    async fn update_txt(&self, domain: &str, value: &str, clear: bool) -> crate::Result<()> {
        let query = serde_urlencoded::to_string([
            ("domains", domain),
            ("token", self.token.as_str()),
            ("clear", if clear { "true" } else { "false" }),
            ("txt", value),
        ])
        .map_err(|err| Error::Serialize(format!("Failed to encode query: {err}")))?;

        let response = self
            .client
            .get(format!("{}?{}", self.endpoint, query))
            .send_raw()
            .await?;
        if response.trim() == "OK" {
            Ok(())
        } else {
            Err(Error::Api(format!(
                "DuckDNS update did not return OK: {response}"
            )))
        }
    }
}

fn main_domain(name: &str) -> crate::Result<String> {
    let trimmed = name.trim_end_matches('.').to_ascii_lowercase();
    if trimmed.ends_with(DUCKDNS_SUFFIX) {
        let labels: Vec<&str> = trimmed.split('.').collect();
        if labels.len() < 3 {
            return Err(Error::Api(format!(
                "DuckDNS requires a subdomain of {DUCKDNS_SUFFIX}: {name}"
            )));
        }
        let start = labels.len() - 3;
        Ok(labels[start..].join("."))
    } else {
        let labels: Vec<&str> = trimmed.split('.').collect();
        if labels.is_empty() {
            return Err(Error::Api(format!("Invalid domain: {name}")));
        }
        Ok(labels[labels.len() - 1].to_string())
    }
}
