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
use std::{borrow::Cow, time::Duration};

const DEFAULT_API_ENDPOINT: &str = "https://freemyip.com/update";

const FREEMYIP_ROOT: &str = "freemyip.com";

#[derive(Clone)]
pub struct FreeMyIpProvider {
    client: HttpClient,
    token: String,
    endpoint: Cow<'static, str>,
}

impl FreeMyIpProvider {
    pub(crate) fn new(token: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        let token = token.as_ref();
        if token.is_empty() {
            return Err(Error::Api("freemyip token is empty".to_string()));
        }
        Ok(Self {
            client: HttpClientBuilder::default().with_timeout(timeout).build(),
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
                "Only TXT records are supported by FreeMyIP".to_string(),
            ));
        }
        let domain = full_domain(name.into_name().as_ref())?;
        match records.len() {
            0 => self.update_txt(&domain, "").await,
            1 => match records.into_iter().next() {
                Some(DnsRecord::TXT(value)) => self.update_txt(&domain, &value).await,
                _ => Err(Error::Api(
                    "Only TXT records are supported by FreeMyIP".to_string(),
                )),
            },
            _ => Err(Error::Api(
                "FreeMyIP only supports one TXT record per host".to_string(),
            )),
        }
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        if record_type != DnsRecordType::TXT {
            return Err(Error::Api(
                "Only TXT records are supported by FreeMyIP".to_string(),
            ));
        }
        if records.is_empty() {
            return Ok(());
        }
        self.set_rrset(name, record_type, ttl, records, origin)
            .await
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        if record_type != DnsRecordType::TXT {
            return Err(Error::Api(
                "Only TXT records are supported by FreeMyIP".to_string(),
            ));
        }
        if records.is_empty() {
            return Ok(());
        }
        let domain = full_domain(name.into_name().as_ref())?;
        self.update_txt(&domain, "").await
    }

    pub(crate) async fn list_rrset(
        &self,
        _name: impl IntoFqdn<'_>,
        _record_type: DnsRecordType,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        Err(Error::Api(
            "FreeMyIP does not support listing records".to_string(),
        ))
    }

    async fn update_txt(&self, domain: &str, value: &str) -> crate::Result<()> {
        let query = serde_urlencoded::to_string([
            ("token", self.token.as_str()),
            ("domain", domain),
            ("txt", value),
        ])
        .map_err(|err| Error::Serialize(format!("Failed to encode query: {err}")))?;

        let response = self
            .client
            .get(format!("{}?{}", self.endpoint, query))
            .send_raw()
            .await?;

        let body = response.trim();
        if body.eq_ignore_ascii_case("ok") {
            Ok(())
        } else {
            Err(Error::Api(format!(
                "freemyip update did not return OK: {body}"
            )))
        }
    }
}

fn full_domain(name: &str) -> crate::Result<String> {
    let trimmed = name.trim_end_matches('.').to_ascii_lowercase();
    if !trimmed.ends_with(FREEMYIP_ROOT) {
        return Err(Error::Api(format!(
            "freemyip requires a domain under {FREEMYIP_ROOT}: {name}"
        )));
    }
    Ok(trimmed)
}
