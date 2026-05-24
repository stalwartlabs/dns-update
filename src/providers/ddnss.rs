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

const DEFAULT_API_ENDPOINT: &str = "https://ddnss.de/upd.php";

#[derive(Clone)]
pub struct DdnssProvider {
    client: HttpClient,
    key: String,
    endpoint: Cow<'static, str>,
}

impl DdnssProvider {
    pub(crate) fn new(key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        let key = key.as_ref();
        if key.is_empty() {
            return Err(Error::Api("DDNSS key is empty".to_string()));
        }
        Ok(Self {
            client: HttpClientBuilder::default().with_timeout(timeout).build(),
            key: key.to_string(),
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
                "Only TXT records are supported by DDNSS".to_string(),
            ));
        }
        let host = name.into_name().into_owned();
        match records.len() {
            0 => self.send_update(&host, None, "2").await,
            1 => match &records[0] {
                DnsRecord::TXT(value) => self.send_update(&host, Some(value.as_str()), "1").await,
                _ => Err(Error::Api(
                    "Only TXT records are supported by DDNSS".to_string(),
                )),
            },
            _ => Err(Error::Api(
                "DDNSS only supports one TXT record per host".to_string(),
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
            "DDNSS does not support add_to_rrset (no list endpoint)".to_string(),
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
            "DDNSS does not support remove_from_rrset (no list endpoint)".to_string(),
        ))
    }

    pub(crate) async fn list_rrset(
        &self,
        _name: impl IntoFqdn<'_>,
        _record_type: DnsRecordType,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        Err(Error::Api(
            "DDNSS does not support listing records".to_string(),
        ))
    }

    async fn send_update(&self, host: &str, txt: Option<&str>, txtm: &str) -> crate::Result<()> {
        let mut params: Vec<(&str, &str)> =
            vec![("key", self.key.as_str()), ("host", host), ("txtm", txtm)];
        if let Some(value) = txt {
            params.push(("txt", value));
        }
        let query = serde_urlencoded::to_string(&params)
            .map_err(|err| Error::Serialize(format!("Failed to encode query: {err}")))?;

        let response = self
            .client
            .get(format!("{}?{}", self.endpoint, query))
            .send_raw()
            .await?;

        if response.to_ascii_lowercase().contains("updated 1 hostname") {
            Ok(())
        } else {
            Err(Error::Api(format!(
                "DDNSS update returned unexpected body: {response}"
            )))
        }
    }
}
