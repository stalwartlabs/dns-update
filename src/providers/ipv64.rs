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
use std::{borrow::Cow, time::Duration};

const DEFAULT_API_ENDPOINT: &str = "https://ipv64.net/api";

#[derive(Clone)]
pub struct Ipv64Provider {
    client: HttpClientBuilder,
    endpoint: Cow<'static, str>,
}

impl Ipv64Provider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        let api_key = api_key.as_ref();
        if api_key.is_empty() {
            return Err(Error::Api("IPv64 API key is empty".to_string()));
        }
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {api_key}"))
            .with_timeout(timeout);
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

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        _ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let content = match &record {
            DnsRecord::TXT(value) => value.clone(),
            _ => {
                return Err(Error::Api(
                    "Only TXT records are supported by IPv64".to_string(),
                ));
            }
        };
        let name = name.into_name();
        let domain = origin.into_name();
        let prefix = strip_origin_from_name(name.as_ref(), domain.as_ref(), Some(""));
        let body = serde_urlencoded::to_string([
            ("add_record", domain.as_ref()),
            ("praefix", prefix.as_str()),
            ("type", "TXT"),
            ("content", content.as_str()),
        ])
        .map_err(|err| Error::Serialize(format!("Failed to encode body: {err}")))?;

        self.client
            .post(self.endpoint.to_string())
            .with_raw_body(body)
            .send_raw()
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
        let name = name.into_name().into_owned();
        let origin_str = origin.into_name().into_owned();
        let record_type = record.as_type();
        self.delete(name.as_str(), origin_str.as_str(), record_type)
            .await
            .ok();
        self.create(name, record, ttl, origin_str).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        if record_type != DnsRecordType::TXT {
            return Err(Error::Api(
                "Only TXT records are supported by IPv64".to_string(),
            ));
        }
        let name = name.into_name();
        let domain = origin.into_name();
        let prefix = strip_origin_from_name(name.as_ref(), domain.as_ref(), Some(""));
        let body = serde_urlencoded::to_string([
            ("del_record", domain.as_ref()),
            ("praefix", prefix.as_str()),
            ("type", "TXT"),
            ("content", ""),
        ])
        .map_err(|err| Error::Serialize(format!("Failed to encode body: {err}")))?;

        self.client
            .delete(self.endpoint.to_string())
            .with_raw_body(body)
            .send_raw()
            .await
            .map(|_| ())
    }
}
