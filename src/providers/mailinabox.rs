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

use base64::{Engine, engine::general_purpose::STANDARD};

use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, http::HttpClientBuilder};
use std::time::Duration;

#[derive(Clone)]
pub struct MailinaboxProvider {
    client: HttpClientBuilder,
    endpoint: String,
}

impl MailinaboxProvider {
    pub(crate) fn new(
        base_url: impl AsRef<str>,
        email: impl AsRef<str>,
        password: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let raw = base_url.as_ref().trim_end_matches('/');
        if raw.is_empty() {
            return Err(Error::Api("Mail-in-a-Box base URL is required".into()));
        }
        if email.as_ref().is_empty() || password.as_ref().is_empty() {
            return Err(Error::Api(
                "Mail-in-a-Box email and password are required".into(),
            ));
        }

        let token = STANDARD.encode(format!("{}:{}", email.as_ref(), password.as_ref()));
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Basic {token}"))
            .with_header("Content-Type", "text/plain")
            .with_header("Accept", "application/json")
            .with_timeout(timeout);

        Ok(Self {
            client,
            endpoint: raw.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().trim_end_matches('/').to_string(),
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
        let _ = (ttl, origin);
        let qname = name.into_name().to_string();
        let record_type = record.as_type();
        let value = mailinabox_value(&record)?;
        self.client
            .post(self.record_url(&qname, record_type))
            .with_raw_body(value)
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
        let _ = (ttl, origin);
        let qname = name.into_name().to_string();
        let record_type = record.as_type();
        let value = mailinabox_value(&record)?;
        self.client
            .put(self.record_url(&qname, record_type))
            .with_raw_body(value)
            .send_raw()
            .await
            .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let _ = origin;
        let qname = name.into_name().to_string();
        self.client
            .delete(self.record_url(&qname, record_type))
            .send_raw()
            .await
            .map(|_| ())
    }

    fn record_url(&self, qname: &str, record_type: DnsRecordType) -> String {
        format!(
            "{}/admin/dns/custom/{}/{}",
            self.endpoint,
            qname,
            record_type.as_str()
        )
    }
}

fn mailinabox_value(record: &DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(value) => value.clone(),
        DnsRecord::NS(value) => value.clone(),
        DnsRecord::MX(mx) => mx.to_string(),
        DnsRecord::TXT(text) => text.clone(),
        DnsRecord::SRV(srv) => srv.to_string(),
        DnsRecord::TLSA(tlsa) => tlsa.to_string(),
        DnsRecord::CAA(caa) => caa.to_string(),
    })
}
