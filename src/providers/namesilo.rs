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
use quick_xml::de::from_str;
use serde::Deserialize;
use std::time::Duration;

#[derive(Clone)]
pub struct NameSiloProvider {
    client: HttpClientBuilder,
    endpoint: String,
    api_key: String,
}

#[derive(Deserialize, Debug)]
struct NameSiloEnvelope {
    reply: NameSiloReply,
}

#[derive(Deserialize, Debug)]
struct NameSiloReply {
    code: String,
    detail: String,
    #[serde(default)]
    resource_record: Vec<ResourceRecord>,
}

#[derive(Deserialize, Debug, Clone)]
struct ResourceRecord {
    record_id: String,
    #[serde(rename = "type")]
    record_type: String,
    host: String,
    #[allow(dead_code)]
    #[serde(default)]
    value: String,
    #[allow(dead_code)]
    #[serde(default)]
    ttl: String,
    #[allow(dead_code)]
    #[serde(default)]
    distance: String,
}

const DEFAULT_API_ENDPOINT: &str = "https://www.namesilo.com/api";

impl NameSiloProvider {
    pub(crate) fn new(
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let key = api_key.as_ref();
        if key.is_empty() {
            return Err(Error::Api(
                "NameSilo API key must not be empty".to_string(),
            ));
        }
        Ok(Self {
            client: HttpClientBuilder::default().with_timeout(timeout),
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            api_key: key.to_string(),
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
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let record_type = record.as_type();
        let distance = record.priority().unwrap_or(0);
        let value = render_value(record)?;

        let mut params = base_params(&self.api_key);
        params.push(("domain", domain.to_string()));
        params.push(("rrtype", record_type.as_str().to_string()));
        params.push(("rrhost", subdomain));
        params.push(("rrvalue", value));
        params.push(("rrttl", ttl.to_string()));
        params.push(("rrdistance", distance.to_string()));

        self.call("dnsAddRecord", &params).await.map(|_| ())
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
        let subdomain = strip_origin_from_name(&name, &domain, Some(""));
        let record_type = record.as_type();
        let distance = record.priority().unwrap_or(0);
        let value = render_value(record)?;

        let record_id = self.obtain_record_id(&domain, &name, record_type).await?;

        let mut params = base_params(&self.api_key);
        params.push(("domain", domain.to_string()));
        params.push(("rrid", record_id));
        params.push(("rrhost", subdomain));
        params.push(("rrvalue", value));
        params.push(("rrttl", ttl.to_string()));
        params.push(("rrdistance", distance.to_string()));

        self.call("dnsUpdateRecord", &params).await.map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name();
        let domain = origin.into_name();
        let record_id = self.obtain_record_id(&domain, &name, record_type).await?;

        let mut params = base_params(&self.api_key);
        params.push(("domain", domain.to_string()));
        params.push(("rrid", record_id));

        self.call("dnsDeleteRecord", &params).await.map(|_| ())
    }

    async fn obtain_record_id(
        &self,
        domain: &str,
        fqdn: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<String> {
        let mut params = base_params(&self.api_key);
        params.push(("domain", domain.to_string()));
        let reply = self.call("dnsListRecords", &params).await?;
        let host_target = fqdn.trim_end_matches('.').to_ascii_lowercase();
        let subdomain_target = strip_origin_from_name(fqdn, domain, Some(""));

        reply
            .resource_record
            .into_iter()
            .find(|r| {
                r.record_type == record_type.as_str()
                    && (r.host.to_ascii_lowercase() == host_target
                        || r.host == subdomain_target)
            })
            .map(|r| r.record_id)
            .ok_or_else(|| {
                Error::Api(format!(
                    "DNS Record {} of type {} not found",
                    fqdn,
                    record_type.as_str()
                ))
            })
    }

    async fn call(
        &self,
        operation: &str,
        params: &[(&str, String)],
    ) -> crate::Result<NameSiloReply> {
        let query = serde_urlencoded::to_string(params)
            .map_err(|e| Error::Serialize(e.to_string()))?;
        let url = format!("{}/{}?{}", self.endpoint, operation, query);
        let body = self.client.get(url).send_raw().await?;
        let envelope: NameSiloEnvelope =
            from_str(&body).map_err(|e| Error::Parse(format!("Invalid XML response: {e}")))?;
        if matches!(envelope.reply.code.as_str(), "300" | "301" | "302") {
            Ok(envelope.reply)
        } else {
            Err(Error::Api(format!(
                "NameSilo error {}: {}",
                envelope.reply.code, envelope.reply.detail
            )))
        }
    }
}

fn base_params(api_key: &str) -> Vec<(&'static str, String)> {
    vec![
        ("version", "1".to_string()),
        ("type", "xml".to_string()),
        ("key", api_key.to_string()),
    ]
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
                "TLSA records are not supported by NameSilo".to_string(),
            ));
        }
    })
}
