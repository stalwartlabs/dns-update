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
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct BluecatV2Config {
    pub server_url: String,
    pub username: String,
    pub password: String,
    pub config_name: String,
    pub view_name: String,
    pub skip_deploy: bool,
    pub request_timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct BluecatV2Provider {
    client: HttpClientBuilder,
    config: BluecatV2Config,
    endpoint: String,
    token: Arc<Mutex<Option<(String, Instant)>>>,
}

#[derive(Serialize, Debug)]
struct LoginInfo<'a> {
    username: &'a str,
    password: &'a str,
}

#[derive(Deserialize, Debug)]
struct SessionResponse {
    #[serde(rename = "basicAuthenticationCredentials")]
    basic_authentication_credentials: String,
}

#[derive(Deserialize, Debug)]
struct ZoneResource {
    id: i64,
    #[serde(rename = "absoluteName")]
    absolute_name: String,
}

#[derive(Deserialize, Debug)]
struct Collection<T> {
    data: Vec<T>,
}

#[derive(Deserialize, Debug)]
struct ResourceRecord {
    id: i64,
    #[serde(rename = "absoluteName", default)]
    absolute_name: Option<String>,
    #[serde(rename = "recordType", default)]
    record_type: Option<String>,
}

#[derive(Serialize, Debug)]
struct ResourceRecordPayload<'a> {
    #[serde(rename = "type")]
    rr_type: &'static str,
    name: &'a str,
    #[serde(rename = "recordType")]
    record_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    #[serde(flatten)]
    data: RecordData,
}

#[derive(Serialize, Debug)]
#[serde(untagged)]
enum RecordData {
    Address {
        addresses: Vec<String>,
    },
    LinkedRecord {
        #[serde(rename = "linkedRecord")]
        linked_record: LinkedRecord,
    },
    Mx {
        priority: u16,
        #[serde(rename = "linkedRecord")]
        linked_record: LinkedRecord,
    },
    Text {
        text: String,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        #[serde(rename = "linkedRecord")]
        linked_record: LinkedRecord,
    },
    Caa {
        flags: u8,
        tag: String,
        value: String,
    },
}

#[derive(Serialize, Debug)]
struct LinkedRecord {
    #[serde(rename = "absoluteName")]
    absolute_name: String,
}

#[derive(Serialize, Debug)]
struct QuickDeploymentPayload {
    #[serde(rename = "type")]
    rr_type: &'static str,
}

impl BluecatV2Provider {
    pub(crate) fn new(config: BluecatV2Config) -> crate::Result<Self> {
        if config.server_url.is_empty() {
            return Err(Error::Api("Bluecat server URL is required".into()));
        }
        if config.username.is_empty() || config.password.is_empty() {
            return Err(Error::Api("Bluecat credentials are required".into()));
        }
        if config.config_name.is_empty() {
            return Err(Error::Api("Bluecat configuration name is required".into()));
        }
        if config.view_name.is_empty() {
            return Err(Error::Api("Bluecat view name is required".into()));
        }

        let endpoint = config.server_url.trim_end_matches('/').to_string();
        let client = HttpClientBuilder::default()
            .with_header("Accept", "application/json")
            .with_timeout(config.request_timeout);

        Ok(Self {
            client,
            config,
            endpoint,
            token: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        self.endpoint = endpoint.as_ref().trim_end_matches('/').to_string();
        self
    }

    async fn ensure_token(&self) -> crate::Result<String> {
        {
            let guard = self
                .token
                .lock()
                .map_err(|_| Error::Api("Bluecat token mutex poisoned".into()))?;
            if let Some((ref token, expiry)) = *guard
                && Instant::now() < expiry
            {
                return Ok(token.clone());
            }
        }

        let url = format!("{}/api/v2/sessions", self.endpoint);
        let session: SessionResponse = self
            .client
            .post(url)
            .with_header("Content-Type", "application/json")
            .with_body(LoginInfo {
                username: &self.config.username,
                password: &self.config.password,
            })?
            .send()
            .await?;

        let expiry = Instant::now() + Duration::from_secs(25 * 60);
        let mut guard = self
            .token
            .lock()
            .map_err(|_| Error::Api("Bluecat token mutex poisoned".into()))?;
        *guard = Some((session.basic_authentication_credentials.clone(), expiry));
        Ok(session.basic_authentication_credentials)
    }

    fn authed_get(&self, url: String, token: &str) -> crate::http::HttpClient {
        self.client
            .get(url)
            .with_header("Authorization", format!("Basic {token}"))
    }

    fn authed_post(&self, url: String, token: &str) -> crate::http::HttpClient {
        self.client
            .post(url)
            .with_header("Authorization", format!("Basic {token}"))
    }

    fn authed_delete(&self, url: String, token: &str) -> crate::http::HttpClient {
        self.client
            .delete(url)
            .with_header("Authorization", format!("Basic {token}"))
    }

    async fn find_zone(&self, token: &str, origin: &str) -> crate::Result<ZoneResource> {
        let origin = origin.trim_end_matches('.');
        let filter = format!(
            "absoluteName:eq('{}') and configuration.name:eq('{}') and view.name:eq('{}')",
            origin, self.config.config_name, self.config.view_name
        );
        let query = serde_urlencoded::to_string([
            ("fields", "id,absoluteName"),
            ("filter", filter.as_str()),
        ])
        .map_err(|err| Error::Serialize(err.to_string()))?;
        let url = format!("{}/api/v2/zones?{}", self.endpoint, query);
        let zones: Collection<ZoneResource> = self.authed_get(url, token).send().await?;
        zones
            .data
            .into_iter()
            .find(|z| z.absolute_name.trim_end_matches('.') == origin)
            .ok_or_else(|| Error::Api(format!("No Bluecat zone found for {origin}")))
    }

    async fn find_record(
        &self,
        token: &str,
        zone_id: i64,
        absolute_name: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<Option<i64>> {
        let rtype = bluecat_record_type(record_type)?;
        let filter = format!(
            "absoluteName:eq('{}') and recordType:eq('{}')",
            absolute_name.trim_end_matches('.'),
            rtype
        );
        let query = serde_urlencoded::to_string([
            ("fields", "id,absoluteName,recordType"),
            ("filter", filter.as_str()),
        ])
        .map_err(|err| Error::Serialize(err.to_string()))?;
        let url = format!(
            "{}/api/v2/zones/{}/resourceRecords?{}",
            self.endpoint, zone_id, query
        );
        let records: Collection<ResourceRecord> = self.authed_get(url, token).send().await?;
        Ok(records.data.into_iter().find_map(|r| {
            let name_ok = r
                .absolute_name
                .as_deref()
                .map(|n| n.trim_end_matches('.') == absolute_name.trim_end_matches('.'))
                .unwrap_or(true);
            let type_ok = r.record_type.as_deref().map(|t| t == rtype).unwrap_or(true);
            if name_ok && type_ok { Some(r.id) } else { None }
        }))
    }

    async fn deploy_zone(&self, token: &str, zone_id: i64) -> crate::Result<()> {
        if self.config.skip_deploy {
            return Ok(());
        }
        let url = format!(
            "{}/api/v2/zones/{}/deployments",
            self.endpoint, zone_id
        );
        self.authed_post(url, token)
            .with_header("Content-Type", "application/json")
            .with_body(QuickDeploymentPayload {
                rr_type: "QuickDeployment",
            })?
            .send_raw()
            .await
            .map(|_| ())
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let token = self.ensure_token().await?;
        let origin = origin.into_name().to_string();
        let zone = self.find_zone(&token, &origin).await?;
        let name = name.into_name().to_string();
        let subdomain = strip_origin_from_name(&name, &origin, Some(""));

        let payload = build_resource_record(&subdomain, &record, ttl)?;
        let url = format!(
            "{}/api/v2/zones/{}/resourceRecords",
            self.endpoint, zone.id
        );
        self.authed_post(url, &token)
            .with_header("Content-Type", "application/json")
            .with_body(payload)?
            .send_raw()
            .await
            .map(|_| ())?;

        self.deploy_zone(&token, zone.id).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let token = self.ensure_token().await?;
        let origin = origin.into_name().to_string();
        let zone = self.find_zone(&token, &origin).await?;
        let name = name.into_name().to_string();
        let subdomain = strip_origin_from_name(&name, &origin, Some(""));
        let record_type = record.as_type();

        if let Some(record_id) = self
            .find_record(&token, zone.id, &name, record_type)
            .await?
        {
            let url = format!("{}/api/v2/resourceRecords/{}", self.endpoint, record_id);
            self.authed_delete(url, &token).send_raw().await.map(|_| ())?;
        }

        let payload = build_resource_record(&subdomain, &record, ttl)?;
        let url = format!(
            "{}/api/v2/zones/{}/resourceRecords",
            self.endpoint, zone.id
        );
        self.authed_post(url, &token)
            .with_header("Content-Type", "application/json")
            .with_body(payload)?
            .send_raw()
            .await
            .map(|_| ())?;

        self.deploy_zone(&token, zone.id).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let token = self.ensure_token().await?;
        let origin = origin.into_name().to_string();
        let zone = self.find_zone(&token, &origin).await?;
        let name = name.into_name().to_string();

        let Some(record_id) = self
            .find_record(&token, zone.id, &name, record_type)
            .await?
        else {
            return Err(Error::NotFound);
        };

        let url = format!("{}/api/v2/resourceRecords/{}", self.endpoint, record_id);
        self.authed_delete(url, &token).send_raw().await.map(|_| ())?;

        self.deploy_zone(&token, zone.id).await
    }
}

fn bluecat_record_type(record_type: DnsRecordType) -> crate::Result<&'static str> {
    Ok(match record_type {
        DnsRecordType::A => "A",
        DnsRecordType::AAAA => "AAAA",
        DnsRecordType::CNAME => "CNAME",
        DnsRecordType::NS => "NS",
        DnsRecordType::MX => "MX",
        DnsRecordType::TXT => "TXT",
        DnsRecordType::SRV => "SRV",
        DnsRecordType::CAA => "CAA",
        DnsRecordType::TLSA => {
            return Err(Error::Api(
                "TLSA records are not supported by Bluecat".into(),
            ));
        }
    })
}

fn build_resource_record<'a>(
    subdomain: &'a str,
    record: &DnsRecord,
    ttl: u32,
) -> crate::Result<ResourceRecordPayload<'a>> {
    let (rr_type, record_type, data) = match record {
        DnsRecord::A(addr) => (
            "GenericRecord",
            "A",
            RecordData::Address {
                addresses: vec![addr.to_string()],
            },
        ),
        DnsRecord::AAAA(addr) => (
            "GenericRecord",
            "AAAA",
            RecordData::Address {
                addresses: vec![addr.to_string()],
            },
        ),
        DnsRecord::CNAME(value) => (
            "AliasRecord",
            "CNAME",
            RecordData::LinkedRecord {
                linked_record: LinkedRecord {
                    absolute_name: value.clone(),
                },
            },
        ),
        DnsRecord::NS(value) => (
            "GenericRecord",
            "NS",
            RecordData::LinkedRecord {
                linked_record: LinkedRecord {
                    absolute_name: value.clone(),
                },
            },
        ),
        DnsRecord::MX(mx) => (
            "MXRecord",
            "MX",
            RecordData::Mx {
                priority: mx.priority,
                linked_record: LinkedRecord {
                    absolute_name: mx.exchange.clone(),
                },
            },
        ),
        DnsRecord::TXT(text) => (
            "TXTRecord",
            "TXT",
            RecordData::Text { text: text.clone() },
        ),
        DnsRecord::SRV(srv) => (
            "SRVRecord",
            "SRV",
            RecordData::Srv {
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
                linked_record: LinkedRecord {
                    absolute_name: srv.target.clone(),
                },
            },
        ),
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.clone().decompose();
            (
                "CAARecord",
                "CAA",
                RecordData::Caa { flags, tag, value },
            )
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Bluecat".into(),
            ));
        }
    };

    Ok(ResourceRecordPayload {
        rr_type,
        name: subdomain,
        record_type,
        ttl: Some(ttl),
        data,
    })
}
