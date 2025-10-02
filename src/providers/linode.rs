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

/*  TODO: update variable names everywhere to disambiguate things and clear confusion:
 *
 *  Example: www.subdomain.ci-cd.stalwart.dns-update.jaygiffin.com
 *  (Where ci-cd.stalwart.dns-update.jaygiffin.com is registered and managed by itself in Linode;
 *   i.e. no access to managing the DNS of stalwart.dns-update.jaygiffin.com or above levels.)
 *
 *    www.subdomain                                          => name these variables "delegate"
 *                  ci-cd.stalwart.dns-update.jaygiffin.com  => name these variables "zone"
 *    www.subdomain.ci-cd.stalwart.dns-update.jaygiffin.com  => name these variables "fqdn"
 *
 *  Notice: no usage of the terms "domain", "subdomain", "origin", or "name" as their meanings
 *   are orthogonal to this usage context, rendering them ambiguous and confusing.
 */

/*  Disclaimer: this is my first time writing Rust and the below code was
 *   adapted from digitalocean.rs by comparing the following resources:
 *
 *  - https://docs.digitalocean.com/reference/api/digitalocean/#tag/Domain-Records/operation/domains_list_records
 *  - https://techdocs.akamai.com/linode-api/reference/get-domain-record
 *  - https://github.com/dns-lexicon/dns-lexicon/blob/1f57ac91d126f5847bd26aa7aa254af3565ba21c/src/lexicon/_private/providers/digitalocean.py
 *  - https://github.com/dns-lexicon/dns-lexicon/blob/58cf9eb209b61d4edd77535a9044a3b6a754a696/src/lexicon/_private/providers/linode4.py
 */

use std::{
    hash::{Hash, Hasher},
    time::Duration,
};

use crate::{
    http::HttpClientBuilder, strip_origin_from_name, ApiCacheFetcher, ApiCacheManager, DnsRecord,
    DnsRecordTrait, DnsRecordType, Error, IntoFqdn,
};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct LinodeProvider {
    client: HttpClientBuilder,
    endpoint: String,
    zone_cache: ApiCacheManager<i64>,
    record_cache: ApiCacheManager<i64>,
}

struct LinodeZoneFetcher<'a> {
    client: &'a HttpClientBuilder,
    endpoint: &'a str,
    zone: &'a str,
}

struct LinodeRecordFetcher<'a> {
    client: &'a HttpClientBuilder,
    endpoint: &'a str,
    zone_id: i64,
    fqdn: &'a str,
    delegate: &'a str,
    rr_type: &'a Option<DnsRecordType>,
}

#[derive(Deserialize)]
pub(crate) struct LinodeDomainsList {
    data: Vec<LinodeDomainEntry>,
}

#[derive(Deserialize)]
pub(crate) struct LinodeRecordsList {
    data: Vec<LinodeRecordEntry>,
}

#[derive(Deserialize)]
pub(crate) struct LinodeErrorsList {
    #[serde(default)]
    data: Vec<LinodeErrorEntry>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct LinodeDomainEntry {
    id: i64,
    domain: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct LinodeRecordEntry {
    id: i64,
    name: String,
    #[serde(rename = "type")]
    rr_type: DnsRecordType,
    /*target: String,
    priority: u16,
    weight: u16,
    port: u16,
    ttl_sec: u32,*/ // unused
}

#[derive(Deserialize, Debug)]
pub(crate) struct LinodeErrorEntry {
    #[serde(default)]
    reason: String,
}

#[derive(Serialize, Default, Debug)]
pub(crate) struct UpdateLinodeRecord {
    #[serde(rename = "type")]
    pub(crate) rr_type: &'static str,
    pub(crate) name: String,
    pub(crate) target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) port: Option<u16>,
    pub(crate) ttl_sec: u32,
}

/// The default endpoint for the linode API.
const DEFAULT_API_ENDPOINT: &str = "https://api.linode.com/v4";

impl<'a> ApiCacheFetcher<i64> for LinodeZoneFetcher<'a> {
    async fn fetch_api_response(&mut self) -> crate::Result<i64> {
        /*  curl -sS --request GET \
            --url https://api.linode.com/v4/domains \
            --header 'accept: application/json' \
            --header "authorization: Bearer 2710cefeb00e975e51ed404e7060a4b6014eba99d333703a3e7dc930923b8482" \
             | jq

           {
             "data": [
               {
                 "id": 3345977,                                        // <-- zone_id
                 "type": "master",
                 "domain": "ci-cd.stalwart.dns-update.jaygiffin.com",  // <-- zone
                 "tags": [],
                 "group": "",
                 "status": "active",
                 "errors": "",
                 "description": "",
                 "soa_email": "noreply@stalw.art",
                 "retry_sec": 0,
                 "master_ips": [],
                 "axfr_ips": [],
                 "expire_sec": 0,
                 "refresh_sec": 0,
                 "ttl_sec": 0,
                 "created": "2025-09-23T16:34:01",
                 "updated": "2025-09-23T16:34:01"
               }
             ],
             "page": 1,
             "pages": 1,
             "results": 1
           }
        */
        self.client
            .get(format!("{}/domains", self.endpoint))
            .send_with_retry::<LinodeDomainsList>(3)
            .await
            .and_then(|result| {
                result
                    .data
                    .into_iter()
                    .find(|record| record.domain == self.zone)
                    .map(|record| record.id)
                    .ok_or_else(|| Error::Api(format!("No linode domain found for {}", self.zone)))
            })
    }
}

impl Hash for LinodeZoneFetcher<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.zone.hash(state);
    }
}

impl<'a> ApiCacheFetcher<i64> for LinodeRecordFetcher<'a> {
    async fn fetch_api_response(&mut self) -> crate::Result<i64> {
        /*  curl -sS --request GET \
            --url https://api.linode.com/v4/domains/3345977/records \
            --header 'accept: application/json' \
            --header "authorization: Bearer 2710cefeb00e975e51ed404e7060a4b6014eba99d333703a3e7dc930923b8482" \
             | jq

           {
             "data": [
               {
                 "id": 41022342,
                 "type": "A",
                 "name": "www",
                 "target": "1.1.1.1",
                 "priority": 0,
                 "weight": 0,
                 "port": 0,
                 "service": null,
                 "protocol": null,
                 "ttl_sec": 0,
                 "tag": null,
                 "created": "2025-09-23T19:41:38",
                 "updated": "2025-09-23T19:41:38"
               },
               {
                 "id": 41022304,
                 "type": "TXT",
                 "name": "_acme-challenge",
                 "target": "1HQjYS6NlSne1RCeCxfTisFAwr8-9fEbGEQ4jWtzBnQ",
                 "priority": 0,
                 "weight": 0,
                 "port": 0,
                 "service": null,
                 "protocol": null,
                 "ttl_sec": 0,
                 "tag": null,
                 "created": "2025-09-23T19:33:45",
                 "updated": "2025-09-23T19:33:45"
               }
             ],
             "page": 1,
             "pages": 1,
             "results": 2
           }
        */
        self.client
            .get(format!(
                "{endpoint}/domains/{zone_id}/records",
                endpoint = self.endpoint,
                zone_id = self.zone_id,
            ))
            .send_with_retry::<LinodeRecordsList>(3)
            .await
            .and_then(|result| {
                result
                    .data
                    .into_iter()
                    .find(|record| {
                        record.name == self.delegate
                            && self.rr_type.as_ref().is_none_or(|v| *v == record.rr_type)
                    })
                    .map(|record| record.id)
                    .ok_or_else(|| {
                        Error::Api(format!(
                            "No {} found under Linode DNS records for {}",
                            self.delegate, self.fqdn
                        ))
                    })
            })
    }
}

impl Hash for LinodeRecordFetcher<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.zone_id.hash(state);
        self.fqdn.hash(state);
        self.delegate.hash(state);
        self.rr_type.hash(state);
    }
}

impl LinodeProvider {
    pub(crate) fn new(auth_token: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {}", auth_token.as_ref()))
            .with_timeout(timeout);

        Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
            zone_cache: ApiCacheManager::default(),
            record_cache: ApiCacheManager::default(),
        }
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
        fqdn: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        zone: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let fqdn = fqdn.into_name();
        let zone = zone.into_name();
        let payload = UpdateLinodeRecord::from(record);
        let delegate = strip_origin_from_name(&fqdn, &zone);
        let zone_id = self
            .zone_cache
            .get_or_update(&mut LinodeZoneFetcher {
                client: &self.client,
                endpoint: &self.endpoint,
                zone: &zone,
            })
            .await?;

        /*  curl -sS --request POST \
            --url https://api.linode.com/v4/domains/3345977/records \
            --header 'accept: application/json' \
            --header 'authorization: Bearer 2710cefeb00e975e51ed404e7060a4b6014eba99d333703a3e7dc930923b8482' \
            --header 'content-type: application/json' \
            --data '{"type": "A", "name": "www.test", "target": "1.2.3.4"}' \
             | jq

           {
             "id": 41035719,
             "type": "A",
             "name": "www.test",
             "target": "1.2.3.4",
             "priority": 0,
             "weight": 0,
             "port": 0,
             "service": null,
             "protocol": null,
             "ttl_sec": 0,
             "tag": null,
             "created": "2025-09-24T16:56:58",
             "updated": "2025-09-24T16:56:58"
           }
        */

        /*  dig @ns1.linode.com +noall +answer -t A www.test.ci-cd.stalwart.dns-update.jaygiffin.com

           www.test.ci-cd.stalwart.dns-update.jaygiffin.com. 86400	IN A 1.2.3.4
        */

        let inflight = self
            .client
            .post(format!(
                "{endpoint}/domains/{zone_id}/records",
                endpoint = self.endpoint,
            ))
            .with_body(payload.with_delegate_ttl(&delegate, ttl))?
            .send_with_retry::<LinodeErrorsList>(3);
        check_api_err(&inflight.await?)
    }

    pub(crate) async fn update(
        &self,
        fqdn: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        zone: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let fqdn = fqdn.into_name();
        let zone = zone.into_name();
        let payload = UpdateLinodeRecord::from(record);
        let delegate = strip_origin_from_name(&fqdn, &zone);
        let zone_id = self
            .zone_cache
            .get_or_update(&mut LinodeZoneFetcher {
                client: &self.client,
                endpoint: &self.endpoint,
                zone: &zone,
            })
            .await?;
        let record_id = self
            .record_cache
            .get_or_update(&mut LinodeRecordFetcher {
                zone_id,
                client: &self.client,
                endpoint: &self.endpoint,
                delegate: &delegate,
                fqdn: &fqdn,
                rr_type: &None,
            })
            .await?;

        /*  curl -sS --request PUT \
            --url https://api.linode.com/v4/domains/3345977/records/41035719 \
            --header 'accept: application/json' \
            --header 'authorization: Bearer 2710cefeb00e975e51ed404e7060a4b6014eba99d333703a3e7dc930923b8482' \
            --header 'content-type: application/json' \
            --data '{"type": "A", "name": "www.test", "target": "87.65.43.210"}' \
             | jq

           {
               "id": 41035719,
               "type": "A",
               "name": "www.test",
               "target": "87.65.43.210",
               "priority": 0,
               "weight": 0,
               "port": 0,
               "service": null,
               "protocol": null,
               "ttl_sec": 0,
               "tag": null,
               "created": "2025-09-24T16:56:58",
               "updated": "2025-09-24T17:10:20"
           }
        */

        /*  dig @ns2.linode.com +noall +answer -t A www.test.ci-cd.stalwart.dns-update.jaygiffin.com

           www.test.ci-cd.stalwart.dns-update.jaygiffin.com. 86400	IN A 87.65.43.210
        */

        let inflight = self
            .client
            .put(format!(
                "{endpoint}/domains/{zone_id}/records/{record_id}",
                endpoint = self.endpoint,
            ))
            .with_body(payload.with_delegate_ttl(&delegate, ttl))?
            .send_with_retry::<LinodeErrorsList>(3);
        check_api_err(&inflight.await?)
    }

    pub(crate) async fn delete(
        &self,
        fqdn: impl IntoFqdn<'_>,
        zone: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let fqdn = fqdn.into_name();
        let zone = zone.into_name();
        let delegate = strip_origin_from_name(&fqdn, &zone);
        let zone_id = self
            .zone_cache
            .get_or_update(&mut LinodeZoneFetcher {
                client: &self.client,
                endpoint: &self.endpoint,
                zone: &zone,
            })
            .await?;
        let record_id = self
            .record_cache
            .get_or_update(&mut LinodeRecordFetcher {
                zone_id,
                client: &self.client,
                endpoint: &self.endpoint,
                delegate: &delegate,
                fqdn: &fqdn,
                rr_type: &Some(record_type),
            })
            .await?;

        /*  curl -sS --request DELETE \
            --url https://api.linode.com/v4/domains/3345977/records/41035719 \
            --header 'accept: application/json' \
            --header 'authorization: Bearer 2710cefeb00e975e51ed404e7060a4b6014eba99d333703a3e7dc930923b8482' \
             | jq

           {}
        */

        /*  nslookup www.test.ci-cd.stalwart.dns-update.jaygiffin.com ns3.linode.com

           Server:		ns3.linode.com
           Address:	2600:14c0:7::3#53

           ** server can't find www.test.ci-cd.stalwart.dns-update.jaygiffin.com: NXDOMAIN
        */

        /*  Notice: the first time output {} because it was successful; if we try again, we can see an error.

           curl -sS --request DELETE \
            --url https://api.linode.com/v4/domains/3345977/records/41035719 \
            --header 'accept: application/json' \
            --header 'authorization: Bearer 2710cefeb00e975e51ed404e7060a4b6014eba99d333703a3e7dc930923b8482' \
             | jq

           {
             "errors": [
               {
                 "reason": "Domain record not found"
               }
             ]
           }
        */

        let inflight = self
            .client
            .delete(format!(
                "{endpoint}/domains/{zone_id}/records/{record_id}",
                endpoint = self.endpoint,
            ))
            .send_with_retry::<LinodeErrorsList>(3);
        check_api_err(&inflight.await?)
    }
}

fn check_api_err(err_list: &LinodeErrorsList) -> crate::Result<()> {
    match err_list.data.first() {
        Some(err_desc) => Err(crate::Error::Api(err_desc.reason.to_string())),
        _ => Ok(()),
    }
}

impl UpdateLinodeRecord {
    pub(crate) fn with_delegate_ttl(self, delegate: &str, ttl_sec: u32) -> Self {
        Self {
            name: delegate.to_string(),
            ttl_sec,
            ..self
        }
    }
}

/// Converts a DNS record into a representation that can be sent to the desec API.
impl From<DnsRecord> for UpdateLinodeRecord {
    fn from(record: DnsRecord) -> Self {
        Self {
            rr_type: record.get_type(),
            name: "".to_string(),
            target: record.get_content(),
            priority: record.get_priority(),
            weight: record.get_weight(),
            port: record.get_port(),
            ttl_sec: 0,
        }
    }
}
