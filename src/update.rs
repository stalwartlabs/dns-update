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

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
use crate::Algorithm;

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
use hickory_client::proto::dnssec::SigningKey;

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
use crate::providers::ovh::{OvhEndpoint, OvhProvider};

#[cfg(feature = "test_provider")]
use crate::providers::{in_memory::InMemoryProvider, pebble::PebbleProvider};

#[cfg(feature = "test_provider")]
use crate::NamedDnsRecord;

#[cfg(feature = "test_provider")]
use std::sync::{Arc, Mutex};

use crate::{
    DnsRecord, DnsRecordType, DnsUpdater, IntoFqdn, TsigAlgorithm,
    providers::{
        bunny::BunnyProvider,
        cloudflare::CloudflareProvider,
        desec::DesecProvider,
        digitalocean::DigitalOceanProvider,
        dnsimple::DNSimpleProvider,
        porkbun::PorkBunProvider,
        rfc2136::{DnsAddress, Rfc2136Provider},
        route53::Route53Provider,
        spaceship::SpaceshipProvider,
    },
};
use std::time::Duration;

impl DnsUpdater {
    /// Create a new DNS updater using the RFC 2136 protocol and TSIG authentication.
    pub fn new_rfc2136_tsig(
        addr: impl TryInto<DnsAddress>,
        key_name: impl AsRef<str>,
        key: impl Into<Vec<u8>>,
        algorithm: TsigAlgorithm,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Rfc2136(Rfc2136Provider::new_tsig(
            addr,
            key_name,
            key,
            algorithm.into(),
        )?))
    }

    /// Create a new DNS updater using the RFC 2136 protocol and SIG(0) authentication.
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    pub fn new_rfc2136_sig0(
        addr: impl TryInto<DnsAddress>,
        signer_name: impl AsRef<str>,
        key: Box<dyn SigningKey>,
        public_key: impl Into<Vec<u8>>,
        algorithm: Algorithm,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Rfc2136(Rfc2136Provider::new_sig0(
            addr,
            signer_name,
            key,
            public_key,
            algorithm.into(),
        )?))
    }

    /// Create a new DNS updater using the Cloudflare API.
    pub fn new_cloudflare(
        secret: impl AsRef<str>,
        email: Option<impl AsRef<str>>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Cloudflare(CloudflareProvider::new(
            secret, email, timeout,
        )?))
    }

    /// Create a new DNS updater using the Cloudflare API.
    pub fn new_digitalocean(
        auth_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::DigitalOcean(DigitalOceanProvider::new(
            auth_token, timeout,
        )))
    }

    /// Create a new DNS updater using the Desec.io API.
    pub fn new_desec(
        auth_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Desec(DesecProvider::new(auth_token, timeout)))
    }

    /// Create a new DNS updater using the OVH API.
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    pub fn new_ovh(
        application_key: impl AsRef<str>,
        application_secret: impl AsRef<str>,
        consumer_key: impl AsRef<str>,
        endpoint: OvhEndpoint,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Ovh(OvhProvider::new(
            application_key,
            application_secret,
            consumer_key,
            endpoint,
            timeout,
        )?))
    }

    pub fn new_bunny(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        Ok(DnsUpdater::Bunny(BunnyProvider::new(api_key, timeout)?))
    }

    pub fn new_porkbun(
        api_key: impl AsRef<str>,
        secret_api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Porkbun(PorkBunProvider::new(
            api_key,
            secret_api_key,
            timeout,
        )))
    }

    /// Create a new DNS updater using the Spaceship API.
    pub fn new_spaceship(
        api_key: impl AsRef<str>,
        api_secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Spaceship(SpaceshipProvider::new(
            api_key, api_secret, timeout,
        )))
    }

    /// Create a new DNS updater using the DNSimple API.
    pub fn new_dnsimple(
        auth_token: impl AsRef<str>,
        account_id: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::DNSimple(DNSimpleProvider::new(
            auth_token, account_id, timeout,
        )))
    }

    /// Create a new DNS updater using the Google Cloud DNS API.
    pub fn new_google_cloud_dns(
        config: crate::providers::google_cloud_dns::GoogleCloudDnsConfig,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::GoogleCloudDns(
            crate::providers::google_cloud_dns::GoogleCloudDnsProvider::new(config)?,
        ))
    }

    /// Create a new DNS updater using the Route53 API.
    pub fn new_route53(config: crate::providers::route53::Route53Config) -> crate::Result<Self> {
        Ok(DnsUpdater::Route53(Route53Provider::new(config)))
    }

    /// Create a new DNS updater using the Pebble Challenge Test Server.
    #[cfg(feature = "test_provider")]
    pub fn new_pebble(base_url: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        DnsUpdater::Pebble(PebbleProvider::new(base_url, timeout))
    }

    /// Create a new DNS updater backed by an in-memory record store.
    #[cfg(feature = "test_provider")]
    pub fn new_in_memory(records: Arc<Mutex<Vec<NamedDnsRecord>>>) -> Self {
        DnsUpdater::InMemory(InMemoryProvider::new(records))
    }

    /// Create a new DNS record.
    pub async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        match self {
            DnsUpdater::Bunny(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Cloudflare(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Desec(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::DigitalOcean(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::DNSimple(provider) => provider.create(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Porkbun(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Rfc2136(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Route53(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Spaceship(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::GoogleCloudDns(provider) => {
                provider.create(name, record, ttl, origin).await
            }
            #[cfg(feature = "test_provider")]
            DnsUpdater::Pebble(provider) => provider.create(name, record, ttl, origin).await,
            #[cfg(feature = "test_provider")]
            DnsUpdater::InMemory(provider) => provider.create(name, record, ttl, origin).await,
        }
    }

    /// Update an existing DNS record.
    pub async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        match self {
            DnsUpdater::Bunny(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Cloudflare(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Desec(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::DigitalOcean(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::DNSimple(provider) => provider.update(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Porkbun(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Rfc2136(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Route53(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Spaceship(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::GoogleCloudDns(provider) => {
                provider.update(name, record, ttl, origin).await
            }
            #[cfg(feature = "test_provider")]
            DnsUpdater::Pebble(provider) => provider.update(name, record, ttl, origin).await,
            #[cfg(feature = "test_provider")]
            DnsUpdater::InMemory(provider) => provider.update(name, record, ttl, origin).await,
        }
    }

    /// Delete an existing DNS record.
    pub async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record: DnsRecordType,
    ) -> crate::Result<()> {
        match self {
            DnsUpdater::Bunny(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Cloudflare(provider) => provider.delete(name, origin).await,
            DnsUpdater::Desec(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::DigitalOcean(provider) => provider.delete(name, origin).await,
            DnsUpdater::DNSimple(provider) => provider.delete(name, origin, record).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Porkbun(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Rfc2136(provider) => provider.delete(name, origin).await,
            DnsUpdater::Route53(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Spaceship(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::GoogleCloudDns(provider) => provider.delete(name, origin, record).await,
            #[cfg(feature = "test_provider")]
            DnsUpdater::Pebble(provider) => provider.delete(name, origin, record).await,
            #[cfg(feature = "test_provider")]
            DnsUpdater::InMemory(provider) => provider.delete(name, origin, record).await,
        }
    }
}
