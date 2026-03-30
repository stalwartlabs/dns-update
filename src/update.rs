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

    /// Create a new DNS record.
    pub async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        match self {
            DnsUpdater::Rfc2136(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Cloudflare(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::DigitalOcean(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Desec(provider) => provider.create(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Bunny(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Porkbun(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::DNSimple(provider) => provider.create(name, record, ttl, origin).await,
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
            DnsUpdater::Rfc2136(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Cloudflare(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::DigitalOcean(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Desec(provider) => provider.update(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Bunny(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Porkbun(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::DNSimple(provider) => provider.update(name, record, ttl, origin).await,
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
            DnsUpdater::Rfc2136(provider) => provider.delete(name, origin).await,
            DnsUpdater::Cloudflare(provider) => provider.delete(name, origin).await,
            DnsUpdater::DigitalOcean(provider) => provider.delete(name, origin).await,
            DnsUpdater::Desec(provider) => provider.delete(name, origin, record).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Bunny(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Porkbun(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::DNSimple(provider) => provider.delete(name, origin, record).await,
        }
    }
}
