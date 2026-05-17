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
        ddnss::DdnssProvider,
        desec::DesecProvider,
        digitalocean::DigitalOceanProvider,
        dnsimple::DNSimpleProvider,
        gandiv5::GandiV5Provider,
        gcore::GcoreProvider,
        godaddy::GodaddyProvider,
        hetzner::HetznerProvider,
        linode::LinodeProvider,
        namedotcom::NameDotComProvider,
        namesilo::NameSiloProvider,
        duckdns::DuckDnsProvider,
        dynu::DynuProvider,
        freemyip::FreeMyIpProvider,
        ipv64::Ipv64Provider,
        porkbun::PorkBunProvider,
        rfc2136::{DnsAddress, Rfc2136Provider},
        route53::Route53Provider,
        scaleway::ScalewayProvider,
        spaceship::SpaceshipProvider,
        vercel::VercelProvider,
        vultr::VultrProvider,
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

    /// Create a new DNS updater using the Bunny API.
    pub fn new_bunny(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        Ok(DnsUpdater::Bunny(BunnyProvider::new(api_key, timeout)?))
    }

    /// Create a new DNS updater using the Linode API.
    pub fn new_linode(
        auth_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Linode(LinodeProvider::new(auth_token, timeout)))
    }

    /// Create a new DNS updater using the Porkbun API.
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

    /// Create a new DNS updater using the Gandi LiveDNS API (v5).
    pub fn new_gandiv5(
        personal_access_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::GandiV5(GandiV5Provider::new(
            personal_access_token,
            timeout,
        )?))
    }

    /// Create a new DNS updater using the GoDaddy API.
    pub fn new_godaddy(
        api_key: impl AsRef<str>,
        api_secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Godaddy(GodaddyProvider::new(
            api_key, api_secret, timeout,
        )?))
    }

    /// Create a new DNS updater using the Hetzner Cloud DNS (v1) API.
    pub fn new_hetzner(
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Hetzner(HetznerProvider::new(
            api_token, timeout,
        )?))
    }

    /// Create a new DNS updater using the Name.com v4 API.
    pub fn new_namedotcom(
        username: impl AsRef<str>,
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::NameDotCom(NameDotComProvider::new(
            username, api_token, timeout,
        )?))
    }

    /// Create a new DNS updater using the NameSilo API.
    pub fn new_namesilo(
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::NameSilo(NameSiloProvider::new(
            api_key, timeout,
        )?))
    }

    /// Create a new DNS updater using the DuckDNS API.
    pub fn new_duckdns(
        token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::DuckDns(DuckDnsProvider::new(token, timeout)?))
    }

    /// Create a new DNS updater using the freemyip.com API.
    pub fn new_freemyip(
        token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::FreeMyIp(FreeMyIpProvider::new(token, timeout)?))
    }

    /// Create a new DNS updater using the IPv64 API.
    pub fn new_ipv64(
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Ipv64(Ipv64Provider::new(api_key, timeout)?))
    }

    /// Create a new DNS updater using the DDNSS.de API.
    pub fn new_ddnss(
        key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Ddnss(DdnssProvider::new(key, timeout)?))
    }

    /// Create a new DNS updater using the Dynu API.
    pub fn new_dynu(
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Dynu(DynuProvider::new(api_key, timeout)?))
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

    /// Create a new DNS updater using the Vultr API.
    pub fn new_vultr(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        Ok(DnsUpdater::Vultr(VultrProvider::new(api_key, timeout)))
    }

    /// Create a new DNS updater using the Scaleway Domains API.
    pub fn new_scaleway(
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Scaleway(ScalewayProvider::new(api_token, timeout)))
    }

    /// Create a new DNS updater using the Gcore DNS API.
    pub fn new_gcore(
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Gcore(GcoreProvider::new(api_token, timeout)))
    }

    /// Create a new DNS updater using the Vercel API.
    pub fn new_vercel(
        auth_token: impl AsRef<str>,
        team_id: Option<impl AsRef<str>>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Vercel(VercelProvider::new(
            auth_token, team_id, timeout,
        )))
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
            DnsUpdater::Ddnss(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Desec(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::DigitalOcean(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::DNSimple(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::GandiV5(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Gcore(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Godaddy(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Hetzner(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Linode(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::NameDotCom(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::NameSilo(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::DuckDns(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Dynu(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::FreeMyIp(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Ipv64(provider) => provider.create(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Porkbun(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Rfc2136(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Route53(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Scaleway(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Spaceship(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Vercel(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Vultr(provider) => provider.create(name, record, ttl, origin).await,
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
            DnsUpdater::Ddnss(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Desec(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::DigitalOcean(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::DNSimple(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::GandiV5(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Gcore(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Godaddy(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Hetzner(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Linode(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::NameDotCom(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::NameSilo(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::DuckDns(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Dynu(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::FreeMyIp(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Ipv64(provider) => provider.update(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Porkbun(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Rfc2136(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Route53(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Scaleway(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Spaceship(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Vercel(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Vultr(provider) => provider.update(name, record, ttl, origin).await,
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
            DnsUpdater::Cloudflare(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Ddnss(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Desec(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::DigitalOcean(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::DNSimple(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::GandiV5(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Gcore(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Godaddy(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Hetzner(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Linode(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::NameDotCom(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::NameSilo(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::DuckDns(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Dynu(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::FreeMyIp(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Ipv64(provider) => provider.delete(name, origin, record).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Porkbun(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Rfc2136(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Route53(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Scaleway(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Spaceship(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Vercel(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Vultr(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::GoogleCloudDns(provider) => provider.delete(name, origin, record).await,
            #[cfg(feature = "test_provider")]
            DnsUpdater::Pebble(provider) => provider.delete(name, origin, record).await,
            #[cfg(feature = "test_provider")]
            DnsUpdater::InMemory(provider) => provider.delete(name, origin, record).await,
        }
    }
}
