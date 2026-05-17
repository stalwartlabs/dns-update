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
use crate::providers::oraclecloud::{OracleCloudConfig, OracleCloudProvider};
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
use crate::providers::ovh::{OvhEndpoint, OvhProvider};

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
use crate::providers::transip::TransipProvider;

#[cfg(feature = "test_provider")]
use crate::providers::{in_memory::InMemoryProvider, pebble::PebbleProvider};

#[cfg(feature = "test_provider")]
use crate::NamedDnsRecord;

#[cfg(feature = "test_provider")]
use std::sync::{Arc, Mutex};

use crate::{
    DnsRecord, DnsRecordType, DnsUpdater, IntoFqdn, TsigAlgorithm,
    providers::{
        alidns::AlidnsProvider,
        baiducloud::BaiduCloudProvider,
        bindman::BindmanProvider,
        bluecatv2::{BluecatV2Config, BluecatV2Provider},
        azuredns::{AzureDnsConfig, AzureDnsProvider},
        bunny::BunnyProvider,
        cloudflare::CloudflareProvider,
        cloudns::ClouDnsProvider,
        constellix::ConstellixProvider,
        ddnss::DdnssProvider,
        desec::DesecProvider,
        digitalocean::DigitalOceanProvider,
        dnsimple::DNSimpleProvider,
        dnsmadeeasy::DnsMadeEasyProvider,
        dreamhost::DreamhostProvider,
        duckdns::DuckDnsProvider,
        dynu::DynuProvider,
        easydns::EasyDnsProvider,
        exoscale::ExoscaleProvider,
        freemyip::FreeMyIpProvider,
        gandiv5::GandiV5Provider,
        gcore::GcoreProvider,
        glesys::GlesysProvider,
        godaddy::GodaddyProvider,
        hetzner::HetznerProvider,
        hostingde::HostingDeProvider,
        huaweicloud::HuaweiCloudProvider,
        infomaniak::InfomaniakProvider,
        ionos::IonosProvider,
        ipv64::Ipv64Provider,
        joker::JokerProvider,
        linode::LinodeProvider,
        luadns::LuaDnsProvider,
        mailinabox::MailinaboxProvider,
        mythicbeasts::MythicBeastsProvider,
        namecheap::NamecheapProvider,
        namedotcom::NameDotComProvider,
        namesilo::NameSiloProvider,
        netcup::NetcupProvider,
        netlify::NetlifyProvider,
        nifcloud::NifcloudProvider,
        ns1::Ns1Provider,
        pdns::PdnsProvider,
        ibmcloud::IbmCloudProvider,
        porkbun::PorkBunProvider,
        rfc2136::{DnsAddress, Rfc2136Provider},
        route53::Route53Provider,
        scaleway::ScalewayProvider,
        spaceship::SpaceshipProvider,
        technitium::TechnitiumProvider,
        tencentcloud::TencentCloudProvider,
        vercel::VercelProvider,
        vultr::VultrProvider,
        websupport::WebSupportProvider,
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

    /// Create a new DNS updater using the Constellix API.
    pub fn new_constellix(
        api_key: impl AsRef<str>,
        secret_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Constellix(ConstellixProvider::new(
            api_key, secret_key, timeout,
        )?))
    }

    /// Create a new DNS updater using the DNSMadeEasy API.
    pub fn new_dnsmadeeasy(
        api_key: impl AsRef<str>,
        api_secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::DnsMadeEasy(DnsMadeEasyProvider::new(
            api_key, api_secret, timeout,
        )?))
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

    /// Create a new DNS updater using the Oracle Cloud Infrastructure DNS API.
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    pub fn new_oraclecloud(config: OracleCloudConfig) -> crate::Result<Self> {
        Ok(DnsUpdater::OracleCloud(OracleCloudProvider::new(config)?))
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

    /// Create a new DNS updater using the Exoscale DNS API.
    pub fn new_exoscale(
        api_key: impl AsRef<str>,
        api_secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Exoscale(ExoscaleProvider::new(
            api_key, api_secret, timeout,
        )?))
    }

    /// Create a new DNS updater using the Nifcloud DNS API.
    pub fn new_nifcloud(
        access_key: impl AsRef<str>,
        secret_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Nifcloud(NifcloudProvider::new(
            access_key, secret_key, timeout,
        )?))
    }

    /// Create a new DNS updater using the WebSupport API.
    pub fn new_websupport(
        api_key: impl AsRef<str>,
        secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::WebSupport(WebSupportProvider::new(
            api_key, secret, timeout,
        )?))
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

    /// Create a new DNS updater using the IONOS DNS API.
    pub fn new_ionos(
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Ionos(IonosProvider::new(api_key, timeout)))
    }

    /// Create a new DNS updater using the hosting.de API.
    pub fn new_hostingde(
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::HostingDe(HostingDeProvider::new(
            api_key, timeout,
        )))
    }

    /// Create a new DNS updater using the Infomaniak API.
    pub fn new_infomaniak(
        access_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Infomaniak(InfomaniakProvider::new(
            access_token,
            timeout,
        )))
    }

    /// Create a new DNS updater using the NS1 API.
    pub fn new_ns1(
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Ns1(Ns1Provider::new(api_key, timeout)))
    }

    /// Create a new DNS updater using the LuaDNS API.
    pub fn new_luadns(
        api_username: impl AsRef<str>,
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::LuaDns(LuaDnsProvider::new(
            api_username,
            api_token,
            timeout,
        )))
    }

    /// Create a new DNS updater using the Netcup CCP API.
    pub fn new_netcup(
        customer_number: impl AsRef<str>,
        api_key: impl AsRef<str>,
        api_password: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Netcup(NetcupProvider::new(
            customer_number,
            api_key,
            api_password,
            timeout,
        )))
    }

    /// Create a new DNS updater using the PowerDNS HTTP API.
    pub fn new_pdns(
        api_key: impl AsRef<str>,
        endpoint: Option<impl AsRef<str>>,
        server_name: Option<impl AsRef<str>>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Pdns(PdnsProvider::new(
            api_key,
            endpoint,
            server_name,
            timeout,
        )))
    }

    /// Create a new DNS updater using the Netlify API.
    pub fn new_netlify(
        access_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Netlify(NetlifyProvider::new(
            access_token,
            timeout,
        )))
    }

    /// Create a new DNS updater using the Technitium DNS Server API.
    pub fn new_technitium(
        base_url: impl AsRef<str>,
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Technitium(TechnitiumProvider::new(
            base_url, api_token, timeout,
        )?))
    }

    /// Create a new DNS updater using the Bindman webhook API.
    pub fn new_bindman(
        manager_url: impl AsRef<str>,
        basic_auth: Option<(impl AsRef<str>, impl AsRef<str>)>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Bindman(BindmanProvider::new(
            manager_url,
            basic_auth,
            timeout,
        )?))
    }

    /// Create a new DNS updater using the Alibaba Cloud DNS API.
    pub fn new_alidns(
        access_key: impl AsRef<str>,
        secret_key: impl AsRef<str>,
        region: Option<impl AsRef<str>>,
        security_token: Option<impl AsRef<str>>,
        line: Option<impl AsRef<str>>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Alidns(AlidnsProvider::new(
            access_key,
            secret_key,
            region,
            security_token,
            line,
            timeout,
        )?))
    }

    /// Create a new DNS updater using the Huawei Cloud DNS API.
    pub fn new_huaweicloud(
        access_key: impl AsRef<str>,
        secret_key: impl AsRef<str>,
        region: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::HuaweiCloud(HuaweiCloudProvider::new(
            access_key.as_ref(),
            secret_key.as_ref(),
            region.as_ref(),
            timeout,
        )?))
    }

    /// Create a new DNS updater using the ClouDNS API.
    pub fn new_cloudns(
        auth_id: Option<impl AsRef<str>>,
        sub_auth_id: Option<impl AsRef<str>>,
        auth_password: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::ClouDns(ClouDnsProvider::new(
            auth_id,
            sub_auth_id,
            auth_password,
            timeout,
        )?))
    }

    /// Create a new DNS updater using the Tencent Cloud DNSPod API.
    pub fn new_tencentcloud(
        secret_id: impl AsRef<str>,
        secret_key: impl AsRef<str>,
        region: Option<impl AsRef<str>>,
        session_token: Option<impl AsRef<str>>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::TencentCloud(TencentCloudProvider::new(
            secret_id,
            secret_key,
            region,
            session_token,
            timeout,
        )?))
    }

    /// Create a new DNS updater using the Baidu Cloud DNS API.
    pub fn new_baiducloud(
        access_key: impl AsRef<str>,
        secret_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::BaiduCloud(BaiduCloudProvider::new(
            access_key.as_ref(),
            secret_key.as_ref(),
            timeout,
        )?))
    }

    /// Create a new DNS updater using the EasyDNS REST API.
    pub fn new_easydns(
        token: impl AsRef<str>,
        key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::EasyDns(EasyDnsProvider::new(
            token, key, timeout,
        )?))
    }

    /// Create a new DNS updater using the Joker DMAPI with an API key.
    pub fn new_joker_api_key(
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Joker(JokerProvider::new_api_key(
            api_key, timeout,
        )?))
    }

    /// Create a new DNS updater using the Joker DMAPI with username and password.
    pub fn new_joker_password(
        username: impl AsRef<str>,
        password: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Joker(JokerProvider::new_password(
            username, password, timeout,
        )?))
    }

    /// Create a new DNS updater using the Mythic Beasts DNSv2 API.
    pub fn new_mythicbeasts(
        username: impl AsRef<str>,
        password: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::MythicBeasts(MythicBeastsProvider::new(
            username, password, timeout,
        )?))
    }

    /// Create a new DNS updater using the Namecheap XML API.
    pub fn new_namecheap(
        api_user: impl AsRef<str>,
        api_key: impl AsRef<str>,
        client_ip: impl AsRef<str>,
        username: Option<impl AsRef<str>>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Namecheap(NamecheapProvider::new(
            api_user, api_key, client_ip, username, timeout,
        )?))
    }

    /// Create a new DNS updater using the TransIP v6 API.
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    pub fn new_transip(
        login: impl AsRef<str>,
        private_key_pem: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Transip(TransipProvider::new(
            login,
            private_key_pem,
            timeout,
        )?))
    }

    /// Create a new DNS updater using the Mail-in-a-Box DNS API.
    pub fn new_mailinabox(
        base_url: impl AsRef<str>,
        email: impl AsRef<str>,
        password: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Mailinabox(MailinaboxProvider::new(
            base_url, email, password, timeout,
        )?))
    }

    /// Create a new DNS updater using the Bluecat Address Manager v2 REST API.
    pub fn new_bluecatv2(config: BluecatV2Config) -> crate::Result<Self> {
        Ok(DnsUpdater::BluecatV2(BluecatV2Provider::new(config)?))
    }

    /// Create a new DNS updater using the GleSYS API.
    pub fn new_glesys(
        api_user: impl AsRef<str>,
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Glesys(GlesysProvider::new(
            api_user, api_key, timeout,
        )))
    }

    /// Create a new DNS updater using the Dreamhost API.
    pub fn new_dreamhost(
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Dreamhost(DreamhostProvider::new(
            api_key, timeout,
        )))
    }

    /// Create a new DNS updater using the Volcano Engine API.
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    pub fn new_volcengine(
        config: crate::providers::volcengine::VolcengineConfig,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Volcengine(
            crate::providers::volcengine::VolcengineProvider::new(config)?,
        ))
    }

    /// Create a new DNS updater using the Yandex Cloud DNS API.
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    pub fn new_yandexcloud(
        config: crate::providers::yandexcloud::YandexCloudConfig,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::YandexCloud(
            crate::providers::yandexcloud::YandexCloudProvider::new(config)?,
        ))
    }

    /// Create a new DNS updater using the Azure DNS REST API with OAuth2 client credentials.
    pub fn new_azuredns(config: AzureDnsConfig) -> crate::Result<Self> {
        Ok(DnsUpdater::AzureDns(AzureDnsProvider::new(config)?))
    }

    /// Create a new DNS updater using the IBM Cloud (SoftLayer classic) DNS API.
    pub fn new_ibmcloud(
        username: impl AsRef<str>,
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::IbmCloud(IbmCloudProvider::new(
            username, api_key, timeout,
        )?))
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
            DnsUpdater::Alidns(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::AzureDns(provider) => provider.create(name, record, ttl, origin).await,
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
            DnsUpdater::Constellix(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::DnsMadeEasy(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Exoscale(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Nifcloud(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::IbmCloud(provider) => provider.create(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => provider.create(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::OracleCloud(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Porkbun(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Rfc2136(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Route53(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Scaleway(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Spaceship(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Vercel(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Vultr(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::WebSupport(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::TencentCloud(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::GoogleCloudDns(provider) => {
                provider.create(name, record, ttl, origin).await
            }
            DnsUpdater::Ionos(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::HostingDe(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Infomaniak(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Netcup(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Netlify(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::EasyDns(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Joker(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::MythicBeasts(provider) => {
                provider.create(name, record, ttl, origin).await
            }
            DnsUpdater::Namecheap(provider) => provider.create(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Transip(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::HuaweiCloud(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::BaiduCloud(provider) => provider.create(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Volcengine(provider) => provider.create(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::YandexCloud(provider) => provider.create(name, record, ttl, origin).await,
            #[cfg(feature = "test_provider")]
            DnsUpdater::Pebble(provider) => provider.create(name, record, ttl, origin).await,
            #[cfg(feature = "test_provider")]
            DnsUpdater::InMemory(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Pdns(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Technitium(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Bindman(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Mailinabox(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::BluecatV2(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Ns1(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::LuaDns(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::ClouDns(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Glesys(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Dreamhost(provider) => provider.create(name, record, ttl, origin).await,
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
            DnsUpdater::Alidns(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::AzureDns(provider) => provider.update(name, record, ttl, origin).await,
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
            DnsUpdater::Constellix(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::DnsMadeEasy(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Exoscale(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Nifcloud(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::IbmCloud(provider) => provider.update(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => provider.update(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::OracleCloud(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Porkbun(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Rfc2136(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Route53(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Scaleway(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Spaceship(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Vercel(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Vultr(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::WebSupport(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::TencentCloud(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::GoogleCloudDns(provider) => {
                provider.update(name, record, ttl, origin).await
            }
            DnsUpdater::Ionos(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::HostingDe(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Infomaniak(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Netcup(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Netlify(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::EasyDns(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Joker(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::MythicBeasts(provider) => {
                provider.update(name, record, ttl, origin).await
            }
            DnsUpdater::Namecheap(provider) => provider.update(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Transip(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::HuaweiCloud(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::BaiduCloud(provider) => provider.update(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Volcengine(provider) => provider.update(name, record, ttl, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::YandexCloud(provider) => provider.update(name, record, ttl, origin).await,
            #[cfg(feature = "test_provider")]
            DnsUpdater::Pebble(provider) => provider.update(name, record, ttl, origin).await,
            #[cfg(feature = "test_provider")]
            DnsUpdater::InMemory(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Pdns(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Technitium(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Bindman(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Mailinabox(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::BluecatV2(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Ns1(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::LuaDns(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::ClouDns(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Glesys(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Dreamhost(provider) => provider.update(name, record, ttl, origin).await,
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
            DnsUpdater::Alidns(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::AzureDns(provider) => provider.delete(name, origin, record).await,
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
            DnsUpdater::Constellix(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::DnsMadeEasy(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Exoscale(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Nifcloud(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::IbmCloud(provider) => provider.delete(name, origin, record).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => provider.delete(name, origin, record).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::OracleCloud(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Porkbun(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Rfc2136(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Route53(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Scaleway(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Spaceship(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Vercel(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Vultr(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::WebSupport(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::TencentCloud(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::GoogleCloudDns(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Ionos(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::HostingDe(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Infomaniak(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Netcup(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Netlify(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::EasyDns(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Joker(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::MythicBeasts(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Namecheap(provider) => provider.delete(name, origin, record).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Transip(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::HuaweiCloud(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::BaiduCloud(provider) => provider.delete(name, origin, record).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Volcengine(provider) => provider.delete(name, origin, record).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::YandexCloud(provider) => provider.delete(name, origin, record).await,
            #[cfg(feature = "test_provider")]
            DnsUpdater::Pebble(provider) => provider.delete(name, origin, record).await,
            #[cfg(feature = "test_provider")]
            DnsUpdater::InMemory(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Pdns(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Technitium(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Bindman(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Mailinabox(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::BluecatV2(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Ns1(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::LuaDns(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::ClouDns(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Glesys(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Dreamhost(provider) => provider.delete(name, origin, record).await,
        }
    }
}
