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
        arvancloud::ArvanCloudProvider,
        autodns::AutodnsProvider,
        azuredns::{AzureDnsConfig, AzureDnsProvider},
        baiducloud::BaiduCloudProvider,
        bluecatv2::{BluecatV2Config, BluecatV2Provider},
        bunny::BunnyProvider,
        cloudflare::CloudflareProvider,
        cloudns::ClouDnsProvider,
        constellix::ConstellixProvider,
        cpanel::CpanelProvider,
        ddnss::DdnssProvider,
        desec::DesecProvider,
        digitalocean::DigitalOceanProvider,
        dnsimple::DNSimpleProvider,
        dnsmadeeasy::DnsMadeEasyProvider,
        domeneshop::DomeneshopProvider,
        dreamhost::DreamhostProvider,
        duckdns::DuckDnsProvider,
        dynu::DynuProvider,
        easydns::EasyDnsProvider,
        edgedns::{EdgeDnsConfig, EdgeDnsProvider},
        exoscale::ExoscaleProvider,
        freemyip::FreeMyIpProvider,
        gandiv5::GandiV5Provider,
        gcore::GcoreProvider,
        glesys::GlesysProvider,
        godaddy::GodaddyProvider,
        hetzner::HetznerProvider,
        hostingde::HostingDeProvider,
        hostinger::HostingerProvider,
        huaweicloud::HuaweiCloudProvider,
        hurricane::HurricaneProvider,
        ibmcloud::IbmCloudProvider,
        infoblox::{InfobloxConfig, InfobloxProvider},
        infomaniak::InfomaniakProvider,
        inwx::InwxProvider,
        ionos::IonosProvider,
        ipv64::Ipv64Provider,
        joker::{JokerAuth, JokerProvider},
        lightsail::{LightsailConfig, LightsailProvider},
        linode::LinodeProvider,
        luadns::LuaDnsProvider,
        mythicbeasts::MythicBeastsProvider,
        namecheap::NamecheapProvider,
        namedotcom::NameDotComProvider,
        namesilo::NameSiloProvider,
        netcup::NetcupProvider,
        netlify::NetlifyProvider,
        nifcloud::NifcloudProvider,
        ns1::Ns1Provider,
        pdns::PdnsProvider,
        plesk::PleskProvider,
        porkbun::PorkBunProvider,
        rfc2136::{DnsAddress, Rfc2136Provider},
        route53::Route53Provider,
        safedns::SafeDnsProvider,
        scaleway::ScalewayProvider,
        simplycom::SimplyComProvider,
        spaceship::SpaceshipProvider,
        tencentcloud::TencentCloudProvider,
        ultradns::UltraDnsProvider,
        vercel::VercelProvider,
        vultr::VultrProvider,
        websupport::WebSupportProvider,
    },
};
use std::collections::HashMap;
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
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Cloudflare(CloudflareProvider::new(
            secret, timeout,
        )?))
    }

    /// Create a new DNS updater using the DigitalOcean API.
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
    pub fn new_duckdns(token: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        Ok(DnsUpdater::DuckDns(DuckDnsProvider::new(token, timeout)?))
    }

    /// Create a new DNS updater using the freemyip.com API.
    pub fn new_freemyip(token: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        Ok(DnsUpdater::FreeMyIp(FreeMyIpProvider::new(token, timeout)?))
    }

    /// Create a new DNS updater using the IPv64 API.
    pub fn new_ipv64(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        Ok(DnsUpdater::Ipv64(Ipv64Provider::new(api_key, timeout)?))
    }

    /// Create a new DNS updater using the DDNSS.de API.
    pub fn new_ddnss(key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        Ok(DnsUpdater::Ddnss(DdnssProvider::new(key, timeout)?))
    }

    /// Create a new DNS updater using the Dynu API.
    pub fn new_dynu(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
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
        Ok(DnsUpdater::Scaleway(ScalewayProvider::new(
            api_token, timeout,
        )))
    }

    /// Create a new DNS updater using the Gcore DNS API.
    pub fn new_gcore(api_token: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
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
    pub fn new_ionos(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
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

    /// Create a new DNS updater using the Domeneshop API.
    pub fn new_domeneshop(
        api_token: impl AsRef<str>,
        api_secret: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Domeneshop(DomeneshopProvider::new(
            api_token, api_secret, timeout,
        )))
    }

    /// Create a new DNS updater using the Simply.com API.
    pub fn new_simplycom(
        account_name: impl AsRef<str>,
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::SimplyCom(SimplyComProvider::new(
            account_name,
            api_key,
            timeout,
        )))
    }

    /// Create a new DNS updater using the ANS SafeDNS API.
    pub fn new_safedns(
        auth_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Safedns(SafeDnsProvider::new(
            auth_token, timeout,
        )))
    }

    /// Create a new DNS updater using the ArvanCloud API.
    pub fn new_arvancloud(
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::ArvanCloud(ArvanCloudProvider::new(
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
    pub fn new_ns1(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
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

    /// Create a new DNS updater using the INWX JSON-RPC API.
    pub fn new_inwx(
        username: impl Into<String>,
        password: impl Into<String>,
        sandbox: bool,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Inwx(InwxProvider::new(
            username, password, sandbox, timeout,
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

    /// Create a new DNS updater using the Joker DMAPI.
    pub fn new_joker(auth: JokerAuth, timeout: Option<Duration>) -> crate::Result<Self> {
        Ok(DnsUpdater::Joker(JokerProvider::new(auth, timeout)?))
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
        global_key: bool,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Transip(TransipProvider::new(
            login,
            private_key_pem,
            global_key,
            timeout,
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

    /// Create a new DNS updater using the Hurricane Electric free DNS service.
    pub fn new_hurricane(
        credentials: HashMap<String, String>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Hurricane(HurricaneProvider::new(
            credentials,
            timeout,
        )?))
    }

    /// Create a new DNS updater using the Hostinger DNS API.
    pub fn new_hostinger(
        api_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Hostinger(HostingerProvider::new(
            api_token, timeout,
        )?))
    }

    /// Create a new DNS updater using the InterNetX AutoDNS API.
    pub fn new_autodns(
        username: impl AsRef<str>,
        password: impl AsRef<str>,
        context: Option<u32>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Autodns(AutodnsProvider::new(
            username, password, context, timeout,
        )?))
    }

    /// Create a new DNS updater using the Plesk REST API (`X-API-Key` auth).
    pub fn new_plesk(
        base_url: impl AsRef<str>,
        api_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Plesk(PleskProvider::new(
            base_url, api_key, timeout,
        )))
    }

    /// Create a new DNS updater using the PowerDNS Authoritative HTTP API.
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

    /// Create a new DNS updater using the cPanel UAPI (API token auth).
    pub fn new_cpanel(
        base_url: impl AsRef<str>,
        username: impl AsRef<str>,
        token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Cpanel(CpanelProvider::new(
            base_url, username, token, timeout,
        )))
    }

    /// Create a new DNS updater using the AWS Lightsail DNS API.
    pub fn new_lightsail(config: LightsailConfig) -> crate::Result<Self> {
        Ok(DnsUpdater::Lightsail(LightsailProvider::new(config)?))
    }

    /// Create a new DNS updater using the Akamai EdgeDNS API.
    pub fn new_edgedns(config: EdgeDnsConfig) -> crate::Result<Self> {
        Ok(DnsUpdater::EdgeDns(EdgeDnsProvider::new(config)?))
    }

    /// Create a new DNS updater using the UltraDNS REST API.
    pub fn new_ultradns(
        username: impl Into<String>,
        password: impl Into<String>,
        endpoint: Option<String>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::UltraDns(UltraDnsProvider::new(
            username, password, endpoint, timeout,
        )?))
    }

    /// Create a new DNS updater using the Infoblox NIOS WAPI.
    pub fn new_infoblox(config: InfobloxConfig) -> crate::Result<Self> {
        Ok(DnsUpdater::Infoblox(InfobloxProvider::new(config)?))
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

    /// Atomically replace the RRSet at (name, type). An empty `records` Vec deletes the RRSet.
    pub async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        match self {
            DnsUpdater::Rfc2136(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Cloudflare(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::DigitalOcean(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Desec(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Constellix(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::DnsMadeEasy(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::OracleCloud(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Bunny(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Linode(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Porkbun(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Exoscale(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Nifcloud(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::WebSupport(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Spaceship(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::DNSimple(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::GandiV5(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Godaddy(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Hetzner(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::NameDotCom(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::NameSilo(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::DuckDns(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::FreeMyIp(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Ipv64(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Ddnss(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Dynu(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::GoogleCloudDns(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Route53(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Vultr(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Scaleway(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Gcore(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Vercel(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Ionos(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::HostingDe(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Domeneshop(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::SimplyCom(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Safedns(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::ArvanCloud(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Infomaniak(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Ns1(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::LuaDns(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Netcup(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Netlify(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Inwx(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Alidns(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::HuaweiCloud(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::ClouDns(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::TencentCloud(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::BaiduCloud(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::EasyDns(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Joker(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::MythicBeasts(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Namecheap(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Transip(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::BluecatV2(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Glesys(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Dreamhost(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Volcengine(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::YandexCloud(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::AzureDns(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::IbmCloud(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Hurricane(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Hostinger(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Autodns(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Plesk(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Pdns(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Cpanel(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Lightsail(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::EdgeDns(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::UltraDns(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Infoblox(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            #[cfg(feature = "test_provider")]
            DnsUpdater::Pebble(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            #[cfg(feature = "test_provider")]
            DnsUpdater::InMemory(provider) => {
                provider
                    .set_rrset(name, record_type, ttl, records, origin)
                    .await
            }
        }
    }

    /// Add records to the RRSet at (name, type). Idempotent: values already present are skipped.
    pub async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        match self {
            DnsUpdater::Rfc2136(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Cloudflare(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::DigitalOcean(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Desec(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Constellix(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::DnsMadeEasy(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::OracleCloud(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Bunny(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Linode(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Porkbun(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Exoscale(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Nifcloud(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::WebSupport(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Spaceship(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::DNSimple(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::GandiV5(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Godaddy(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Hetzner(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::NameDotCom(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::NameSilo(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::DuckDns(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::FreeMyIp(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Ipv64(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Ddnss(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Dynu(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::GoogleCloudDns(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Route53(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Vultr(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Scaleway(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Gcore(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Vercel(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Ionos(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::HostingDe(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Domeneshop(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::SimplyCom(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Safedns(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::ArvanCloud(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Infomaniak(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Ns1(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::LuaDns(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Netcup(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Netlify(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Inwx(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Alidns(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::HuaweiCloud(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::ClouDns(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::TencentCloud(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::BaiduCloud(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::EasyDns(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Joker(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::MythicBeasts(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Namecheap(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Transip(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::BluecatV2(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Glesys(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Dreamhost(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Volcengine(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::YandexCloud(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::AzureDns(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::IbmCloud(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Hurricane(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Hostinger(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Autodns(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Plesk(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Pdns(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Cpanel(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Lightsail(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::EdgeDns(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::UltraDns(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            DnsUpdater::Infoblox(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            #[cfg(feature = "test_provider")]
            DnsUpdater::Pebble(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
            #[cfg(feature = "test_provider")]
            DnsUpdater::InMemory(provider) => {
                provider
                    .add_to_rrset(name, record_type, ttl, records, origin)
                    .await
            }
        }
    }

    /// Remove the listed records from the RRSet at (name, type). Idempotent: values not present are skipped.
    pub async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        match self {
            DnsUpdater::Rfc2136(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Cloudflare(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::DigitalOcean(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Desec(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Constellix(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::DnsMadeEasy(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::OracleCloud(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Bunny(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Linode(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Porkbun(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Exoscale(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Nifcloud(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::WebSupport(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Spaceship(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::DNSimple(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::GandiV5(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Godaddy(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Hetzner(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::NameDotCom(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::NameSilo(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::DuckDns(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::FreeMyIp(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Ipv64(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Ddnss(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Dynu(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::GoogleCloudDns(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Route53(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Vultr(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Scaleway(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Gcore(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Vercel(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Ionos(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::HostingDe(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Domeneshop(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::SimplyCom(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Safedns(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::ArvanCloud(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Infomaniak(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Ns1(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::LuaDns(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Netcup(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Netlify(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Inwx(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Alidns(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::HuaweiCloud(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::ClouDns(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::TencentCloud(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::BaiduCloud(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::EasyDns(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Joker(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::MythicBeasts(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Namecheap(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Transip(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::BluecatV2(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Glesys(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Dreamhost(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Volcengine(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::YandexCloud(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::AzureDns(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::IbmCloud(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Hurricane(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Hostinger(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Autodns(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Plesk(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Pdns(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Cpanel(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Lightsail(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::EdgeDns(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::UltraDns(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            DnsUpdater::Infoblox(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            #[cfg(feature = "test_provider")]
            DnsUpdater::Pebble(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
            #[cfg(feature = "test_provider")]
            DnsUpdater::InMemory(provider) => {
                provider
                    .remove_from_rrset(name, record_type, records, origin)
                    .await
            }
        }
    }

    /// List the records of the RRSet at (name, type). Returns an empty Vec when the RRSet does not exist.
    pub async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        match self {
            DnsUpdater::Rfc2136(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Cloudflare(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::DigitalOcean(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::Desec(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Constellix(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::DnsMadeEasy(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Ovh(provider) => provider.list_rrset(name, record_type, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::OracleCloud(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::Bunny(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Linode(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Porkbun(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Exoscale(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Nifcloud(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::WebSupport(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::Spaceship(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::DNSimple(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::GandiV5(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Godaddy(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Hetzner(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::NameDotCom(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::NameSilo(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::DuckDns(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::FreeMyIp(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Ipv64(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Ddnss(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Dynu(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::GoogleCloudDns(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::Route53(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Vultr(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Scaleway(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Gcore(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Vercel(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Ionos(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::HostingDe(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Domeneshop(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::SimplyCom(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Safedns(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::ArvanCloud(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::Infomaniak(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::Ns1(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::LuaDns(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Netcup(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Netlify(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Inwx(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Alidns(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::HuaweiCloud(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::ClouDns(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::TencentCloud(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::BaiduCloud(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::EasyDns(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Joker(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::MythicBeasts(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::Namecheap(provider) => provider.list_rrset(name, record_type, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Transip(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::BluecatV2(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Glesys(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Dreamhost(provider) => provider.list_rrset(name, record_type, origin).await,
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::Volcengine(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            DnsUpdater::YandexCloud(provider) => {
                provider.list_rrset(name, record_type, origin).await
            }
            DnsUpdater::AzureDns(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::IbmCloud(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Hurricane(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Hostinger(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Autodns(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Plesk(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Pdns(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Cpanel(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Lightsail(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::EdgeDns(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::UltraDns(provider) => provider.list_rrset(name, record_type, origin).await,
            DnsUpdater::Infoblox(provider) => provider.list_rrset(name, record_type, origin).await,
            #[cfg(feature = "test_provider")]
            DnsUpdater::Pebble(provider) => provider.list_rrset(name, record_type, origin).await,
            #[cfg(feature = "test_provider")]
            DnsUpdater::InMemory(provider) => provider.list_rrset(name, record_type, origin).await,
        }
    }
}
