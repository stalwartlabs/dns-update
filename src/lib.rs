#![doc = include_str!("../README.md")]
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
use providers::ovh::OvhProvider;

#[cfg(feature = "test_provider")]
use providers::{in_memory::InMemoryProvider, pebble::PebbleProvider};

pub use hickory_proto::dnssec;
use providers::{
    bunny::BunnyProvider, cloudflare::CloudflareProvider, constellix::ConstellixProvider,
    ddnss::DdnssProvider, desec::DesecProvider, digitalocean::DigitalOceanProvider,
    dnsimple::DNSimpleProvider, dnsmadeeasy::DnsMadeEasyProvider, duckdns::DuckDnsProvider,
    dynu::DynuProvider, exoscale::ExoscaleProvider, freemyip::FreeMyIpProvider,
    gandiv5::GandiV5Provider, gcore::GcoreProvider, godaddy::GodaddyProvider,
    hetzner::HetznerProvider, hostingde::HostingDeProvider, infomaniak::InfomaniakProvider,
    ionos::IonosProvider, ipv64::Ipv64Provider, linode::LinodeProvider,
    namedotcom::NameDotComProvider, namesilo::NameSiloProvider, netcup::NetcupProvider,
    netlify::NetlifyProvider, nifcloud::NifcloudProvider, porkbun::PorkBunProvider,
    rfc2136::Rfc2136Provider, route53::Route53Provider, scaleway::ScalewayProvider,
    spaceship::SpaceshipProvider, vercel::VercelProvider, vultr::VultrProvider,
    websupport::WebSupportProvider,
};
use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
};

pub mod bind;
pub mod crypto;
pub mod http;
pub mod jwt;
pub mod providers;
pub mod tests;
pub mod update;
pub mod utils;

#[derive(Debug)]
pub enum Error {
    Protocol(String),
    Parse(String),
    Client(String),
    Response(String),
    Api(String),
    Serialize(String),
    Unauthorized,
    NotFound,
    BadRequest,
}

/// A DNS record type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    NS,
    MX,
    TXT,
    SRV,
    TLSA,
    CAA,
}

/// A named DNS record, which consists of a name and a DNS record.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NamedDnsRecord {
    pub name: String,
    pub record: DnsRecord,
}

/// A DNS record type with a value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DnsRecord {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    NS(String),
    MX(MXRecord),
    TXT(String),
    SRV(SRVRecord),
    TLSA(TLSARecord),
    CAA(CAARecord),
}

// An MX record, which consists of an exchange string and a priority.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MXRecord {
    pub exchange: String,
    pub priority: u16,
}

// A SRV record, which consists of a target string, priority, weight, and port.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SRVRecord {
    pub target: String,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
}

// A TLSA record, which consists of a certificate usage, selector, matching type, and certificate data.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLSARecord {
    pub cert_usage: TlsaCertUsage,
    pub selector: TlsaSelector,
    pub matching: TlsaMatching,
    pub cert_data: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum TlsaCertUsage {
    PkixTa,
    PkixEe,
    DaneTa,
    DaneEe,
    Private,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum TlsaSelector {
    Full,
    Spki,
    Private,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum TlsaMatching {
    Raw,
    Sha256,
    Sha512,
    Private,
}

// A CAA record, which can be either an Issue, IssueWild, or Iodef record.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CAARecord {
    Issue {
        issuer_critical: bool,
        name: Option<String>,
        options: Vec<KeyValue>,
    },
    IssueWild {
        issuer_critical: bool,
        name: Option<String>,
        options: Vec<KeyValue>,
    },
    Iodef {
        issuer_critical: bool,
        url: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

/// A TSIG algorithm.
pub enum TsigAlgorithm {
    HmacMd5,
    Gss,
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha256_128,
    HmacSha384,
    HmacSha384_192,
    HmacSha512,
    HmacSha512_256,
}

/// A DNSSEC algorithm.
pub enum Algorithm {
    RSASHA256,
    RSASHA512,
    ECDSAP256SHA256,
    ECDSAP384SHA384,
    ED25519,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
#[non_exhaustive]
pub enum DnsUpdater {
    Rfc2136(Rfc2136Provider),
    Cloudflare(CloudflareProvider),
    DigitalOcean(DigitalOceanProvider),
    Desec(DesecProvider),
    Constellix(ConstellixProvider),
    DnsMadeEasy(DnsMadeEasyProvider),
    Exoscale(ExoscaleProvider),
    Nifcloud(NifcloudProvider),
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    Ovh(OvhProvider),
    Bunny(BunnyProvider),
    Linode(LinodeProvider),
    Porkbun(PorkBunProvider),
    Spaceship(SpaceshipProvider),
    WebSupport(WebSupportProvider),
    DNSimple(DNSimpleProvider),
    GandiV5(GandiV5Provider),
    Godaddy(GodaddyProvider),
    Hetzner(HetznerProvider),
    NameDotCom(NameDotComProvider),
    NameSilo(NameSiloProvider),
    DuckDns(DuckDnsProvider),
    FreeMyIp(FreeMyIpProvider),
    Ipv64(Ipv64Provider),
    Ddnss(DdnssProvider),
    Dynu(DynuProvider),
    GoogleCloudDns(providers::google_cloud_dns::GoogleCloudDnsProvider),
    Ionos(IonosProvider),
    HostingDe(HostingDeProvider),
    Infomaniak(InfomaniakProvider),
    Netcup(NetcupProvider),
    Netlify(NetlifyProvider),
    #[cfg(feature = "test_provider")]
    Pebble(PebbleProvider),
    #[cfg(feature = "test_provider")]
    InMemory(InMemoryProvider),
    Route53(Route53Provider),
    Scaleway(ScalewayProvider),
    Gcore(GcoreProvider),
    Vercel(VercelProvider),
    Vultr(VultrProvider),
}

pub trait IntoFqdn<'x> {
    fn into_fqdn(self) -> Cow<'x, str>;
    fn into_name(self) -> Cow<'x, str>;
}
