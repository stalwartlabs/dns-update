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

pub use hickory_client::proto::dnssec;
use providers::{
    bunny::BunnyProvider, cloudflare::CloudflareProvider, desec::DesecProvider,
    digitalocean::DigitalOceanProvider, dnsimple::DNSimpleProvider, porkbun::PorkBunProvider,
    rfc2136::Rfc2136Provider,
};
use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
};

pub mod bind;
pub mod crypto;
pub mod http;
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
#[derive(Clone, Copy, Debug)]
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
#[derive(Clone, Debug)]
pub struct NamedDnsRecord {
    pub name: String,
    pub record: DnsRecord,
}

/// A DNS record type with a value.
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]

pub struct MXRecord {
    pub exchange: String,
    pub priority: u16,
}

// A SRV record, which consists of a target string, priority, weight, and port.
#[derive(Clone, Debug)]
pub struct SRVRecord {
    pub target: String,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
}

// A TLSA record, which consists of a certificate usage, selector, matching type, and certificate data.
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    Ovh(OvhProvider),
    Bunny(BunnyProvider),
    Porkbun(PorkBunProvider),
    DNSimple(DNSimpleProvider),
}

pub trait IntoFqdn<'x> {
    fn into_fqdn(self) -> Cow<'x, str>;
    fn into_name(self) -> Cow<'x, str>;
}
