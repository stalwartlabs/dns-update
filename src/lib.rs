#![doc = include_str!("../README.md")]
use core::fmt;
/*
 * Copyright Stalwart Labs Ltd. See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */
use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
    time::Duration,
};

use hickory_client::proto::rr::dnssec::{KeyPair, Private};
use providers::{
    cloudflare::CloudflareProvider,
    rfc2136::{DnsAddress, Rfc2136Provider},
};

pub mod http;
pub mod providers;

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
}

/// A DNS record type.
pub enum DnsRecord {
    A {
        content: Ipv4Addr,
    },
    AAAA {
        content: Ipv6Addr,
    },
    CNAME {
        content: String,
    },
    NS {
        content: String,
    },
    MX {
        content: String,
        priority: u16,
    },
    TXT {
        content: String,
    },
    SRV {
        content: String,
        priority: u16,
        weight: u16,
        port: u16,
    },
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
pub enum DnsUpdater {
    Rfc2136(Rfc2136Provider),
    Cloudflare(CloudflareProvider),
}

pub trait IntoFqdn<'x> {
    fn into_fqdn(self) -> Cow<'x, str>;
    fn into_name(self) -> Cow<'x, str>;
}

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
    pub fn new_rfc2136_sig0(
        addr: impl TryInto<DnsAddress>,
        signer_name: impl AsRef<str>,
        key: KeyPair<Private>,
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
        }
    }

    /// Delete an existing DNS record.
    pub async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        match self {
            DnsUpdater::Rfc2136(provider) => provider.delete(name, origin).await,
            DnsUpdater::Cloudflare(provider) => provider.delete(name, origin).await,
        }
    }
}

impl<'x> IntoFqdn<'x> for &'x str {
    fn into_fqdn(self) -> Cow<'x, str> {
        if self.ends_with('.') {
            Cow::Borrowed(self)
        } else {
            Cow::Owned(format!("{}.", self))
        }
    }

    fn into_name(self) -> Cow<'x, str> {
        if let Some(name) = self.strip_suffix('.') {
            Cow::Borrowed(name)
        } else {
            Cow::Borrowed(self)
        }
    }
}

impl<'x> IntoFqdn<'x> for &'x String {
    fn into_fqdn(self) -> Cow<'x, str> {
        self.as_str().into_fqdn()
    }

    fn into_name(self) -> Cow<'x, str> {
        self.as_str().into_name()
    }
}

impl<'x> IntoFqdn<'x> for String {
    fn into_fqdn(self) -> Cow<'x, str> {
        if self.ends_with('.') {
            Cow::Owned(self)
        } else {
            Cow::Owned(format!("{}.", self))
        }
    }

    fn into_name(self) -> Cow<'x, str> {
        if let Some(name) = self.strip_suffix('.') {
            Cow::Owned(name.to_string())
        } else {
            Cow::Owned(self)
        }
    }
}

impl FromStr for TsigAlgorithm {
    type Err = ();

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        match s {
            "hmac-md5" => Ok(TsigAlgorithm::HmacMd5),
            "gss" => Ok(TsigAlgorithm::Gss),
            "hmac-sha1" => Ok(TsigAlgorithm::HmacSha1),
            "hmac-sha224" => Ok(TsigAlgorithm::HmacSha224),
            "hmac-sha256" => Ok(TsigAlgorithm::HmacSha256),
            "hmac-sha256-128" => Ok(TsigAlgorithm::HmacSha256_128),
            "hmac-sha384" => Ok(TsigAlgorithm::HmacSha384),
            "hmac-sha384-192" => Ok(TsigAlgorithm::HmacSha384_192),
            "hmac-sha512" => Ok(TsigAlgorithm::HmacSha512),
            "hmac-sha512-256" => Ok(TsigAlgorithm::HmacSha512_256),
            _ => Err(()),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Protocol(e) => write!(f, "Protocol error: {}", e),
            Error::Parse(e) => write!(f, "Parse error: {}", e),
            Error::Client(e) => write!(f, "Client error: {}", e),
            Error::Response(e) => write!(f, "Response error: {}", e),
            Error::Api(e) => write!(f, "API error: {}", e),
            Error::Serialize(e) => write!(f, "Serialize error: {}", e),
            Error::Unauthorized => write!(f, "Unauthorized"),
            Error::NotFound => write!(f, "Not found"),
        }
    }
}
