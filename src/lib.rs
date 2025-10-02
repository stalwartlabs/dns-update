#![doc = include_str!("../README.md")]
use core::fmt;
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
use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
    future::Future,
    hash::{DefaultHasher, Hash, Hasher},
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use hickory_client::proto::rr::dnssec::{KeyPair, Private};

use providers::{
    cloudflare::CloudflareProvider,
    desec::DesecProvider,
    digitalocean::DigitalOceanProvider,
    linode::LinodeProvider,
    ovh::{OvhEndpoint, OvhProvider},
    rfc2136::{DnsAddress, Rfc2136Provider},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod http;
pub mod providers;
pub mod tests;

#[derive(Debug, PartialEq)]
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
#[derive(Debug, Default, Clone, Hash, Eq, PartialEq)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    NS,
    MX,
    TXT,
    SRV,
    #[default]
    ANY,
}

/// A DNS record type with a value.
/// FIXME: the u16 are incorrect; they should be NonZero<u16>. Idk what to do as this would be a breaking change
#[derive(Clone)]
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

pub trait DnsRecordTrait {
    fn get_type(&self) -> &'static str;
    fn get_content(&self) -> String;
    fn get_priority(&self) -> Option<u16>;
    fn get_weight(&self) -> Option<u16>;
    fn get_port(&self) -> Option<u16>;
    fn fmt_ovh_desec(&self) -> (String, &str) {
        let mut content: String = "".to_string();
        if let Some(v) = self.get_priority() {
            content = v.to_string() + " ";
        }
        if let Some(v) = self.get_weight() {
            content += &(v.to_string() + " ");
        }
        if let Some(v) = self.get_port() {
            content += &(v.to_string() + " ");
        }
        content += &self.get_content();
        (content, self.get_type())
    }
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
    Ovh(OvhProvider),
    Linode(LinodeProvider),
}

pub trait IntoFqdn<'x> {
    fn into_fqdn(self) -> Cow<'x, str>;
    fn into_name(self) -> Cow<'x, str>;
}

#[derive(Clone, Default)]
struct CacheKV<T: Clone + Sized + Default + Send>(u64, T);

#[derive(Clone, Default)]
pub(crate) struct ApiCacheManager<T: Clone + Sized + Default + Send> {
    rmx: Arc<Mutex<CacheKV<T>>>,
}

pub(crate) trait ApiCacheFetcher<T>: Hash
where
    T: Clone + Sized + Default + Send,
{
    fn fetch_api_response(&mut self) -> impl Future<Output = crate::Result<T>> + Send + Sync;
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

    /// Create a new DNS updater using the Linode API.
    pub fn new_linode(
        auth_token: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        Ok(DnsUpdater::Linode(LinodeProvider::new(auth_token, timeout)))
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
            DnsUpdater::Ovh(provider) => provider.create(name, record, ttl, origin).await,
            DnsUpdater::Linode(provider) => provider.create(name, record, ttl, origin).await,
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
            DnsUpdater::Ovh(provider) => provider.update(name, record, ttl, origin).await,
            DnsUpdater::Linode(provider) => provider.update(name, record, ttl, origin).await,
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
            DnsUpdater::Ovh(provider) => provider.delete(name, origin, record).await,
            DnsUpdater::Linode(provider) => provider.delete(name, origin, record).await,
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

pub fn strip_origin_from_name(name: &str, origin: &str) -> String {
    let name = name.trim_end_matches('.');
    let origin = origin.trim_end_matches('.');

    if name == origin {
        return "@".to_string();
    }

    if name.ends_with(&format!(".{}", origin)) {
        name[..name.len() - origin.len() - 1].to_string()
    } else {
        name.to_string()
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
            Error::BadRequest => write!(f, "Bad request"),
        }
    }
}

impl TryFrom<&str> for DnsRecordType {
    type Error = ();

    fn try_from(i: &str) -> std::result::Result<Self, Self::Error> {
        match i.to_uppercase().as_str() {
            "ANY" => Ok(DnsRecordType::ANY),
            "A" => Ok(DnsRecordType::A),
            "AAAA" => Ok(DnsRecordType::AAAA),
            "CNAME" => Ok(DnsRecordType::CNAME),
            "NS" => Ok(DnsRecordType::NS),
            "MX" => Ok(DnsRecordType::MX),
            "TXT" => Ok(DnsRecordType::TXT),
            "SRV" => Ok(DnsRecordType::SRV),
            _ => Err(()),
        }
    }
}

impl TryFrom<String> for DnsRecordType {
    type Error = ();

    fn try_from(i: String) -> std::result::Result<Self, Self::Error> {
        DnsRecordType::try_from(i.as_str())
    }
}

impl FromStr for DnsRecordType {
    type Err = ();

    fn from_str(i: &str) -> std::result::Result<Self, Self::Err> {
        DnsRecordType::try_from(i)
    }
}

impl From<DnsRecordType> for &'static str {
    fn from(v: DnsRecordType) -> &'static str {
        match v {
            DnsRecordType::A => "A",
            DnsRecordType::AAAA => "AAAA",
            DnsRecordType::CNAME => "CNAME",
            DnsRecordType::NS => "NS",
            DnsRecordType::MX => "MX",
            DnsRecordType::TXT => "TXT",
            DnsRecordType::SRV => "SRV",
            DnsRecordType::ANY => "ANY",
        }
    }
}

impl From<DnsRecordType> for String {
    fn from(v: DnsRecordType) -> String {
        let s: &'static str = v.into();
        s.to_string()
    }
}

impl From<DnsRecord> for DnsRecordType {
    fn from(v: DnsRecord) -> DnsRecordType {
        match v {
            DnsRecord::A { .. } => DnsRecordType::A,
            DnsRecord::AAAA { .. } => DnsRecordType::AAAA,
            DnsRecord::CNAME { .. } => DnsRecordType::CNAME,
            DnsRecord::NS { .. } => DnsRecordType::NS,
            DnsRecord::MX { .. } => DnsRecordType::MX,
            DnsRecord::TXT { .. } => DnsRecordType::TXT,
            DnsRecord::SRV { .. } => DnsRecordType::SRV,
        }
    }
}

impl<'de> Deserialize<'de> for DnsRecordType {
    fn deserialize<D>(de: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: String = String::deserialize(de)?;
        let e = format!("Invalid DnsRecordType {}", v);
        DnsRecordType::try_from(v).map_err(|_d| serde::de::Error::custom(Error::Parse(e)))
    }
}

impl Serialize for DnsRecordType {
    fn serialize<S>(&self, se: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s: &'static str = self.clone().into();
        se.serialize_str(s)
    }
}

impl std::error::Error for Error {}

impl Display for DnsRecordType {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl DnsRecordTrait for DnsRecord {
    fn get_type(&self) -> &'static str {
        DnsRecordType::from(self.clone()).into()
    }
    fn get_content(&self) -> String {
        match self {
            DnsRecord::A { content } => content.to_string(),
            DnsRecord::AAAA { content } => content.to_string(),
            DnsRecord::CNAME { content } => content.to_string(),
            DnsRecord::NS { content } => content.to_string(),
            DnsRecord::MX { content, .. } => content.to_string(),
            DnsRecord::TXT { content } => content.to_string(),
            DnsRecord::SRV { content, .. } => content.to_string(),
        }
    }
    fn get_priority(&self) -> Option<u16> {
        if let DnsRecord::MX { priority, .. } = self {
            Some(*priority)
        } else if let DnsRecord::SRV { priority, .. } = self {
            Some(*priority)
        } else {
            None
        }
    }
    fn get_weight(&self) -> Option<u16> {
        if let DnsRecord::SRV { weight, .. } = self {
            Some(*weight)
        } else {
            None
        }
    }
    fn get_port(&self) -> Option<u16> {
        if let DnsRecord::SRV { port, .. } = self {
            Some(*port)
        } else {
            None
        }
    }
}

impl<T: Clone + Sized + Default + Send> ApiCacheManager<T> {
    pub async fn get_or_update<F>(&self, fet: &mut F) -> crate::Result<T>
    where
        F: ApiCacheFetcher<T> + Send + Sync,
    {
        let (mut dfh, mut kv) = (DefaultHasher::default(), CacheKV::<T>::default());
        fet.hash(&mut dfh);
        if let Ok(mut guard) = self.rmx.try_lock() {
            std::mem::swap(&mut kv, &mut *guard);
        }
        let (hash, mut value) = (dfh.finish().max(1u64), kv.1);
        if kv.0 != hash {
            value = fet.fetch_api_response().await?
        };
        if let Ok(mut guard) = self.rmx.try_lock() {
            kv = CacheKV::<T>(hash, value.clone());
            std::mem::swap(&mut kv, &mut *guard);
        }
        Ok(value)
    }
}
