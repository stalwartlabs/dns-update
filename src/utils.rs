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

use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, KeyValue, MXRecord, SRVRecord,
    TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector, TsigAlgorithm,
};
use std::{
    borrow::Cow,
    fmt::{self, Display, Formatter},
    str::FromStr,
};

/// Strip `name` from `origin`, return `return_if_equal` if `name` is the same
/// as `origin`, or  `@` if `None` given.
pub(crate) fn strip_origin_from_name(
    name: &str,
    origin: &str,
    return_if_equal: Option<&str>,
) -> String {
    let name = name.trim_end_matches('.');
    let origin = origin.trim_end_matches('.');

    if name == origin {
        return return_if_equal.unwrap_or("@").to_string();
    }

    if name.ends_with(&format!(".{}", origin)) {
        name[..name.len() - origin.len() - 1].to_string()
    } else {
        name.to_string()
    }
}

impl fmt::Display for TLSARecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{} {} {} ",
            u8::from(self.cert_usage),
            u8::from(self.selector),
            u8::from(self.matching),
        )?;

        for ch in &self.cert_data {
            write!(f, "{:02x}", ch)?;
        }

        Ok(())
    }
}

impl fmt::Display for KeyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&self.key)?;
        if !self.value.is_empty() {
            write!(f, "={}", self.value)?;
        }

        Ok(())
    }
}

impl CAARecord {
    pub fn decompose(self) -> (u8, String, String) {
        match self {
            CAARecord::Issue {
                issuer_critical,
                name,
                options,
            } => {
                let flags = if issuer_critical { 128 } else { 0 };
                let mut value = name.unwrap_or_default();
                for opt in &options {
                    use std::fmt::Write;
                    write!(value, "; {}", opt).unwrap();
                }
                (flags, "issue".to_string(), value)
            }
            CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            } => {
                let flags = if issuer_critical { 128 } else { 0 };
                let mut value = name.unwrap_or_default();
                for opt in &options {
                    use std::fmt::Write;
                    write!(value, "; {}", opt).unwrap();
                }
                (flags, "issuewild".to_string(), value)
            }
            CAARecord::Iodef {
                issuer_critical,
                url,
            } => {
                let flags = if issuer_critical { 128 } else { 0 };
                (flags, "iodef".to_string(), url)
            }
        }
    }
}

impl fmt::Display for CAARecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            CAARecord::Issue {
                issuer_critical,
                name,
                options,
            } => {
                if *issuer_critical {
                    f.write_str("128 ")?;
                } else {
                    f.write_str("0 ")?;
                }
                f.write_str("issue ")?;
                f.write_str("\"")?;
                if let Some(name) = name {
                    f.write_str(name)?;
                }
                for opt in options {
                    write!(f, ";{}", opt)?;
                }
                f.write_str("\"")?;
            }
            CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            } => {
                if *issuer_critical {
                    f.write_str("128 ")?;
                } else {
                    f.write_str("0 ")?;
                }
                f.write_str("issuewild ")?;
                f.write_str("\"")?;
                if let Some(name) = name {
                    f.write_str(name)?;
                }
                for opt in options {
                    write!(f, ";{}", opt)?;
                }
                f.write_str("\"")?;
            }
            CAARecord::Iodef {
                issuer_critical,
                url,
            } => {
                if *issuer_critical {
                    f.write_str("128 ")?;
                } else {
                    f.write_str("0 ")?;
                }
                f.write_str("iodef ")?;
                f.write_str("\"")?;
                f.write_str(url)?;
                f.write_str("\"")?;
            }
        }
        Ok(())
    }
}

impl Display for MXRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.priority, self.exchange)
    }
}

impl Display for SRVRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.priority, self.weight, self.port, self.target
        )
    }
}

impl DnsRecord {
    pub fn as_type(&self) -> DnsRecordType {
        match self {
            DnsRecord::A { .. } => DnsRecordType::A,
            DnsRecord::AAAA { .. } => DnsRecordType::AAAA,
            DnsRecord::CNAME { .. } => DnsRecordType::CNAME,
            DnsRecord::NS { .. } => DnsRecordType::NS,
            DnsRecord::MX { .. } => DnsRecordType::MX,
            DnsRecord::TXT { .. } => DnsRecordType::TXT,
            DnsRecord::SRV { .. } => DnsRecordType::SRV,
            DnsRecord::TLSA { .. } => DnsRecordType::TLSA,
            DnsRecord::CAA { .. } => DnsRecordType::CAA,
        }
    }
}

impl From<TlsaCertUsage> for u8 {
    fn from(usage: TlsaCertUsage) -> Self {
        match usage {
            TlsaCertUsage::PkixTa => 0,
            TlsaCertUsage::PkixEe => 1,
            TlsaCertUsage::DaneTa => 2,
            TlsaCertUsage::DaneEe => 3,
            TlsaCertUsage::Private => 255,
        }
    }
}

impl From<TlsaSelector> for u8 {
    fn from(selector: TlsaSelector) -> Self {
        match selector {
            TlsaSelector::Full => 0,
            TlsaSelector::Spki => 1,
            TlsaSelector::Private => 255,
        }
    }
}

impl From<TlsaMatching> for u8 {
    fn from(matching: TlsaMatching) -> Self {
        match matching {
            TlsaMatching::Raw => 0,
            TlsaMatching::Sha256 => 1,
            TlsaMatching::Sha512 => 2,
            TlsaMatching::Private => 255,
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

impl std::error::Error for Error {}

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

impl Display for DnsRecordType {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
