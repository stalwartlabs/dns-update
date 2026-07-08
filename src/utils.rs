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

const MAX_CHUNK_BYTES: usize = 255;

pub(crate) fn txt_chunks_to_text(output: &mut String, text: &str, separator: &str) {
    output.push('"');
    let mut current_bytes: usize = 0;
    for ch in text.chars() {
        let ch_len = ch.len_utf8();
        if current_bytes > 0 && current_bytes + ch_len > MAX_CHUNK_BYTES {
            output.push('"');
            output.push_str(separator);
            output.push('"');
            current_bytes = 0;
        }
        match ch {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            _ => output.push(ch),
        }
        current_bytes += ch_len;
    }
    output.push('"');
}

pub(crate) fn txt_chunks(content: String) -> Vec<String> {
    if content.len() <= MAX_CHUNK_BYTES {
        return vec![content];
    }

    let mut chunks = Vec::new();
    let mut chunk = String::new();

    for ch in content.chars() {
        let ch_len = ch.len_utf8();
        if !chunk.is_empty() && chunk.len() + ch_len > MAX_CHUNK_BYTES {
            chunks.push(std::mem::take(&mut chunk));
        }
        chunk.push(ch);
    }

    if !chunk.is_empty() {
        chunks.push(chunk);
    }

    chunks
}

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

impl Display for DnsRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            DnsRecord::A(addr) => Display::fmt(addr, f),
            DnsRecord::AAAA(addr) => Display::fmt(addr, f),
            DnsRecord::CNAME(name) => f.write_str(name),
            DnsRecord::NS(name) => f.write_str(name),
            DnsRecord::MX(record) => Display::fmt(record, f),
            DnsRecord::TXT(text) => f.write_str(text),
            DnsRecord::SRV(record) => Display::fmt(record, f),
            DnsRecord::TLSA(record) => Display::fmt(record, f),
            DnsRecord::CAA(record) => Display::fmt(record, f),
        }
    }
}

impl DnsRecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DnsRecordType::A => "A",
            DnsRecordType::AAAA => "AAAA",
            DnsRecordType::CNAME => "CNAME",
            DnsRecordType::NS => "NS",
            DnsRecordType::MX => "MX",
            DnsRecordType::TXT => "TXT",
            DnsRecordType::SRV => "SRV",
            DnsRecordType::TLSA => "TLSA",
            DnsRecordType::CAA => "CAA",
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

pub(crate) fn strip_trailing_dot(value: &str) -> &str {
    value.strip_suffix('.').unwrap_or(value)
}

pub(crate) fn parse_srv(value: &str) -> crate::Result<DnsRecord> {
    let mut parts = value.split_whitespace();
    let priority = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV priority in '{value}': {e}")))?;
    let weight = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV weight in '{value}': {e}")))?;
    let port = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid SRV port in '{value}': {e}")))?;
    let target = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid SRV value '{value}'")))?;
    Ok(DnsRecord::SRV(SRVRecord {
        priority,
        weight,
        port,
        target: strip_trailing_dot(target).to_string(),
    }))
}

pub(crate) fn parse_mx(value: &str) -> crate::Result<DnsRecord> {
    let mut parts = value.splitn(2, char::is_whitespace);
    let priority = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid MX value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid MX priority in '{value}': {e}")))?;
    let exchange = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid MX value '{value}'")))?
        .trim();
    Ok(DnsRecord::MX(MXRecord {
        priority,
        exchange: strip_trailing_dot(exchange).to_string(),
    }))
}

pub(crate) fn parse_tlsa(value: &str) -> crate::Result<DnsRecord> {
    let mut parts = value.split_whitespace();
    let usage: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA usage in '{value}': {e}")))?;
    let selector: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA selector in '{value}': {e}")))?;
    let matching: u8 = parts
        .next()
        .ok_or_else(|| Error::Parse(format!("invalid TLSA value '{value}'")))?
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA matching in '{value}': {e}")))?;
    let hex: String = parts.collect();
    if hex.is_empty() {
        return Err(Error::Parse(format!("invalid TLSA value '{value}'")));
    }
    Ok(DnsRecord::TLSA(TLSARecord {
        cert_usage: tlsa_cert_usage_from_u8(usage)?,
        selector: tlsa_selector_from_u8(selector)?,
        matching: tlsa_matching_from_u8(matching)?,
        cert_data: decode_hex(&hex)?,
    }))
}

pub(crate) fn unquote_txt(content: &str) -> String {
    if !content.contains('"') {
        return content.to_string();
    }
    let mut out = String::with_capacity(content.len());
    let mut in_quotes = false;
    let mut escaped = false;
    for ch in content.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
        } else if in_quotes && ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            in_quotes = !in_quotes;
        } else if in_quotes {
            out.push(ch);
        }
    }
    out
}

pub(crate) fn build_caa(flags: u8, tag: &str, value: &str) -> crate::Result<CAARecord> {
    let issuer_critical = flags & 0x80 != 0;
    match tag {
        "issue" => {
            let (name, options) = split_caa_value(value);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = split_caa_value(value);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: value.to_string(),
        }),
        other => Err(Error::Parse(format!("unknown CAA tag: {other}"))),
    }
}

pub(crate) fn split_caa_value(value: &str) -> (Option<String>, Vec<KeyValue>) {
    let mut parts = value.split(';').map(str::trim);
    let name = match parts.next().unwrap_or("") {
        "" => None,
        head => Some(head.to_string()),
    };
    let options = parts
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => KeyValue {
                key: k.trim().to_string(),
                value: v.trim().to_string(),
            },
            None => KeyValue {
                key: p.trim().to_string(),
                value: String::new(),
            },
        })
        .collect();
    (name, options)
}

pub(crate) fn tlsa_cert_usage_from_u8(value: u8) -> crate::Result<TlsaCertUsage> {
    Ok(match value {
        0 => TlsaCertUsage::PkixTa,
        1 => TlsaCertUsage::PkixEe,
        2 => TlsaCertUsage::DaneTa,
        3 => TlsaCertUsage::DaneEe,
        255 => TlsaCertUsage::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA cert usage: {value}"))),
    })
}

pub(crate) fn tlsa_selector_from_u8(value: u8) -> crate::Result<TlsaSelector> {
    Ok(match value {
        0 => TlsaSelector::Full,
        1 => TlsaSelector::Spki,
        255 => TlsaSelector::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA selector: {value}"))),
    })
}

pub(crate) fn tlsa_matching_from_u8(value: u8) -> crate::Result<TlsaMatching> {
    Ok(match value {
        0 => TlsaMatching::Raw,
        1 => TlsaMatching::Sha256,
        2 => TlsaMatching::Sha512,
        255 => TlsaMatching::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA matching: {value}"))),
    })
}

pub(crate) fn decode_hex(hex: &str) -> crate::Result<Vec<u8>> {
    hex::decode(hex).map_err(|e| Error::Parse(format!("invalid hex string: {e}")))
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
            Error::Unsupported(e) => write!(f, "Unsupported: {}", e),
        }
    }
}

impl Display for DnsRecordType {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
