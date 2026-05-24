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

use crate::utils::txt_chunks;
use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, KeyValue as DnsKeyValue, MXRecord,
    SRVRecord, TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector,
};
use hickory_net::NetError;
use hickory_net::client::{Client, ClientHandle};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_net::xfer::DnsMultiplexer;
use hickory_proto::ProtoError;
use hickory_proto::dnssec::DnsSecError;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::caa::KeyValue;
use hickory_proto::rr::rdata::tlsa::{CertUsage, Matching, Selector};
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::rdata::{A, AAAA, CAA, CNAME, MX, NS, SRV, TLSA, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType, TSigner};
use std::net::{AddrParseError, SocketAddr};

#[derive(Clone)]
pub struct Rfc2136Provider {
    addr: DnsAddress,
    signer: Option<TSigner>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsAddress {
    Tcp(SocketAddr),
    Udp(SocketAddr),
}

impl Rfc2136Provider {
    pub(crate) fn new_tsig(
        addr: impl TryInto<DnsAddress>,
        key_name: impl AsRef<str>,
        key: impl Into<Vec<u8>>,
        algorithm: TsigAlgorithm,
    ) -> crate::Result<Self> {
        Ok(Rfc2136Provider {
            addr: addr
                .try_into()
                .map_err(|_| Error::Parse("Invalid address".to_string()))?,
            signer: Some(TSigner::new(
                key.into(),
                algorithm,
                Name::from_ascii(key_name.as_ref())?,
                60,
            )?),
        })
    }

    async fn connect(&self) -> crate::Result<Client<TokioRuntimeProvider>> {
        match &self.addr {
            DnsAddress::Udp(addr) => {
                let mut builder = UdpClientStream::builder(*addr, TokioRuntimeProvider::new());
                if let Some(signer) = &self.signer {
                    builder = builder.with_signer(Some(signer.clone()));
                }
                let stream = builder.build();
                let (client, bg) = Client::from_sender(stream);
                tokio::spawn(bg);
                Ok(client)
            }
            DnsAddress::Tcp(addr) => {
                let (stream_future, sender) =
                    TcpClientStream::new(*addr, None, None, TokioRuntimeProvider::new());
                let stream = stream_future.await?;
                let mut multiplexer = DnsMultiplexer::new(stream, sender);
                if let Some(signer) = &self.signer {
                    multiplexer = multiplexer.with_signer(signer.clone());
                }
                let (client, bg) = Client::from_sender(multiplexer);
                tokio::spawn(bg);
                Ok(client)
            }
        }
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let owner = Name::from_str_relaxed(name.into_name().as_ref())?;
        let zone = Name::from_str_relaxed(origin.into_fqdn().as_ref())?;
        let rtype: RecordType = record_type.into();

        let mut client = self.connect().await?;

        let delete = Record::update0(owner.clone(), 0, rtype);
        let result = client.delete_rrset(delete, zone.clone()).await?;
        if result.response_code != ResponseCode::NoError {
            return Err(Error::Response(result.response_code.to_string()));
        }

        if records.is_empty() {
            return Ok(());
        }

        let rrset = build_rrset(owner, rtype, ttl, records)?;
        let result = client.append(rrset, zone, false).await?;
        if result.response_code != ResponseCode::NoError {
            return Err(Error::Response(result.response_code.to_string()));
        }
        Ok(())
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let owner = Name::from_str_relaxed(name.into_name().as_ref())?;
        let zone = Name::from_str_relaxed(origin.into_fqdn().as_ref())?;
        let rtype: RecordType = record_type.into();
        let rrset = build_rrset(owner, rtype, ttl, records)?;

        let mut client = self.connect().await?;
        let result = client.append(rrset, zone, false).await?;
        if result.response_code != ResponseCode::NoError {
            return Err(Error::Response(result.response_code.to_string()));
        }
        Ok(())
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let owner = Name::from_str_relaxed(name.into_name().as_ref())?;
        let zone = Name::from_str_relaxed(origin.into_fqdn().as_ref())?;
        let rtype: RecordType = record_type.into();
        let rrset = build_rrset(owner, rtype, 0, records)?;

        let mut client = self.connect().await?;
        let result = client.delete_by_rdata(rrset, zone).await?;
        if result.response_code != ResponseCode::NoError {
            return Err(Error::Response(result.response_code.to_string()));
        }
        Ok(())
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let owner = Name::from_str_relaxed(name.into_name().as_ref())?;
        let rtype: RecordType = record_type.into();

        let mut client = self.connect().await?;
        let response = client.query(owner.clone(), DNSClass::IN, rtype).await?;
        if response.response_code != ResponseCode::NoError
            && response.response_code != ResponseCode::NXDomain
        {
            return Err(Error::Response(response.response_code.to_string()));
        }

        let mut out = Vec::new();
        for record in response.answers.iter() {
            if record.record_type() != rtype || record.name != owner {
                continue;
            }
            out.push(rdata_to_dns_record(&record.data)?);
        }
        Ok(out)
    }
}

fn rdata_to_dns_record(data: &RData) -> crate::Result<DnsRecord> {
    Ok(match data {
        RData::A(a) => DnsRecord::A(a.0),
        RData::AAAA(aaaa) => DnsRecord::AAAA(aaaa.0),
        RData::CNAME(cname) => DnsRecord::CNAME(strip_trailing_dot(&cname.0.to_utf8())),
        RData::NS(ns) => DnsRecord::NS(strip_trailing_dot(&ns.0.to_utf8())),
        RData::MX(mx) => DnsRecord::MX(MXRecord {
            priority: mx.preference,
            exchange: strip_trailing_dot(&mx.exchange.to_utf8()),
        }),
        RData::TXT(txt) => {
            let combined: String = txt
                .txt_data
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                .collect();
            DnsRecord::TXT(combined)
        }
        RData::SRV(srv) => DnsRecord::SRV(SRVRecord {
            priority: srv.priority,
            weight: srv.weight,
            port: srv.port,
            target: strip_trailing_dot(&srv.target.to_utf8()),
        }),
        RData::TLSA(tlsa) => DnsRecord::TLSA(TLSARecord {
            cert_usage: tlsa_cert_usage_from(tlsa.cert_usage)?,
            selector: tlsa_selector_from(tlsa.selector)?,
            matching: tlsa_matching_from(tlsa.matching)?,
            cert_data: tlsa.cert_data.clone(),
        }),
        RData::CAA(caa) => DnsRecord::CAA(caa_to_record(caa)?),
        other => {
            return Err(Error::Api(format!(
                "Unsupported RData type for list_rrset: {}",
                other.record_type()
            )));
        }
    })
}

fn strip_trailing_dot(s: &str) -> String {
    s.strip_suffix('.').unwrap_or(s).to_string()
}

fn caa_to_record(caa: &CAA) -> crate::Result<CAARecord> {
    let issuer_critical = caa.issuer_critical;
    let value_text = String::from_utf8_lossy(&caa.value).into_owned();
    match caa.tag.as_str() {
        "issue" => {
            let (name, options) = parse_caa_value(&value_text);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(&value_text);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: value_text,
        }),
        other => Err(Error::Api(format!(
            "Unsupported CAA tag for list_rrset: {other}"
        ))),
    }
}

fn parse_caa_value(value: &str) -> (Option<String>, Vec<DnsKeyValue>) {
    let mut parts = value.split(';').map(str::trim);
    let name_part = parts.next().unwrap_or("").trim().to_string();
    let name = if name_part.is_empty() {
        None
    } else {
        Some(name_part)
    };
    let options = parts
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => DnsKeyValue {
                key: k.trim().to_string(),
                value: v.trim().to_string(),
            },
            None => DnsKeyValue {
                key: p.trim().to_string(),
                value: String::new(),
            },
        })
        .collect();
    (name, options)
}

fn tlsa_cert_usage_from(usage: CertUsage) -> crate::Result<TlsaCertUsage> {
    Ok(match usage {
        CertUsage::PkixTa => TlsaCertUsage::PkixTa,
        CertUsage::PkixEe => TlsaCertUsage::PkixEe,
        CertUsage::DaneTa => TlsaCertUsage::DaneTa,
        CertUsage::DaneEe => TlsaCertUsage::DaneEe,
        CertUsage::Private => TlsaCertUsage::Private,
        other => return Err(Error::Api(format!("Unknown TLSA cert usage: {other:?}"))),
    })
}

fn tlsa_selector_from(sel: Selector) -> crate::Result<TlsaSelector> {
    Ok(match sel {
        Selector::Full => TlsaSelector::Full,
        Selector::Spki => TlsaSelector::Spki,
        Selector::Private => TlsaSelector::Private,
        other => return Err(Error::Api(format!("Unknown TLSA selector: {other:?}"))),
    })
}

fn tlsa_matching_from(m: Matching) -> crate::Result<TlsaMatching> {
    Ok(match m {
        Matching::Raw => TlsaMatching::Raw,
        Matching::Sha256 => TlsaMatching::Sha256,
        Matching::Sha512 => TlsaMatching::Sha512,
        Matching::Private => TlsaMatching::Private,
        other => return Err(Error::Api(format!("Unknown TLSA matching: {other:?}"))),
    })
}

fn build_rrset(
    name: Name,
    rtype: RecordType,
    ttl: u32,
    records: Vec<DnsRecord>,
) -> crate::Result<RecordSet> {
    let mut rrset = RecordSet::with_ttl(name, rtype, ttl);
    for record in records {
        let (record_type, rdata) = convert_record(record)?;
        if record_type != rtype {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {rtype}, got {record_type}"
            )));
        }
        rrset.add_rdata(rdata);
    }
    Ok(rrset)
}

impl From<DnsRecordType> for RecordType {
    fn from(record_type: DnsRecordType) -> Self {
        match record_type {
            DnsRecordType::A => RecordType::A,
            DnsRecordType::AAAA => RecordType::AAAA,
            DnsRecordType::CNAME => RecordType::CNAME,
            DnsRecordType::NS => RecordType::NS,
            DnsRecordType::MX => RecordType::MX,
            DnsRecordType::TXT => RecordType::TXT,
            DnsRecordType::SRV => RecordType::SRV,
            DnsRecordType::TLSA => RecordType::TLSA,
            DnsRecordType::CAA => RecordType::CAA,
        }
    }
}

fn convert_record(record: DnsRecord) -> crate::Result<(RecordType, RData)> {
    Ok(match record {
        DnsRecord::A(content) => (RecordType::A, RData::A(A::from(content))),
        DnsRecord::AAAA(content) => (RecordType::AAAA, RData::AAAA(AAAA::from(content))),
        DnsRecord::CNAME(content) => (
            RecordType::CNAME,
            RData::CNAME(CNAME(Name::from_str_relaxed(content)?)),
        ),
        DnsRecord::NS(content) => (
            RecordType::NS,
            RData::NS(NS(Name::from_str_relaxed(content)?)),
        ),
        DnsRecord::MX(content) => (
            RecordType::MX,
            RData::MX(MX::new(
                content.priority,
                Name::from_str_relaxed(content.exchange)?,
            )),
        ),
        DnsRecord::TXT(content) => (RecordType::TXT, RData::TXT(TXT::new(txt_chunks(content)))),
        DnsRecord::SRV(content) => (
            RecordType::SRV,
            RData::SRV(SRV::new(
                content.priority,
                content.weight,
                content.port,
                Name::from_str_relaxed(content.target)?,
            )),
        ),
        DnsRecord::TLSA(content) => (
            RecordType::TLSA,
            RData::TLSA(TLSA::new(
                content.cert_usage.into(),
                content.selector.into(),
                content.matching.into(),
                content.cert_data,
            )),
        ),
        DnsRecord::CAA(caa) => (
            RecordType::CAA,
            RData::CAA(match caa {
                CAARecord::Issue {
                    issuer_critical,
                    name,
                    options,
                } => CAA::new_issue(
                    issuer_critical,
                    name.map(Name::from_str_relaxed).transpose()?,
                    options
                        .into_iter()
                        .map(|kv| KeyValue::new(kv.key, kv.value))
                        .collect(),
                ),
                CAARecord::IssueWild {
                    issuer_critical,
                    name,
                    options,
                } => CAA::new_issuewild(
                    issuer_critical,
                    name.map(Name::from_str_relaxed).transpose()?,
                    options
                        .into_iter()
                        .map(|kv| KeyValue::new(kv.key, kv.value))
                        .collect(),
                ),
                CAARecord::Iodef {
                    issuer_critical,
                    url,
                } => CAA::new_iodef(
                    issuer_critical,
                    url.parse()
                        .map_err(|_| Error::Parse("Invalid URL in CAA record".to_string()))?,
                ),
            }),
        ),
    })
}

impl From<TlsaCertUsage> for CertUsage {
    fn from(usage: TlsaCertUsage) -> Self {
        match usage {
            TlsaCertUsage::PkixTa => CertUsage::PkixTa,
            TlsaCertUsage::PkixEe => CertUsage::PkixEe,
            TlsaCertUsage::DaneTa => CertUsage::DaneTa,
            TlsaCertUsage::DaneEe => CertUsage::DaneEe,
            TlsaCertUsage::Private => CertUsage::Private,
        }
    }
}

impl From<TlsaMatching> for Matching {
    fn from(matching: TlsaMatching) -> Self {
        match matching {
            TlsaMatching::Raw => Matching::Raw,
            TlsaMatching::Sha256 => Matching::Sha256,
            TlsaMatching::Sha512 => Matching::Sha512,
            TlsaMatching::Private => Matching::Private,
        }
    }
}

impl From<TlsaSelector> for Selector {
    fn from(selector: TlsaSelector) -> Self {
        match selector {
            TlsaSelector::Full => Selector::Full,
            TlsaSelector::Spki => Selector::Spki,
            TlsaSelector::Private => Selector::Private,
        }
    }
}

impl TryFrom<&str> for DnsAddress {
    type Error = ();

    fn try_from(url: &str) -> Result<Self, Self::Error> {
        let (host, is_tcp) = if let Some(host) = url.strip_prefix("udp://") {
            (host, false)
        } else if let Some(host) = url.strip_prefix("tcp://") {
            (host, true)
        } else {
            (url, false)
        };
        let (host, port) = if let Some(host) = host.strip_prefix('[') {
            let (host, maybe_port) = host.rsplit_once(']').ok_or(())?;

            (
                host,
                maybe_port
                    .rsplit_once(':')
                    .map(|(_, port)| port)
                    .unwrap_or("53"),
            )
        } else if let Some((host, port)) = host.rsplit_once(':') {
            (host, port)
        } else {
            (host, "53")
        };

        let addr = SocketAddr::new(host.parse().map_err(|_| ())?, port.parse().map_err(|_| ())?);

        if is_tcp {
            Ok(DnsAddress::Tcp(addr))
        } else {
            Ok(DnsAddress::Udp(addr))
        }
    }
}

impl TryFrom<&String> for DnsAddress {
    type Error = ();

    fn try_from(url: &String) -> Result<Self, Self::Error> {
        DnsAddress::try_from(url.as_str())
    }
}

impl TryFrom<String> for DnsAddress {
    type Error = ();

    fn try_from(url: String) -> Result<Self, Self::Error> {
        DnsAddress::try_from(url.as_str())
    }
}

impl From<crate::TsigAlgorithm> for TsigAlgorithm {
    fn from(alg: crate::TsigAlgorithm) -> Self {
        match alg {
            crate::TsigAlgorithm::HmacMd5 => TsigAlgorithm::HmacMd5,
            crate::TsigAlgorithm::Gss => TsigAlgorithm::Gss,
            crate::TsigAlgorithm::HmacSha1 => TsigAlgorithm::HmacSha1,
            crate::TsigAlgorithm::HmacSha224 => TsigAlgorithm::HmacSha224,
            crate::TsigAlgorithm::HmacSha256 => TsigAlgorithm::HmacSha256,
            crate::TsigAlgorithm::HmacSha256_128 => TsigAlgorithm::HmacSha256_128,
            crate::TsigAlgorithm::HmacSha384 => TsigAlgorithm::HmacSha384,
            crate::TsigAlgorithm::HmacSha384_192 => TsigAlgorithm::HmacSha384_192,
            crate::TsigAlgorithm::HmacSha512 => TsigAlgorithm::HmacSha512,
            crate::TsigAlgorithm::HmacSha512_256 => TsigAlgorithm::HmacSha512_256,
        }
    }
}

impl From<ProtoError> for Error {
    fn from(e: ProtoError) -> Self {
        Error::Protocol(e.to_string())
    }
}

impl From<AddrParseError> for Error {
    fn from(e: AddrParseError) -> Self {
        Error::Parse(e.to_string())
    }
}

impl From<NetError> for Error {
    fn from(e: NetError) -> Self {
        Error::Client(e.to_string())
    }
}

impl From<DnsSecError> for Error {
    fn from(e: DnsSecError) -> Self {
        Error::Protocol(e.to_string())
    }
}
