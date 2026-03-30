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

use crate::{CAARecord, DnsRecord, Error, IntoFqdn, TlsaCertUsage, TlsaMatching, TlsaSelector};
use hickory_client::ClientError;
use hickory_client::client::{Client, ClientHandle};
use hickory_client::proto::ProtoError;
use hickory_client::proto::dnssec::rdata::KEY;
use hickory_client::proto::dnssec::rdata::tsig::TsigAlgorithm;
use hickory_client::proto::dnssec::tsig::TSigner;
use hickory_client::proto::dnssec::{Algorithm, DnsSecError, SigSigner, SigningKey};
use hickory_client::proto::op::MessageFinalizer;
use hickory_client::proto::op::ResponseCode;
use hickory_client::proto::rr::rdata::caa::KeyValue;
use hickory_client::proto::rr::rdata::tlsa::{CertUsage, Matching, Selector};
use hickory_client::proto::rr::rdata::{A, AAAA, CAA, CNAME, MX, NS, SRV, TLSA, TXT};
use hickory_client::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::tcp::TcpClientStream;
use hickory_client::proto::udp::UdpClientStream;
use std::net::{AddrParseError, SocketAddr};
use std::sync::Arc;

#[derive(Clone)]
pub struct Rfc2136Provider {
    addr: DnsAddress,
    signer: Arc<dyn MessageFinalizer>,
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
            signer: Arc::new(TSigner::new(
                key.into(),
                algorithm,
                Name::from_ascii(key_name.as_ref())?,
                60,
            )?),
        })
    }

    pub(crate) fn new_sig0(
        addr: impl TryInto<DnsAddress>,
        signer_name: impl AsRef<str>,
        key: Box<dyn SigningKey>,
        public_key: impl Into<Vec<u8>>,
        algorithm: Algorithm,
    ) -> crate::Result<Self> {
        let sig0key = KEY::new(
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            algorithm,
            public_key.into(),
        );

        let signer = SigSigner::sig0(sig0key, key, Name::from_str_relaxed(signer_name.as_ref())?);

        Ok(Rfc2136Provider {
            addr: addr
                .try_into()
                .map_err(|_| Error::Parse("Invalid address".to_string()))?,
            signer: Arc::new(signer),
        })
    }

    async fn connect(&self) -> crate::Result<Client> {
        match &self.addr {
            DnsAddress::Udp(addr) => {
                let stream = UdpClientStream::builder(*addr, TokioRuntimeProvider::new())
                    .with_signer(Some(self.signer.clone()))
                    .build();
                let (client, bg) = Client::connect(stream).await?;
                tokio::spawn(bg);
                Ok(client)
            }
            DnsAddress::Tcp(addr) => {
                let (stream, sender) =
                    TcpClientStream::new(*addr, None, None, TokioRuntimeProvider::new());
                let (client, bg) = Client::new(stream, sender, Some(self.signer.clone())).await?;
                tokio::spawn(bg);
                Ok(client)
            }
        }
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let (_rr_type, rdata) = convert_record(record)?;
        let record = Record::from_rdata(
            Name::from_str_relaxed(name.into_name().as_ref())?,
            ttl,
            rdata,
        );

        let mut client = self.connect().await?;
        let result = client
            .create(record, Name::from_str_relaxed(origin.into_fqdn().as_ref())?)
            .await?;
        if result.response_code() == ResponseCode::NoError {
            Ok(())
        } else {
            Err(crate::Error::Response(result.response_code().to_string()))
        }
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let (_rr_type, rdata) = convert_record(record)?;
        let record = Record::from_rdata(
            Name::from_str_relaxed(name.into_name().as_ref())?,
            ttl,
            rdata,
        );

        let mut client = self.connect().await?;
        let result = client
            .append(
                record,
                Name::from_str_relaxed(origin.into_fqdn().as_ref())?,
                false,
            )
            .await?;
        if result.response_code() == ResponseCode::NoError {
            Ok(())
        } else {
            Err(crate::Error::Response(result.response_code().to_string()))
        }
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let mut client = self.connect().await?;
        let result = client
            .delete_all(
                Name::from_str_relaxed(name.into_name().as_ref())?,
                Name::from_str_relaxed(origin.into_fqdn().as_ref())?,
                DNSClass::IN,
            )
            .await?;
        if result.response_code() == ResponseCode::NoError {
            Ok(())
        } else {
            Err(crate::Error::Response(result.response_code().to_string()))
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
        DnsRecord::TXT(content) => (RecordType::TXT, RData::TXT(TXT::new(vec![content]))),
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

impl From<crate::Algorithm> for Algorithm {
    fn from(alg: crate::Algorithm) -> Self {
        match alg {
            crate::Algorithm::RSASHA256 => Algorithm::RSASHA256,
            crate::Algorithm::RSASHA512 => Algorithm::RSASHA512,
            crate::Algorithm::ECDSAP256SHA256 => Algorithm::ECDSAP256SHA256,
            crate::Algorithm::ECDSAP384SHA384 => Algorithm::ECDSAP384SHA384,
            crate::Algorithm::ED25519 => Algorithm::ED25519,
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

impl From<ClientError> for Error {
    fn from(e: ClientError) -> Self {
        Error::Client(e.to_string())
    }
}

impl From<DnsSecError> for Error {
    fn from(e: DnsSecError) -> Self {
        Error::Protocol(e.to_string())
    }
}
