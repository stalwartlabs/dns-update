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

use std::net::{AddrParseError, SocketAddr};
use std::sync::Arc;

use hickory_client::client::{AsyncClient, ClientConnection, ClientHandle, Signer};
use hickory_client::error::ClientError;
use hickory_client::op::ResponseCode;
use hickory_client::proto::error::ProtoError;
use hickory_client::proto::rr::dnssec::tsig::TSigner;
use hickory_client::proto::rr::dnssec::{Algorithm, KeyPair, Private, SigSigner};
use hickory_client::rr::rdata::key::KEY;
use hickory_client::rr::rdata::tsig::TsigAlgorithm;
use hickory_client::rr::rdata::{A, AAAA, CNAME, MX, NS, SRV, TXT};
use hickory_client::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_client::tcp::TcpClientConnection;
use hickory_client::udp::UdpClientConnection;

use crate::{DnsRecord, Error, IntoFqdn};

#[derive(Clone)]
pub struct Rfc2136Provider {
    addr: DnsAddress,
    signer: Arc<Signer>,
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
            signer: Arc::new(Signer::from(TSigner::new(
                key.into(),
                algorithm,
                Name::from_ascii(key_name.as_ref())?,
                60,
            )?)),
        })
    }

    pub(crate) fn new_sig0(
        addr: impl TryInto<DnsAddress>,
        signer_name: impl AsRef<str>,
        key: KeyPair<Private>,
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
            signer: Arc::new(Signer::from(signer)),
        })
    }

    async fn connect(&self) -> crate::Result<AsyncClient> {
        match &self.addr {
            DnsAddress::Udp(addr) => {
                let conn = UdpClientConnection::new(*addr)?.new_stream(Some(self.signer.clone()));
                let (client, bg) = AsyncClient::connect(conn).await?;
                tokio::spawn(bg);
                Ok(client)
            }
            DnsAddress::Tcp(addr) => {
                let conn = TcpClientConnection::new(*addr)?.new_stream(Some(self.signer.clone()));
                let (client, bg) = AsyncClient::connect(conn).await?;
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
        let (rr_type, rdata) = convert_record(record)?;
        let mut record = Record::with(
            Name::from_str_relaxed(name.into_name().as_ref())?,
            rr_type,
            ttl,
        );
        record.set_data(Some(rdata));

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
        let (rr_type, rdata) = convert_record(record)?;
        let mut record = Record::with(
            Name::from_str_relaxed(name.into_name().as_ref())?,
            rr_type,
            ttl,
        );
        record.set_data(Some(rdata));

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
        DnsRecord::A { content } => (RecordType::A, RData::A(A::from(content))),
        DnsRecord::AAAA { content } => (RecordType::AAAA, RData::AAAA(AAAA::from(content))),
        DnsRecord::CNAME { content } => (
            RecordType::CNAME,
            RData::CNAME(CNAME(Name::from_str_relaxed(content)?)),
        ),
        DnsRecord::NS { content } => (
            RecordType::NS,
            RData::NS(NS(Name::from_str_relaxed(content)?)),
        ),
        DnsRecord::MX { content, priority } => (
            RecordType::MX,
            RData::MX(MX::new(priority, Name::from_str_relaxed(content)?)),
        ),
        DnsRecord::TXT { content } => (RecordType::TXT, RData::TXT(TXT::new(vec![content]))),
        DnsRecord::SRV {
            content,
            priority,
            weight,
            port,
        } => (
            RecordType::SRV,
            RData::SRV(SRV::new(
                priority,
                weight,
                port,
                Name::from_str_relaxed(content)?,
            )),
        ),
    })
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
