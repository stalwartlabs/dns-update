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

//! Integration tests for the RFC 2136 provider.
//!
//! These talk to a real DNS server and are off by default. Bring one up via the
//! Stalwart docker-compose at `tests/docker/docker-compose.yml` (services
//! `powerdns` and `powerdns-init`) and run:
//!
//! ```text
//! RFC2136_TEST=1 cargo test --test rfc2136 -- --test-threads=1
//! ```
//!
//! Override via env vars: `RFC2136_HOST` (default `127.0.0.1`), `RFC2136_PORT`
//! (default `5300`), `RFC2136_ZONE` (default `stalwart.test`), `RFC2136_KEY_NAME`
//! (default `stalwart-update-key`), `RFC2136_KEY_B64` (default matches the
//! docker init script).

#![cfg(test)]

use base64::{Engine, engine::general_purpose};
use hickory_net::client::{Client, ClientHandle};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_proto::rr::rdata::tsig::TsigAlgorithm as HickoryTsigAlgorithm;
use hickory_proto::rr::{DNSClass, Name, RData, RecordType, TSigner};
use hickory_net::xfer::DnsMultiplexer;

use crate::providers::rfc2136::{DnsAddress, Rfc2136Provider};
use crate::{
    CAARecord, DnsRecord, DnsRecordType, KeyValue, MXRecord, SRVRecord, TLSARecord, TlsaCertUsage,
    TlsaMatching, TlsaSelector,
};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Once;
use std::time::Duration;

const ZONE_DEFAULT: &str = "stalwart.test";
const KEY_NAME_DEFAULT: &str = "stalwart-update-key";
const KEY_B64_DEFAULT: &str = "c3RhbHdhcnQtdGVzdC10c2lnLXNlY3JldC1rZXkxMjM0NTY3ODkw";
const HOST_DEFAULT: &str = "127.0.0.1";
const PORT_DEFAULT: u16 = 5300;

fn enabled() -> bool {
    std::env::var("RFC2136_TEST").is_ok()
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn zone() -> String {
    env_or("RFC2136_ZONE", ZONE_DEFAULT)
}

fn key_name() -> String {
    env_or("RFC2136_KEY_NAME", KEY_NAME_DEFAULT)
}

fn key_bytes() -> Vec<u8> {
    general_purpose::STANDARD
        .decode(env_or("RFC2136_KEY_B64", KEY_B64_DEFAULT))
        .expect("invalid base64 key")
}

fn socket_addr() -> SocketAddr {
    let host = env_or("RFC2136_HOST", HOST_DEFAULT);
    let port: u16 = std::env::var("RFC2136_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(PORT_DEFAULT);
    SocketAddr::new(host.parse().expect("invalid RFC2136_HOST"), port)
}

fn udp_provider() -> Rfc2136Provider {
    Rfc2136Provider::new_tsig(
        DnsAddress::Udp(socket_addr()),
        key_name(),
        key_bytes(),
        HickoryTsigAlgorithm::HmacSha256,
    )
    .expect("build udp provider")
}

fn tcp_provider() -> Rfc2136Provider {
    Rfc2136Provider::new_tsig(
        DnsAddress::Tcp(socket_addr()),
        key_name(),
        key_bytes(),
        HickoryTsigAlgorithm::HmacSha256,
    )
    .expect("build tcp provider")
}

static CRYPTO_INIT: Once = Once::new();

fn ensure_crypto_provider() {
    CRYPTO_INIT.call_once(|| {
        #[cfg(feature = "aws-lc-rs")]
        {
            let _ = ::rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
        #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
        {
            let _ = ::rustls::crypto::ring::default_provider().install_default();
        }
    });
}

async fn query_records(name: &str, rtype: RecordType) -> Vec<RData> {
    let builder = UdpClientStream::builder(socket_addr(), TokioRuntimeProvider::new());
    let stream = builder.build();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
    tokio::spawn(bg);
    let resp = client
        .query(Name::from_ascii(name).unwrap(), DNSClass::IN, rtype)
        .await
        .expect("query failed");
    resp.answers.iter().map(|r| r.data.clone()).collect()
}

/// Sign a `delete-name` update for `name` to clean up after each test.
async fn cleanup_name(name: &str, rtype: DnsRecordType) {
    let provider = udp_provider();
    let _ = provider.set_rrset(name, rtype, 0, vec![], zone()).await;
}

fn unique_label(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{prefix}-{pid}-{nanos}-{n}")
}

async fn wait_for_record(name: &str, rtype: RecordType, attempts: u32) -> Vec<RData> {
    for _ in 0..attempts {
        let answers = query_records(name, rtype).await;
        if !answers.is_empty() {
            return answers;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Vec::new()
}

/// Direct TSIG UDP roundtrip (sanity check unrelated to Rfc2136Provider).
async fn signed_update_via_hickory_udp(record_name: &str, txt_value: &str) {
    let signer = TSigner::new(
        key_bytes(),
        HickoryTsigAlgorithm::HmacSha256,
        Name::from_ascii(key_name()).unwrap(),
        60,
    )
    .expect("build signer");

    let builder = UdpClientStream::builder(socket_addr(), TokioRuntimeProvider::new())
        .with_signer(Some(signer));
    let stream = builder.build();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
    tokio::spawn(bg);

    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::TXT;
    let record = Record::from_rdata(
        Name::from_ascii(record_name).unwrap(),
        60,
        RData::TXT(TXT::new(vec![txt_value.to_string()])),
    );
    let zone = Name::from_ascii(zone()).unwrap();
    let resp = client.create(record, zone).await.expect("create failed");
    assert!(
        resp.response_code == hickory_proto::op::ResponseCode::NoError,
        "rcode: {}",
        resp.response_code
    );
}

#[tokio::test]
async fn udp_tsig_baseline() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let name = format!("{}.{}", unique_label("baseline"), zone());
    signed_update_via_hickory_udp(&name, "baseline").await;
    let records = wait_for_record(&name, RecordType::TXT, 20).await;
    assert!(!records.is_empty(), "record not visible after create");
    cleanup_name(&name, DnsRecordType::TXT).await;
}

#[tokio::test]
async fn udp_create_a_record() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("{}.{}", unique_label("a"), zone());
    provider
        .set_rrset(
            &name,
            DnsRecordType::A,
            60,
            vec![DnsRecord::A(Ipv4Addr::new(10, 0, 0, 1))],
            zone(),
        )
        .await
        .expect("set A");

    let answers = wait_for_record(&name, RecordType::A, 20).await;
    assert!(answers.iter().any(|d| matches!(d, RData::A(a) if a.0 == Ipv4Addr::new(10, 0, 0, 1))));
    cleanup_name(&name, DnsRecordType::A).await;
}

#[tokio::test]
async fn tcp_create_a_record() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = tcp_provider();
    let name = format!("{}.{}", unique_label("a-tcp"), zone());
    provider
        .set_rrset(
            &name,
            DnsRecordType::A,
            60,
            vec![DnsRecord::A(Ipv4Addr::new(10, 0, 0, 2))],
            zone(),
        )
        .await
        .expect("set A via TCP (TSIG signed)");

    let answers = wait_for_record(&name, RecordType::A, 20).await;
    assert!(
        answers
            .iter()
            .any(|d| matches!(d, RData::A(a) if a.0 == Ipv4Addr::new(10, 0, 0, 2))),
        "TCP TSIG-signed update did not produce a record visible to queries"
    );
    cleanup_name(&name, DnsRecordType::A).await;
}

#[tokio::test]
async fn udp_create_aaaa_record() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("{}.{}", unique_label("aaaa"), zone());
    let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
    provider
        .set_rrset(
            &name,
            DnsRecordType::AAAA,
            60,
            vec![DnsRecord::AAAA(addr)],
            zone(),
        )
        .await
        .expect("set AAAA");

    let answers = wait_for_record(&name, RecordType::AAAA, 20).await;
    assert!(answers.iter().any(|d| matches!(d, RData::AAAA(a) if a.0 == addr)));
    cleanup_name(&name, DnsRecordType::AAAA).await;
}

#[tokio::test]
async fn udp_create_cname_record() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("{}.{}", unique_label("cname"), zone());
    let target = format!("ns1.{}.", zone());
    provider
        .set_rrset(
            &name,
            DnsRecordType::CNAME,
            60,
            vec![DnsRecord::CNAME(target.clone())],
            zone(),
        )
        .await
        .expect("set CNAME");

    let answers = wait_for_record(&name, RecordType::CNAME, 20).await;
    assert!(answers.iter().any(|d| matches!(d, RData::CNAME(c) if c.0.to_ascii() == target)));
    cleanup_name(&name, DnsRecordType::CNAME).await;
}

#[tokio::test]
async fn udp_create_mx_record() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("{}.{}", unique_label("mx"), zone());
    let exchange = format!("mail.{}.", zone());
    provider
        .set_rrset(
            &name,
            DnsRecordType::MX,
            60,
            vec![DnsRecord::MX(MXRecord {
                exchange: exchange.clone(),
                priority: 20,
            })],
            zone(),
        )
        .await
        .expect("set MX");

    let answers = wait_for_record(&name, RecordType::MX, 20).await;
    assert!(answers.iter().any(|d| match d {
        RData::MX(m) => m.preference == 20 && m.exchange.to_ascii() == exchange,
        _ => false,
    }));
    cleanup_name(&name, DnsRecordType::MX).await;
}

#[tokio::test]
async fn udp_create_srv_record() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("_imap._tcp.{}.{}", unique_label("srv"), zone());
    let target = format!("mail.{}.", zone());
    provider
        .set_rrset(
            &name,
            DnsRecordType::SRV,
            60,
            vec![DnsRecord::SRV(SRVRecord {
                target: target.clone(),
                priority: 0,
                weight: 5,
                port: 143,
            })],
            zone(),
        )
        .await
        .expect("set SRV");

    let answers = wait_for_record(&name, RecordType::SRV, 20).await;
    assert!(answers.iter().any(|d| match d {
        RData::SRV(s) =>
            s.priority == 0
                && s.weight == 5
                && s.port == 143
                && s.target.to_ascii() == target,
        _ => false,
    }));
    cleanup_name(&name, DnsRecordType::SRV).await;
}

#[tokio::test]
async fn udp_create_short_txt_record() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("{}.{}", unique_label("txt"), zone());
    let value = "v=test1; short".to_string();
    provider
        .set_rrset(
            &name,
            DnsRecordType::TXT,
            60,
            vec![DnsRecord::TXT(value.clone())],
            zone(),
        )
        .await
        .expect("set TXT");

    let answers = wait_for_record(&name, RecordType::TXT, 20).await;
    let txt = answers.iter().find_map(|d| match d {
        RData::TXT(t) => Some(t),
        _ => None,
    });
    let txt = txt.expect("no TXT in answer");
    let combined: String = txt
        .txt_data
        .iter()
        .map(|bytes| String::from_utf8_lossy(bytes).to_string())
        .collect();
    assert_eq!(combined, value);
    cleanup_name(&name, DnsRecordType::TXT).await;
}

#[tokio::test]
async fn udp_create_long_txt_record_chunked() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("{}.{}", unique_label("txt-long"), zone());
    let value: String = (0..600).map(|i| (b'a' + (i % 26) as u8) as char).collect();
    provider
        .set_rrset(
            &name,
            DnsRecordType::TXT,
            60,
            vec![DnsRecord::TXT(value.clone())],
            zone(),
        )
        .await
        .expect("set long TXT");

    let answers = wait_for_record(&name, RecordType::TXT, 20).await;
    let txt = answers
        .iter()
        .find_map(|d| match d {
            RData::TXT(t) => Some(t),
            _ => None,
        })
        .expect("no TXT in answer");
    // hickory exposes the chunked representation as separate items in `txt_data`.
    let mut combined = String::new();
    for bytes in txt.txt_data.iter() {
        combined.push_str(&String::from_utf8_lossy(bytes));
    }
    assert_eq!(combined, value);
    // No individual chunk should exceed 255 bytes (RFC 1035 limit).
    assert!(txt.txt_data.iter().all(|chunk| chunk.len() <= 255));
    cleanup_name(&name, DnsRecordType::TXT).await;
}

#[tokio::test]
async fn udp_create_tlsa_record() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("_25._tcp.{}.{}", unique_label("tlsa"), zone());
    let cert: Vec<u8> = (0..32).collect();
    provider
        .set_rrset(
            &name,
            DnsRecordType::TLSA,
            60,
            vec![DnsRecord::TLSA(TLSARecord {
                cert_usage: TlsaCertUsage::DaneEe,
                selector: TlsaSelector::Spki,
                matching: TlsaMatching::Sha256,
                cert_data: cert.clone(),
            })],
            zone(),
        )
        .await
        .expect("set TLSA");

    let answers = wait_for_record(&name, RecordType::TLSA, 20).await;
    assert!(answers.iter().any(|d| match d {
        RData::TLSA(t) => t.cert_data == cert,
        _ => false,
    }));
    cleanup_name(&name, DnsRecordType::TLSA).await;
}

#[tokio::test]
async fn udp_add_to_rrset_appends_two_tlsa_at_same_owner() {
    // Regression: two add_to_rrset calls at the same (name, TLSA) owner must
    // both succeed and coexist. This is the same scenario where the old
    // single-record create API hit YXRRSET on the second call.
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("_25._tcp.{}.{}", unique_label("tlsa-multi"), zone());
    let leaf: Vec<u8> = (0..32).collect();
    let intermediate: Vec<u8> = (32..64).collect();

    provider
        .add_to_rrset(
            &name,
            DnsRecordType::TLSA,
            60,
            vec![DnsRecord::TLSA(TLSARecord {
                cert_usage: TlsaCertUsage::DaneEe,
                selector: TlsaSelector::Spki,
                matching: TlsaMatching::Sha256,
                cert_data: leaf.clone(),
            })],
            zone(),
        )
        .await
        .expect("add first TLSA");

    provider
        .add_to_rrset(
            &name,
            DnsRecordType::TLSA,
            60,
            vec![DnsRecord::TLSA(TLSARecord {
                cert_usage: TlsaCertUsage::DaneTa,
                selector: TlsaSelector::Spki,
                matching: TlsaMatching::Sha256,
                cert_data: intermediate.clone(),
            })],
            zone(),
        )
        .await
        .expect("add second TLSA at same owner");

    let answers = wait_for_record(&name, RecordType::TLSA, 20).await;
    let datas: Vec<&Vec<u8>> = answers
        .iter()
        .filter_map(|d| match d {
            RData::TLSA(t) => Some(&t.cert_data),
            _ => None,
        })
        .collect();
    assert!(
        datas.iter().any(|d| **d == leaf),
        "leaf TLSA missing from RRSet: {datas:?}"
    );
    assert!(
        datas.iter().any(|d| **d == intermediate),
        "intermediate TLSA missing from RRSet: {datas:?}"
    );
    cleanup_name(&name, DnsRecordType::TLSA).await;
}

#[tokio::test]
async fn udp_create_caa_record() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("{}.{}", unique_label("caa"), zone());
    provider
        .set_rrset(
            &name,
            DnsRecordType::CAA,
            60,
            vec![DnsRecord::CAA(CAARecord::Issue {
                issuer_critical: false,
                name: Some("letsencrypt.org".to_string()),
                options: vec![KeyValue {
                    key: "validationmethods".to_string(),
                    value: "dns-01".to_string(),
                }],
            })],
            zone(),
        )
        .await
        .expect("set CAA");

    let answers = wait_for_record(&name, RecordType::CAA, 20).await;
    assert!(!answers.is_empty(), "CAA record not visible after create");
    cleanup_name(&name, DnsRecordType::CAA).await;
}

#[tokio::test]
async fn udp_delete_record_round_trip() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("{}.{}", unique_label("del"), zone());

    provider
        .set_rrset(
            &name,
            DnsRecordType::A,
            60,
            vec![DnsRecord::A(Ipv4Addr::new(10, 0, 0, 99))],
            zone(),
        )
        .await
        .expect("set A");
    assert!(!wait_for_record(&name, RecordType::A, 20).await.is_empty());

    provider
        .set_rrset(&name, DnsRecordType::A, 0, vec![], zone())
        .await
        .expect("clear A");

    // Confirm the record is gone.
    let mut empty = false;
    for _ in 0..20 {
        if query_records(&name, RecordType::A).await.is_empty() {
            empty = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(empty, "record still present after delete");
}

#[tokio::test]
async fn tcp_tsig_signer_is_actually_applied() {
    // Regression: in dns-update v0.3.0 the TCP path did not attach the TSIG
    // signer when migrating to hickory 0.26, producing unsigned updates that
    // PowerDNS rejects with REFUSED. We verify the operation succeeds.
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = tcp_provider();
    let name = format!("{}.{}", unique_label("tcp-sig"), zone());
    provider
        .set_rrset(
            &name,
            DnsRecordType::TXT,
            60,
            vec![DnsRecord::TXT("tcp-sig-test".into())],
            zone(),
        )
        .await
        .expect("TCP TSIG-signed create must succeed");

    // Also confirm via an unsigned UDP query so a working UDP path doesn't mask a TCP regression.
    let answers = wait_for_record(&name, RecordType::TXT, 20).await;
    assert!(!answers.is_empty());
    cleanup_name(&name, DnsRecordType::TXT).await;
}

#[tokio::test]
async fn set_rrset_publishes_two_tlsa_in_one_call() {
    // Direct exercise of the new RRSet API: a single set_rrset call must
    // atomically put both TLSA values at the same owner (the case forum 321 hit
    // when the per-record create API tried two creates and the second was
    // rejected with YXRRSET).
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("_25._tcp.{}.{}", unique_label("tlsa-set"), zone());
    let leaf: Vec<u8> = (0..32).collect();
    let intermediate: Vec<u8> = (32..64).collect();

    provider
        .set_rrset(
            &name,
            DnsRecordType::TLSA,
            60,
            vec![
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: leaf.clone(),
                }),
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneTa,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: intermediate.clone(),
                }),
            ],
            zone(),
        )
        .await
        .expect("set_rrset");

    let answers = wait_for_record(&name, RecordType::TLSA, 20).await;
    let datas: Vec<&Vec<u8>> = answers
        .iter()
        .filter_map(|d| match d {
            RData::TLSA(t) => Some(&t.cert_data),
            _ => None,
        })
        .collect();
    assert!(datas.iter().any(|d| **d == leaf), "leaf TLSA missing: {datas:?}");
    assert!(
        datas.iter().any(|d| **d == intermediate),
        "intermediate TLSA missing: {datas:?}"
    );
    cleanup_name(&name, DnsRecordType::TLSA).await;
}

#[tokio::test]
async fn set_rrset_replaces_existing_with_new_values() {
    // Cert renewal: same (name, type) RRSet should end up containing only the
    // new values; the old ones disappear.
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("{}.{}", unique_label("set-replace"), zone());

    provider
        .set_rrset(
            &name,
            DnsRecordType::A,
            60,
            vec![
                DnsRecord::A(Ipv4Addr::new(10, 0, 0, 1)),
                DnsRecord::A(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            zone(),
        )
        .await
        .expect("initial set_rrset");

    provider
        .set_rrset(
            &name,
            DnsRecordType::A,
            60,
            vec![
                DnsRecord::A(Ipv4Addr::new(10, 0, 0, 3)),
                DnsRecord::A(Ipv4Addr::new(10, 0, 0, 4)),
            ],
            zone(),
        )
        .await
        .expect("second set_rrset");

    let answers = wait_for_record(&name, RecordType::A, 20).await;
    let addrs: Vec<Ipv4Addr> = answers
        .iter()
        .filter_map(|d| match d {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    assert!(
        addrs.contains(&Ipv4Addr::new(10, 0, 0, 3))
            && addrs.contains(&Ipv4Addr::new(10, 0, 0, 4)),
        "new addresses missing: {addrs:?}"
    );
    assert!(
        !addrs.contains(&Ipv4Addr::new(10, 0, 0, 1))
            && !addrs.contains(&Ipv4Addr::new(10, 0, 0, 2)),
        "old addresses still present: {addrs:?}"
    );
    cleanup_name(&name, DnsRecordType::A).await;
}

#[tokio::test]
async fn set_rrset_empty_records_deletes_the_rrset() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("{}.{}", unique_label("set-empty"), zone());

    provider
        .set_rrset(
            &name,
            DnsRecordType::A,
            60,
            vec![DnsRecord::A(Ipv4Addr::new(10, 0, 0, 50))],
            zone(),
        )
        .await
        .expect("set_rrset initial");
    assert!(!wait_for_record(&name, RecordType::A, 20).await.is_empty());

    provider
        .set_rrset(&name, DnsRecordType::A, 60, vec![], zone())
        .await
        .expect("set_rrset empty");

    let mut empty = false;
    for _ in 0..20 {
        if query_records(&name, RecordType::A).await.is_empty() {
            empty = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(empty, "rrset still present after set_rrset(empty)");
}

#[tokio::test]
async fn add_to_rrset_appends_without_replacing() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("{}.{}", unique_label("add"), zone());

    provider
        .set_rrset(
            &name,
            DnsRecordType::A,
            60,
            vec![DnsRecord::A(Ipv4Addr::new(10, 1, 0, 1))],
            zone(),
        )
        .await
        .expect("set_rrset initial");

    provider
        .add_to_rrset(
            &name,
            DnsRecordType::A,
            60,
            vec![
                DnsRecord::A(Ipv4Addr::new(10, 1, 0, 2)),
                DnsRecord::A(Ipv4Addr::new(10, 1, 0, 3)),
            ],
            zone(),
        )
        .await
        .expect("add_to_rrset");

    let answers = wait_for_record(&name, RecordType::A, 20).await;
    let addrs: Vec<Ipv4Addr> = answers
        .iter()
        .filter_map(|d| match d {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    for expected in [
        Ipv4Addr::new(10, 1, 0, 1),
        Ipv4Addr::new(10, 1, 0, 2),
        Ipv4Addr::new(10, 1, 0, 3),
    ] {
        assert!(addrs.contains(&expected), "expected {expected} in {addrs:?}");
    }
    cleanup_name(&name, DnsRecordType::A).await;
}

#[tokio::test]
async fn remove_from_rrset_drops_only_listed_values() {
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("{}.{}", unique_label("remove"), zone());

    provider
        .set_rrset(
            &name,
            DnsRecordType::A,
            60,
            vec![
                DnsRecord::A(Ipv4Addr::new(10, 2, 0, 1)),
                DnsRecord::A(Ipv4Addr::new(10, 2, 0, 2)),
                DnsRecord::A(Ipv4Addr::new(10, 2, 0, 3)),
            ],
            zone(),
        )
        .await
        .expect("set_rrset initial");

    provider
        .remove_from_rrset(
            &name,
            DnsRecordType::A,
            vec![DnsRecord::A(Ipv4Addr::new(10, 2, 0, 2))],
            zone(),
        )
        .await
        .expect("remove_from_rrset");

    let answers = wait_for_record(&name, RecordType::A, 20).await;
    let addrs: Vec<Ipv4Addr> = answers
        .iter()
        .filter_map(|d| match d {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    assert!(addrs.contains(&Ipv4Addr::new(10, 2, 0, 1)));
    assert!(!addrs.contains(&Ipv4Addr::new(10, 2, 0, 2)));
    assert!(addrs.contains(&Ipv4Addr::new(10, 2, 0, 3)));
    cleanup_name(&name, DnsRecordType::A).await;
}

#[tokio::test]
async fn set_rrset_is_idempotent_on_rerun() {
    // Running set_rrset twice with the same values must leave the server in
    // the same observable state (this is the property Stalwart's reconcile
    // loop depends on).
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let provider = udp_provider();
    let name = format!("{}.{}", unique_label("set-idem"), zone());
    let records = vec![
        DnsRecord::A(Ipv4Addr::new(10, 3, 0, 1)),
        DnsRecord::A(Ipv4Addr::new(10, 3, 0, 2)),
    ];

    provider
        .set_rrset(&name, DnsRecordType::A, 60, records.clone(), zone())
        .await
        .expect("first set_rrset");
    let first: Vec<RData> = wait_for_record(&name, RecordType::A, 20).await;

    provider
        .set_rrset(&name, DnsRecordType::A, 60, records, zone())
        .await
        .expect("second set_rrset");
    let second: Vec<RData> = wait_for_record(&name, RecordType::A, 20).await;

    let mut first_addrs: Vec<Ipv4Addr> = first
        .iter()
        .filter_map(|d| match d {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    let mut second_addrs: Vec<Ipv4Addr> = second
        .iter()
        .filter_map(|d| match d {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    first_addrs.sort();
    second_addrs.sort();
    assert_eq!(first_addrs, second_addrs, "set_rrset is not idempotent");
    cleanup_name(&name, DnsRecordType::A).await;
}

#[tokio::test]
async fn legacy_create_via_dns_updater_dispatch_returns_error() {
    // The DnsUpdater dispatch refuses the legacy single-record API for RFC 2136.
    if !enabled() {
        return;
    }
    ensure_crypto_provider();
    let updater = crate::DnsUpdater::new_rfc2136_tsig(
        format!("udp://{}", socket_addr()),
        key_name(),
        key_bytes(),
        crate::TsigAlgorithm::HmacSha256,
    )
    .expect("build DnsUpdater");
    let name = format!("{}.{}", unique_label("legacy"), zone());
    let result = updater
        .create(&name, DnsRecord::A(Ipv4Addr::new(10, 99, 0, 1)), 60, zone())
        .await;
    assert!(
        matches!(result, Err(crate::Error::Api(ref msg)) if msg.contains("RRSet API")),
        "expected Error::Api(RRSet API ...), got {result:?}"
    );
}

#[tokio::test]
async fn tcp_unsigned_update_is_rejected() {
    // Send an update via TCP without any TSIG signer. PowerDNS is configured to
    // require TSIG, so the response must be a non-NoError code (REFUSED in practice).
    if !enabled() {
        return;
    }

    let addr = socket_addr();
    let (stream_future, sender) =
        TcpClientStream::new(addr, None, None, TokioRuntimeProvider::new());
    let stream = stream_future.await.expect("tcp connect");
    let multiplexer = DnsMultiplexer::new(stream, sender);
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(multiplexer);
    tokio::spawn(bg);

    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::TXT;
    let name = format!("{}.{}", unique_label("unsigned"), zone());
    let record = Record::from_rdata(
        Name::from_ascii(&name).unwrap(),
        60,
        RData::TXT(TXT::new(vec!["should-be-rejected".into()])),
    );
    let zone_name = Name::from_ascii(zone()).unwrap();
    let resp = client.create(record, zone_name).await.expect("send");
    assert_ne!(
        resp.response_code,
        hickory_proto::op::ResponseCode::NoError,
        "server accepted unsigned update; check that TSIG is enforced",
    );
}
