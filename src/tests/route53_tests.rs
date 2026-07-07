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

use crate::providers::route53::{Route53Config, Route53Provider};
use crate::{
    CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, SRVRecord, TLSARecord,
    TlsaCertUsage, TlsaMatching, TlsaSelector,
};
use mockito::{Matcher, Mock, ServerGuard};

const ZONE_ID: &str = "Z1ABCDEFGH";

fn setup_provider(endpoint: String) -> Route53Provider {
    Route53Provider::new(Route53Config {
        access_key_id: "AKIA_TEST".to_string(),
        secret_access_key: "test_secret".to_string(),
        session_token: None,
        region: Some("us-east-1".to_string()),
        hosted_zone_id: Some(ZONE_ID.to_string()),
        private_zone_only: Some(false),
        endpoint: None,
    })
    .with_endpoint(endpoint)
}

fn setup_provider_zone_lookup(endpoint: String) -> Route53Provider {
    Route53Provider::new(Route53Config {
        access_key_id: "AKIA_TEST".to_string(),
        secret_access_key: "test_secret".to_string(),
        session_token: None,
        region: Some("us-east-1".to_string()),
        hosted_zone_id: None,
        private_zone_only: Some(false),
        endpoint: None,
    })
    .with_endpoint(endpoint)
}

fn list_path() -> String {
    format!("/2013-04-01/hostedzone/{}/rrset", ZONE_ID)
}

fn change_path() -> String {
    format!("/2013-04-01/hostedzone/{}/rrset", ZONE_ID)
}

fn list_response_xml(rrsets: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ResourceRecordSets>{rrsets}</ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
  <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>"#
    )
}

fn rrset_xml(name: &str, rtype: &str, ttl: u32, values: &[&str]) -> String {
    let mut records = String::new();
    for v in values {
        records.push_str(&format!(
            "<ResourceRecord><Value>{}</Value></ResourceRecord>",
            v.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        ));
    }
    format!(
        "<ResourceRecordSet><Name>{name}</Name><Type>{rtype}</Type><TTL>{ttl}</TTL><ResourceRecords>{records}</ResourceRecords></ResourceRecordSet>"
    )
}

fn change_response_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ChangeInfo>
    <Id>/change/C123</Id>
    <Status>PENDING</Status>
    <SubmittedAt>2026-05-24T12:00:00Z</SubmittedAt>
  </ChangeInfo>
</ChangeResourceRecordSetsResponse>"#
}

fn mock_list(server: &mut ServerGuard, name: &str, rtype: &str, body: String) -> Mock {
    server
        .mock("GET", list_path().as_str())
        .match_query(Matcher::AllOf(vec![
            Matcher::UrlEncoded("name".into(), name.into()),
            Matcher::UrlEncoded("type".into(), rtype.into()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/xml")
        .with_body(body)
        .create()
}

fn mock_change(server: &mut ServerGuard, body_substrings: Vec<String>) -> Mock {
    let matchers: Vec<Matcher> = body_substrings.into_iter().map(Matcher::Regex).collect();
    server
        .mock("POST", change_path().as_str())
        .match_body(Matcher::AllOf(matchers))
        .with_status(200)
        .with_header("content-type", "application/xml")
        .with_body(change_response_xml())
        .create()
}

fn mock_empty_rrset_list(server: &mut ServerGuard, name: &str, rtype: &str) -> Mock {
    mock_list(server, name, rtype, list_response_xml(""))
}

#[tokio::test]
async fn test_route53_provider_creation() {
    let _provider = Route53Provider::new(Route53Config {
        access_key_id: "test_access_key".to_string(),
        secret_access_key: "test_secret_key".to_string(),
        session_token: None,
        region: Some("us-east-1".to_string()),
        hosted_zone_id: Some("test_zone_id".to_string()),
        private_zone_only: Some(false),
        endpoint: None,
    });
}

#[tokio::test]
async fn test_route53_updater_creation() {
    let updater = DnsUpdater::new_route53(Route53Config {
        access_key_id: "test_access_key".to_string(),
        secret_access_key: "test_secret_key".to_string(),
        session_token: None,
        region: Some("us-west-2".to_string()),
        hosted_zone_id: None,
        private_zone_only: Some(true),
        endpoint: None,
    })
    .unwrap();
    match updater {
        DnsUpdater::Route53(_) => {}
        _ => panic!("Expected Route53 provider"),
    }
}

#[tokio::test]
async fn test_route53_config_defaults() {
    let _provider = Route53Provider::new(Route53Config {
        access_key_id: "test_access_key".to_string(),
        secret_access_key: "test_secret_key".to_string(),
        session_token: None,
        region: None,
        hosted_zone_id: None,
        private_zone_only: None,
        endpoint: None,
    });
}

#[tokio::test]
async fn test_route53_config_with_session_token() {
    let _provider = Route53Provider::new(Route53Config {
        access_key_id: "test_access_key".to_string(),
        secret_access_key: "test_secret_key".to_string(),
        session_token: Some("test_session_token".to_string()),
        region: Some("eu-west-1".to_string()),
        hosted_zone_id: Some("Z1234567890".to_string()),
        private_zone_only: Some(true),
        endpoint: None,
    });
}

#[tokio::test]
async fn test_route53_config_minimal() {
    let updater = DnsUpdater::new_route53(Route53Config {
        access_key_id: "test_access_key".to_string(),
        secret_access_key: "test_secret_key".to_string(),
        session_token: None,
        region: None,
        hosted_zone_id: None,
        private_zone_only: None,
        endpoint: None,
    })
    .unwrap();
    match updater {
        DnsUpdater::Route53(_) => {}
        _ => panic!("Expected Route53 provider"),
    }
}

#[tokio::test]
async fn test_route53_custom_endpoint_from_config() {
    let mut server = mockito::Server::new_async().await;
    let change = mock_change(
        &mut server,
        vec![
            r"<Action>UPSERT</Action>".to_string(),
            r"<Value>1\.2\.3\.4</Value>".to_string(),
        ],
    );

    let provider = Route53Provider::new(Route53Config {
        access_key_id: "AKIA_TEST".to_string(),
        secret_access_key: "test_secret".to_string(),
        session_token: None,
        region: Some("eu-central-1".to_string()),
        hosted_zone_id: Some(ZONE_ID.to_string()),
        private_zone_only: Some(false),
        endpoint: Some(server.url()),
    });

    let result = provider
        .set_rrset(
            "host.example.com",
            DnsRecordType::A,
            300,
            vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "set_rrset returned: {result:?}");
    change.assert();
}

#[tokio::test]
async fn test_set_rrset_upsert_with_records() {
    let mut server = mockito::Server::new_async().await;
    let change = mock_change(
        &mut server,
        vec![
            r"<Action>UPSERT</Action>".to_string(),
            r"<Name>host\.example\.com\.</Name>".to_string(),
            r"<Type>A</Type>".to_string(),
            r"<TTL>300</TTL>".to_string(),
            r"<Value>1\.2\.3\.4</Value>".to_string(),
            r"<Value>5\.6\.7\.8</Value>".to_string(),
        ],
    );

    let provider = setup_provider(server.url());
    let result = provider
        .set_rrset(
            "host.example.com",
            DnsRecordType::A,
            300,
            vec![
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                DnsRecord::A("5.6.7.8".parse().unwrap()),
            ],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "set_rrset returned: {result:?}");
    change.assert();
}

#[tokio::test]
async fn test_set_rrset_empty_deletes_existing() {
    let mut server = mockito::Server::new_async().await;
    let list = mock_list(
        &mut server,
        "gone.example.com.",
        "A",
        list_response_xml(&rrset_xml(
            "gone.example.com.",
            "A",
            300,
            &["1.2.3.4", "5.6.7.8"],
        )),
    );
    let change = mock_change(
        &mut server,
        vec![
            r"<Action>DELETE</Action>".to_string(),
            r"<Name>gone\.example\.com\.</Name>".to_string(),
            r"<Type>A</Type>".to_string(),
            r"<Value>1\.2\.3\.4</Value>".to_string(),
            r"<Value>5\.6\.7\.8</Value>".to_string(),
        ],
    );

    let provider = setup_provider(server.url());
    let result = provider
        .set_rrset(
            "gone.example.com",
            DnsRecordType::A,
            300,
            vec![],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "set_rrset returned: {result:?}");
    list.assert();
    change.assert();
}

#[tokio::test]
async fn test_set_rrset_empty_noop_when_absent() {
    let mut server = mockito::Server::new_async().await;
    let list = mock_empty_rrset_list(&mut server, "missing.example.com.", "A");
    let no_change = server
        .mock("POST", change_path().as_str())
        .expect(0)
        .create();

    let provider = setup_provider(server.url());
    let result = provider
        .set_rrset(
            "missing.example.com",
            DnsRecordType::A,
            300,
            vec![],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "set_rrset returned: {result:?}");
    list.assert();
    no_change.assert();
}

#[tokio::test]
async fn test_set_rrset_records_must_match_declared_type() {
    let mut server = mockito::Server::new_async().await;
    let no_call = server.mock("POST", Matcher::Any).expect(0).create();

    let provider = setup_provider(server.url());
    let result = provider
        .set_rrset(
            "host.example.com",
            DnsRecordType::A,
            300,
            vec![DnsRecord::TXT("oops".to_string())],
            "example.com",
        )
        .await;

    assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    no_call.assert();
}

#[tokio::test]
async fn test_add_to_rrset_empty_is_early_return() {
    let mut server = mockito::Server::new_async().await;
    let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
    let _no_post = server.mock("POST", Matcher::Any).expect(0).create();

    let provider = setup_provider(server.url());
    let result = provider
        .add_to_rrset(
            "host.example.com",
            DnsRecordType::A,
            300,
            vec![],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
}

#[tokio::test]
async fn test_add_to_rrset_skips_already_present_value() {
    let mut server = mockito::Server::new_async().await;
    let list = mock_list(
        &mut server,
        "host.example.com.",
        "A",
        list_response_xml(&rrset_xml("host.example.com.", "A", 300, &["1.2.3.4"])),
    );
    let change = mock_change(
        &mut server,
        vec![
            r"<Action>UPSERT</Action>".to_string(),
            r"<Value>1\.2\.3\.4</Value>".to_string(),
            r"<Value>9\.9\.9\.9</Value>".to_string(),
        ],
    );

    let provider = setup_provider(server.url());
    let result = provider
        .add_to_rrset(
            "host.example.com",
            DnsRecordType::A,
            300,
            vec![
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                DnsRecord::A("9.9.9.9".parse().unwrap()),
            ],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
    list.assert();
    change.assert();
}

#[tokio::test]
async fn test_add_to_rrset_creates_when_absent() {
    let mut server = mockito::Server::new_async().await;
    let list = mock_empty_rrset_list(&mut server, "fresh.example.com.", "A");
    let change = mock_change(
        &mut server,
        vec![
            r"<Action>UPSERT</Action>".to_string(),
            r"<Name>fresh\.example\.com\.</Name>".to_string(),
            r"<Value>9\.9\.9\.9</Value>".to_string(),
        ],
    );

    let provider = setup_provider(server.url());
    let result = provider
        .add_to_rrset(
            "fresh.example.com",
            DnsRecordType::A,
            300,
            vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
    list.assert();
    change.assert();
}

#[tokio::test]
async fn test_remove_from_rrset_empty_is_early_return() {
    let mut server = mockito::Server::new_async().await;
    let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
    let _no_post = server.mock("POST", Matcher::Any).expect(0).create();

    let provider = setup_provider(server.url());
    let result = provider
        .remove_from_rrset("host.example.com", DnsRecordType::A, vec![], "example.com")
        .await;

    assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
}

#[tokio::test]
async fn test_remove_from_rrset_noop_when_value_absent() {
    let mut server = mockito::Server::new_async().await;
    let list = mock_list(
        &mut server,
        "host.example.com.",
        "A",
        list_response_xml(&rrset_xml("host.example.com.", "A", 300, &["1.2.3.4"])),
    );
    let _no_change = server
        .mock("POST", change_path().as_str())
        .expect(0)
        .create();

    let provider = setup_provider(server.url());
    let result = provider
        .remove_from_rrset(
            "host.example.com",
            DnsRecordType::A,
            vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    list.assert();
}

#[tokio::test]
async fn test_remove_from_rrset_drops_filtered_entry() {
    let mut server = mockito::Server::new_async().await;
    let list = mock_list(
        &mut server,
        "host.example.com.",
        "A",
        list_response_xml(&rrset_xml(
            "host.example.com.",
            "A",
            600,
            &["1.2.3.4", "9.9.9.9"],
        )),
    );
    let change = mock_change(
        &mut server,
        vec![
            r"<Action>UPSERT</Action>".to_string(),
            r"<TTL>600</TTL>".to_string(),
            r"<Value>1\.2\.3\.4</Value>".to_string(),
        ],
    );

    let provider = setup_provider(server.url());
    let result = provider
        .remove_from_rrset(
            "host.example.com",
            DnsRecordType::A,
            vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    list.assert();
    change.assert();
}

#[tokio::test]
async fn test_remove_from_rrset_deletes_when_last_value_removed() {
    let mut server = mockito::Server::new_async().await;
    let list = mock_list(
        &mut server,
        "host.example.com.",
        "A",
        list_response_xml(&rrset_xml("host.example.com.", "A", 600, &["1.2.3.4"])),
    );
    let change = mock_change(
        &mut server,
        vec![
            r"<Action>DELETE</Action>".to_string(),
            r"<TTL>600</TTL>".to_string(),
            r"<Value>1\.2\.3\.4</Value>".to_string(),
        ],
    );

    let provider = setup_provider(server.url());
    let result = provider
        .remove_from_rrset(
            "host.example.com",
            DnsRecordType::A,
            vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    list.assert();
    change.assert();
}

#[tokio::test]
async fn test_list_rrset_returns_parsed_records() {
    let mut server = mockito::Server::new_async().await;
    let list = mock_list(
        &mut server,
        "host.example.com.",
        "A",
        list_response_xml(&rrset_xml(
            "host.example.com.",
            "A",
            300,
            &["1.1.1.1", "2.2.2.2"],
        )),
    );

    let provider = setup_provider(server.url());
    let result = provider
        .list_rrset("host.example.com", DnsRecordType::A, "example.com")
        .await
        .unwrap();
    assert_eq!(
        result,
        vec![
            DnsRecord::A("1.1.1.1".parse().unwrap()),
            DnsRecord::A("2.2.2.2".parse().unwrap()),
        ]
    );
    list.assert();
}

#[tokio::test]
async fn test_list_rrset_empty_when_not_found() {
    let mut server = mockito::Server::new_async().await;
    let list = mock_empty_rrset_list(&mut server, "host.example.com.", "A");

    let provider = setup_provider(server.url());
    let result = provider
        .list_rrset("host.example.com", DnsRecordType::A, "example.com")
        .await
        .unwrap();
    assert!(result.is_empty());
    list.assert();
}

#[tokio::test]
async fn test_list_rrset_cross_type_isolation() {
    let mut server = mockito::Server::new_async().await;
    let body = list_response_xml(&format!(
        "{}{}",
        rrset_xml("host.example.com.", "A", 300, &["1.1.1.1"]),
        rrset_xml("host.example.com.", "TXT", 300, &["\"keep-me\""]),
    ));
    let list = mock_list(&mut server, "host.example.com.", "A", body);

    let provider = setup_provider(server.url());
    let result = provider
        .list_rrset("host.example.com", DnsRecordType::A, "example.com")
        .await
        .unwrap();
    assert_eq!(result, vec![DnsRecord::A("1.1.1.1".parse().unwrap())]);
    list.assert();
}

#[tokio::test]
async fn test_set_rrset_only_touches_requested_type() {
    let mut server = mockito::Server::new_async().await;
    let body = list_response_xml(&format!(
        "{}{}",
        rrset_xml("host.example.com.", "A", 300, &["1.1.1.1"]),
        rrset_xml("host.example.com.", "TXT", 300, &["\"keep-me\""]),
    ));
    let _list = mock_list(&mut server, "host.example.com.", "A", body);

    let change = mock_change(
        &mut server,
        vec![
            r"<Action>UPSERT</Action>".to_string(),
            r"<Type>A</Type>".to_string(),
            r"<Value>2\.2\.2\.2</Value>".to_string(),
        ],
    );

    let txt_change = server
        .mock("POST", change_path().as_str())
        .match_body(Matcher::Regex(r"<Type>TXT</Type>".to_string()))
        .expect(0)
        .create();

    let provider = setup_provider(server.url());
    let result = provider
        .set_rrset(
            "host.example.com",
            DnsRecordType::A,
            300,
            vec![DnsRecord::A("2.2.2.2".parse().unwrap())],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "set_rrset returned: {result:?}");
    change.assert();
    txt_change.assert();
}

#[tokio::test]
async fn test_set_rrset_mx_with_two_priorities() {
    let mut server = mockito::Server::new_async().await;
    let change = mock_change(
        &mut server,
        vec![
            r"<Action>UPSERT</Action>".to_string(),
            r"<Type>MX</Type>".to_string(),
            r"<Value>10 mx1\.example\.com\.</Value>".to_string(),
            r"<Value>20 mx2\.example\.com\.</Value>".to_string(),
        ],
    );

    let provider = setup_provider(server.url());
    let result = provider
        .set_rrset(
            "example.com",
            DnsRecordType::MX,
            3600,
            vec![
                DnsRecord::MX(MXRecord {
                    exchange: "mx1.example.com.".to_string(),
                    priority: 10,
                }),
                DnsRecord::MX(MXRecord {
                    exchange: "mx2.example.com.".to_string(),
                    priority: 20,
                }),
            ],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "set_rrset returned: {result:?}");
    change.assert();
}

#[tokio::test]
async fn test_set_rrset_tlsa_two_records_same_owner() {
    let mut server = mockito::Server::new_async().await;
    let change = mock_change(
        &mut server,
        vec![
            r"<Action>UPSERT</Action>".to_string(),
            r"<Type>TLSA</Type>".to_string(),
            r"<Value>3 1 1 aa</Value>".to_string(),
            r"<Value>2 1 1 bb</Value>".to_string(),
        ],
    );

    let provider = setup_provider(server.url());
    let result = provider
        .set_rrset(
            "_25._tcp.mail.example.com",
            DnsRecordType::TLSA,
            300,
            vec![
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xaa],
                }),
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneTa,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xbb],
                }),
            ],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "set_rrset returned: {result:?}");
    change.assert();
}

#[tokio::test]
async fn test_set_rrset_caa() {
    let mut server = mockito::Server::new_async().await;
    let change = mock_change(
        &mut server,
        vec![
            r"<Action>UPSERT</Action>".to_string(),
            r"<Type>CAA</Type>".to_string(),
            r#"0 issue "letsencrypt\.org""#.to_string(),
        ],
    );

    let provider = setup_provider(server.url());
    let result = provider
        .set_rrset(
            "example.com",
            DnsRecordType::CAA,
            3600,
            vec![DnsRecord::CAA(CAARecord::Issue {
                issuer_critical: false,
                name: Some("letsencrypt.org".to_string()),
                options: vec![],
            })],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "set_rrset returned: {result:?}");
    change.assert();
}

#[tokio::test]
async fn test_set_rrset_srv() {
    let mut server = mockito::Server::new_async().await;
    let change = mock_change(
        &mut server,
        vec![
            r"<Action>UPSERT</Action>".to_string(),
            r"<Type>SRV</Type>".to_string(),
            r"<Value>10 5 993 mail\.example\.com\.</Value>".to_string(),
        ],
    );

    let provider = setup_provider(server.url());
    let result = provider
        .set_rrset(
            "_imaps._tcp.example.com",
            DnsRecordType::SRV,
            300,
            vec![DnsRecord::SRV(SRVRecord {
                priority: 10,
                weight: 5,
                port: 993,
                target: "mail.example.com.".to_string(),
            })],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "set_rrset returned: {result:?}");
    change.assert();
}

#[tokio::test]
async fn test_set_rrset_long_txt_is_chunked() {
    let mut server = mockito::Server::new_async().await;
    let change = mock_change(
        &mut server,
        vec![
            r"<Action>UPSERT</Action>".to_string(),
            r"<Type>TXT</Type>".to_string(),
        ],
    );

    let provider = setup_provider(server.url());
    let long_value: String = "x".repeat(400);
    let result = provider
        .set_rrset(
            "selector._domainkey.example.com",
            DnsRecordType::TXT,
            300,
            vec![DnsRecord::TXT(long_value)],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "set_rrset returned: {result:?}");
    change.assert();
}

#[tokio::test]
async fn test_zone_lookup_strips_hostedzone_prefix() {
    let mut server = mockito::Server::new_async().await;
    let zone_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <HostedZones>
    <HostedZone>
      <Id>/hostedzone/{ZONE_ID}</Id>
      <Name>example.com.</Name>
      <CallerReference>ref</CallerReference>
      <Config><PrivateZone>false</PrivateZone></Config>
    </HostedZone>
  </HostedZones>
  <IsTruncated>false</IsTruncated>
  <MaxItems>100</MaxItems>
</ListHostedZonesByNameResponse>"#
    );
    let zone_mock = server
        .mock("GET", "/2013-04-01/hostedzonesbyname")
        .with_status(200)
        .with_header("content-type", "application/xml")
        .with_body(zone_xml)
        .create();
    let change = mock_change(
        &mut server,
        vec![
            r"<Action>UPSERT</Action>".to_string(),
            r"<Value>1\.1\.1\.1</Value>".to_string(),
        ],
    );

    let provider = setup_provider_zone_lookup(server.url());
    let result = provider
        .set_rrset(
            "host.example.com",
            DnsRecordType::A,
            300,
            vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "set_rrset returned: {result:?}");
    zone_mock.assert();
    change.assert();
}

#[tokio::test]
async fn test_session_token_is_signed() {
    let mut server = mockito::Server::new_async().await;
    let change = server
        .mock("POST", change_path().as_str())
        .match_header("x-amz-security-token", "SESSION123")
        .match_body(Matcher::Regex(r"<Action>UPSERT</Action>".to_string()))
        .with_status(200)
        .with_body(change_response_xml())
        .expect(1)
        .create();

    let endpoint = server.url();
    let provider = Route53Provider::new(Route53Config {
        access_key_id: "AKIA_TEST".to_string(),
        secret_access_key: "test_secret".to_string(),
        session_token: Some("SESSION123".to_string()),
        region: Some("us-east-1".to_string()),
        hosted_zone_id: Some(ZONE_ID.to_string()),
        private_zone_only: Some(false),
        endpoint: None,
    })
    .with_endpoint(endpoint);

    let result = provider
        .set_rrset(
            "host.example.com",
            DnsRecordType::A,
            300,
            vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "set_rrset returned: {result:?}");
    change.assert();
}

#[tokio::test]
async fn test_unauthorized_response_maps_to_error_unauthorized() {
    let mut server = mockito::Server::new_async().await;
    let _ = server
        .mock("POST", change_path().as_str())
        .with_status(401)
        .with_body("<Error><Code>InvalidSignature</Code></Error>")
        .create();

    let provider = setup_provider(server.url());
    let result = provider
        .set_rrset(
            "host.example.com",
            DnsRecordType::A,
            300,
            vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
            "example.com",
        )
        .await;

    assert!(
        matches!(result, Err(Error::Unauthorized)),
        "expected Unauthorized, got {result:?}"
    );
}

#[tokio::test]
async fn test_list_rrset_filters_to_requested_type_only() {
    let mut server = mockito::Server::new_async().await;
    let body = list_response_xml(&format!(
        "{}{}",
        rrset_xml("host.example.com.", "A", 300, &["1.1.1.1"]),
        rrset_xml("host.example.com.", "AAAA", 300, &["::1"]),
    ));
    let _list = mock_list(&mut server, "host.example.com.", "A", body);

    let provider = setup_provider(server.url());
    let result = provider
        .list_rrset("host.example.com", DnsRecordType::A, "example.com")
        .await
        .unwrap();
    assert_eq!(result, vec![DnsRecord::A("1.1.1.1".parse().unwrap())]);
}

#[tokio::test]
async fn test_set_rrset_txt_with_quotes() {
    let mut server = mockito::Server::new_async().await;
    let change = mock_change(
        &mut server,
        vec![
            r"<Action>UPSERT</Action>".to_string(),
            r"<Type>TXT</Type>".to_string(),
        ],
    );

    let provider = setup_provider(server.url());
    let result = provider
        .set_rrset(
            "quoted.example.com",
            DnsRecordType::TXT,
            300,
            vec![DnsRecord::TXT(r#"with "quote" inside"#.to_string())],
            "example.com",
        )
        .await;

    assert!(result.is_ok(), "set_rrset returned: {result:?}");
    change.assert();
}

#[tokio::test]
async fn test_add_to_rrset_type_validation() {
    let mut server = mockito::Server::new_async().await;
    let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

    let provider = setup_provider(server.url());
    let result = provider
        .add_to_rrset(
            "host.example.com",
            DnsRecordType::A,
            300,
            vec![DnsRecord::TXT("nope".to_string())],
            "example.com",
        )
        .await;

    assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
}

#[tokio::test]
async fn test_remove_from_rrset_type_validation() {
    let mut server = mockito::Server::new_async().await;
    let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

    let provider = setup_provider(server.url());
    let result = provider
        .remove_from_rrset(
            "host.example.com",
            DnsRecordType::A,
            vec![DnsRecord::TXT("nope".to_string())],
            "example.com",
        )
        .await;

    assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
}

#[tokio::test]
#[ignore = "Requires AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, ROUTE53_ORIGIN and ROUTE53_HOSTED_ZONE_ID"]
async fn integration_test() {
    let access_key = std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default();
    let secret = std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();
    let origin = std::env::var("ROUTE53_ORIGIN").unwrap_or_default();
    let hosted_zone_id = std::env::var("ROUTE53_HOSTED_ZONE_ID").ok();
    assert!(!access_key.is_empty(), "Set AWS_ACCESS_KEY_ID");
    assert!(!secret.is_empty(), "Set AWS_SECRET_ACCESS_KEY");
    assert!(!origin.is_empty(), "Set ROUTE53_ORIGIN (e.g. example.com)");

    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let host = format!("dnsupdate-poc-{run_id}.{origin}");

    let provider = Route53Provider::new(Route53Config {
        access_key_id: access_key,
        secret_access_key: secret,
        session_token: None,
        region: Some("us-east-1".to_string()),
        hosted_zone_id,
        private_zone_only: Some(false),
        endpoint: None,
    });

    provider
        .set_rrset(
            host.as_str(),
            DnsRecordType::A,
            60,
            vec![
                DnsRecord::A("192.0.2.1".parse().unwrap()),
                DnsRecord::A("192.0.2.2".parse().unwrap()),
            ],
            origin.as_str(),
        )
        .await
        .expect("set_rrset two A");
    let listed = provider
        .list_rrset(host.as_str(), DnsRecordType::A, origin.as_str())
        .await
        .expect("list_rrset");
    assert_eq!(listed.len(), 2);

    provider
        .add_to_rrset(
            host.as_str(),
            DnsRecordType::A,
            60,
            vec![DnsRecord::A("192.0.2.3".parse().unwrap())],
            origin.as_str(),
        )
        .await
        .expect("add_to_rrset");
    let listed = provider
        .list_rrset(host.as_str(), DnsRecordType::A, origin.as_str())
        .await
        .expect("list_rrset after add");
    assert_eq!(listed.len(), 3);

    provider
        .remove_from_rrset(
            host.as_str(),
            DnsRecordType::A,
            vec![DnsRecord::A("192.0.2.2".parse().unwrap())],
            origin.as_str(),
        )
        .await
        .expect("remove_from_rrset");
    let listed = provider
        .list_rrset(host.as_str(), DnsRecordType::A, origin.as_str())
        .await
        .expect("list_rrset after remove");
    assert_eq!(listed.len(), 2);

    provider
        .set_rrset(host.as_str(), DnsRecordType::A, 60, vec![], origin.as_str())
        .await
        .expect("set_rrset empty");
    let listed = provider
        .list_rrset(host.as_str(), DnsRecordType::A, origin.as_str())
        .await
        .expect("list_rrset after delete");
    assert!(listed.is_empty());
}
