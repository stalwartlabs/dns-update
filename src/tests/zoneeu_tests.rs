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

#[cfg(test)]
mod tests {
    use crate::providers::zoneeu::ZoneEuProvider;
    use crate::{
        CAARecord, DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord, TLSARecord, TlsaCertUsage,
        TlsaMatching, TlsaSelector,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const ZONE_JSON: &str = r#"[
        {"resource_url": "https://api.zone.eu/v2/dns/example.com", "identificator": "example.com", "active": true, "ipv6": false}
    ]"#;

    fn setup_provider(endpoint: &str) -> ZoneEuProvider {
        ZoneEuProvider::new("user", "key", Some(Duration::from_secs(2)))
            .with_endpoint(endpoint.to_string())
    }

    fn basic_auth_value() -> String {
        use encodify::base64::STANDARD as BASE64;
        format!("Basic {}", BASE64.encode(b"user:key"))
    }

    fn mock_zone(server: &mut ServerGuard) -> Mock {
        server
            .mock("GET", "/dns/example.com")
            .match_header("authorization", basic_auth_value().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ZONE_JSON)
            .create()
    }

    fn mock_list(server: &mut ServerGuard, segment: &str, body: serde_json::Value) -> Mock {
        server
            .mock("GET", format!("/dns/example.com/{segment}").as_str())
            .match_header("authorization", basic_auth_value().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    fn mock_post(server: &mut ServerGuard, segment: &str, body: serde_json::Value) -> Mock {
        server
            .mock("POST", format!("/dns/example.com/{segment}").as_str())
            .match_header("authorization", basic_auth_value().as_str())
            .match_body(Matcher::Json(body))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id": "1", "name": "www.example.com", "destination": "1.2.3.4"}]"#)
            .create()
    }

    fn mock_delete(server: &mut ServerGuard, segment: &str, id: &str) -> Mock {
        server
            .mock(
                "DELETE",
                format!("/dns/example.com/{segment}/{id}").as_str(),
            )
            .match_header("authorization", basic_auth_value().as_str())
            .with_status(204)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "a", json!([]));
        let create = mock_post(
            &mut server,
            "a",
            json!({
                "name": "www.example.com",
                "destination": "1.2.3.4",
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(
            &mut server,
            "a",
            json!([
                {"id": "1", "name": "www.example.com", "destination": "1.2.3.4"}
            ]),
        );
        let _no_post = server.mock("POST", "/dns/example.com/a").expect(0).create();
        let _no_delete = server
            .mock("DELETE", Matcher::Regex("^/dns/example.com/a/".into()))
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_creates_missing() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(
            &mut server,
            "a",
            json!([
                {"id": "11", "name": "host.example.com", "destination": "1.1.1.1"},
                {"id": "22", "name": "host.example.com", "destination": "9.9.9.9"},
                {"id": "33", "name": "other.example.com", "destination": "7.7.7.7"}
            ]),
        );
        let delete_stale = mock_delete(&mut server, "a", "22");
        let create_new = mock_post(
            &mut server,
            "a",
            json!({
                "name": "host.example.com",
                "destination": "8.8.8.8",
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("8.8.8.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_all_at_owner_and_type() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(
            &mut server,
            "txt",
            json!([
                {"id": "33", "name": "gone.example.com", "destination": "first"},
                {"id": "44", "name": "gone.example.com", "destination": "second"},
                {"id": "55", "name": "stay.example.com", "destination": "third"}
            ]),
        );
        let delete_first = mock_delete(&mut server, "txt", "33");
        let delete_second = mock_delete(&mut server, "txt", "44");
        let _no_delete = server
            .mock("DELETE", "/dns/example.com/txt/55")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "gone.example.com",
                DnsRecordType::TXT,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        delete_first.assert();
        delete_second.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_values_already_present() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(
            &mut server,
            "txt",
            json!([
                {"id": "7", "name": "_acme-challenge.example.com", "destination": "token-one"}
            ]),
        );
        let create = mock_post(
            &mut server,
            "txt",
            json!({
                "name": "_acme-challenge.example.com",
                "destination": "token-two",
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                60,
                vec![
                    DnsRecord::TXT("token-one".to_string()),
                    DnsRecord::TXT("token-two".to_string()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_value() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(
            &mut server,
            "txt",
            json!([
                {"id": "7", "name": "_acme-challenge.example.com", "destination": "token-one"},
                {"id": "8", "name": "_acme-challenge.example.com", "destination": "token-two"}
            ]),
        );
        let delete = mock_delete(&mut server, "txt", "8");
        let _no_delete = server
            .mock("DELETE", "/dns/example.com/txt/7")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("token-two".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_sends_priority() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "mx", json!([]));
        let create = mock_post(
            &mut server,
            "mx",
            json!({
                "name": "example.com",
                "destination": "mail.example.com",
                "priority": 10,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                300,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com.".to_string(),
                    priority: 10,
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_sends_components() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "srv", json!([]));
        let create = mock_post(
            &mut server,
            "srv",
            json!({
                "name": "_sip._tcp.example.com",
                "destination": "sip.example.com",
                "priority": 10,
                "weight": 20,
                "port": 5060,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                300,
                vec![DnsRecord::SRV(SRVRecord {
                    target: "sip.example.com".to_string(),
                    priority: 10,
                    weight: 20,
                    port: 5060,
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_sends_flag_and_tag() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "caa", json!([]));
        let create = mock_post(
            &mut server,
            "caa",
            json!({
                "name": "example.com",
                "destination": "letsencrypt.org",
                "flag": 0,
                "tag": "issue",
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::CAA,
                300,
                vec![DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".to_string()),
                    options: vec![],
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_sends_components() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "tlsa", json!([]));
        let create = mock_post(
            &mut server,
            "tlsa",
            json!({
                "name": "_443._tcp.example.com",
                "destination": "abcdef",
                "certificate_usage": 3,
                "selector": 1,
                "matching_type": 1,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_443._tcp.example.com",
                DnsRecordType::TLSA,
                300,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xab, 0xcd, 0xef],
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_records_and_ignores_other_owners() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(
            &mut server,
            "mx",
            json!([
                {"id": "1", "name": "example.com", "destination": "mail.example.com", "priority": 10},
                {"id": "2", "name": "other.example.com", "destination": "spam.example.com", "priority": 20}
            ]),
        );

        let provider = setup_provider(server.url().as_str());
        let records = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .unwrap();

        assert_eq!(
            records,
            vec![DnsRecord::MX(MXRecord {
                exchange: "mail.example.com".to_string(),
                priority: 10,
            })]
        );
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_empty_when_type_is_absent() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "caa", json!([]));

        let provider = setup_provider(server.url().as_str());
        let records = provider
            .list_rrset("example.com", DnsRecordType::CAA, "example.com")
            .await
            .unwrap();

        assert!(records.is_empty(), "list_rrset returned: {records:?}");
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_zone_is_resolved_by_walking_up_the_origin() {
        let mut server = mockito::Server::new_async().await;
        let missing_zone = server
            .mock("GET", "/dns/sub.example.com")
            .with_status(404)
            .create();
        let zone = mock_zone(&mut server);
        let list = mock_list(
            &mut server,
            "a",
            json!([
                {"id": "5", "name": "www.sub.example.com", "destination": "1.2.3.4"}
            ]),
        );

        let provider = setup_provider(server.url().as_str());
        let records = provider
            .list_rrset("www.sub.example.com", DnsRecordType::A, "sub.example.com")
            .await
            .unwrap();

        assert_eq!(records, vec![DnsRecord::A("1.2.3.4".parse().unwrap())]);
        missing_zone.assert();
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_string_record_id_is_used_in_the_delete_path() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(
            &mut server,
            "a",
            json!([
                {"id": "4321", "name": "www.example.com", "destination": "1.2.3.4"}
            ]),
        );
        let delete = mock_delete(&mut server, "a", "4321");

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_numeric_record_id_is_used_in_the_delete_path() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(
            &mut server,
            "srv",
            json!([
                {"id": 133232, "name": "_sip._tcp.example.com", "destination": "sip.example.com",
                 "priority": 10, "weight": 20, "port": 5060}
            ]),
        );
        let delete = mock_delete(&mut server, "srv", "133232");

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_record_type_mismatch_is_rejected() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = server.mock("GET", "/dns/example.com/a").expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not an address".to_string())],
                "example.com",
            )
            .await;

        match result {
            Err(Error::Api(message)) => {
                assert!(message.contains("RRSet record type mismatch"), "{message}")
            }
            other => panic!("set_rrset returned: {other:?}"),
        }
        zone.assert();
        list.assert();
    }

    async fn round_trip(
        provider: &ZoneEuProvider,
        origin: &str,
        name: &str,
        record_type: DnsRecordType,
        input: Vec<DnsRecord>,
        expected: Vec<DnsRecord>,
    ) {
        provider
            .set_rrset(name, record_type, 300, input, origin)
            .await
            .unwrap_or_else(|err| panic!("{record_type} set_rrset: {err}"));
        let listed = provider
            .list_rrset(name, record_type, origin)
            .await
            .unwrap_or_else(|err| panic!("{record_type} list_rrset: {err}"));
        assert_eq!(listed, expected, "{record_type} round trip");

        provider
            .set_rrset(name, record_type, 300, vec![], origin)
            .await
            .unwrap_or_else(|err| panic!("{record_type} delete: {err}"));
        assert!(
            provider
                .list_rrset(name, record_type, origin)
                .await
                .unwrap()
                .is_empty(),
            "{record_type} was not deleted"
        );
    }

    #[tokio::test]
    #[ignore = "Requires ZONE_EU_USERNAME, ZONE_EU_API_KEY and ZONE_EU_ZONE"]
    async fn integration_test() {
        let username = std::env::var("ZONE_EU_USERNAME").unwrap_or_default();
        let api_key = std::env::var("ZONE_EU_API_KEY").unwrap_or_default();
        let origin = std::env::var("ZONE_EU_ZONE").unwrap_or_default();
        assert!(!username.is_empty(), "Set ZONE_EU_USERNAME");
        assert!(!api_key.is_empty(), "Set ZONE_EU_API_KEY");
        assert!(!origin.is_empty(), "Set ZONE_EU_ZONE (e.g. example.com)");

        // All test owners live under a unique prefix so concurrent runs from
        // different machines won't trample each other. Every RRSet is deleted
        // as soon as it has been read back.
        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let label = |kind: &str| format!("dnsupdate-poc-{run_id}-{kind}.{origin}");

        let provider = ZoneEuProvider::new(&username, &api_key, Some(Duration::from_secs(30)));

        round_trip(
            &provider,
            &origin,
            &label("a"),
            DnsRecordType::A,
            vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
            vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
        )
        .await;

        round_trip(
            &provider,
            &origin,
            &label("aaaa"),
            DnsRecordType::AAAA,
            vec![DnsRecord::AAAA("2001:db8::1".parse().unwrap())],
            vec![DnsRecord::AAAA("2001:db8::1".parse().unwrap())],
        )
        .await;

        round_trip(
            &provider,
            &origin,
            &label("cname"),
            DnsRecordType::CNAME,
            vec![DnsRecord::CNAME("target.example.com.".to_string())],
            vec![DnsRecord::CNAME("target.example.com".to_string())],
        )
        .await;

        round_trip(
            &provider,
            &origin,
            &label("mx"),
            DnsRecordType::MX,
            vec![DnsRecord::MX(MXRecord {
                exchange: "mail.example.com.".to_string(),
                priority: 10,
            })],
            vec![DnsRecord::MX(MXRecord {
                exchange: "mail.example.com".to_string(),
                priority: 10,
            })],
        )
        .await;

        round_trip(
            &provider,
            &origin,
            &format!("_sip._tcp.{}", label("srv")),
            DnsRecordType::SRV,
            vec![DnsRecord::SRV(SRVRecord {
                target: "sip.example.com.".to_string(),
                priority: 10,
                weight: 20,
                port: 5060,
            })],
            vec![DnsRecord::SRV(SRVRecord {
                target: "sip.example.com".to_string(),
                priority: 10,
                weight: 20,
                port: 5060,
            })],
        )
        .await;

        round_trip(
            &provider,
            &origin,
            &label("caa"),
            DnsRecordType::CAA,
            vec![DnsRecord::CAA(CAARecord::Issue {
                issuer_critical: false,
                name: Some("letsencrypt.org".to_string()),
                options: vec![],
            })],
            vec![DnsRecord::CAA(CAARecord::Issue {
                issuer_critical: false,
                name: Some("letsencrypt.org".to_string()),
                options: vec![],
            })],
        )
        .await;

        round_trip(
            &provider,
            &origin,
            &format!("_443._tcp.{}", label("tlsa")),
            DnsRecordType::TLSA,
            vec![DnsRecord::TLSA(TLSARecord {
                cert_usage: TlsaCertUsage::DaneEe,
                selector: TlsaSelector::Spki,
                matching: TlsaMatching::Sha256,
                cert_data: vec![0xab; 32],
            })],
            vec![DnsRecord::TLSA(TLSARecord {
                cert_usage: TlsaCertUsage::DaneEe,
                selector: TlsaSelector::Spki,
                matching: TlsaMatching::Sha256,
                cert_data: vec![0xab; 32],
            })],
        )
        .await;

        let txt = label("txt");
        provider
            .set_rrset(
                txt.as_str(),
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("first".to_string())],
                origin.as_str(),
            )
            .await
            .unwrap();
        provider
            .add_to_rrset(
                txt.as_str(),
                DnsRecordType::TXT,
                300,
                vec![
                    DnsRecord::TXT("first".to_string()),
                    DnsRecord::TXT("second".to_string()),
                ],
                origin.as_str(),
            )
            .await
            .unwrap();
        let mut listed = provider
            .list_rrset(txt.as_str(), DnsRecordType::TXT, origin.as_str())
            .await
            .unwrap();
        listed.sort_by_key(|record| record.to_string());
        assert_eq!(
            listed,
            vec![
                DnsRecord::TXT("first".to_string()),
                DnsRecord::TXT("second".to_string())
            ],
            "add_to_rrset must skip the value that is already present"
        );

        provider
            .remove_from_rrset(
                txt.as_str(),
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("first".to_string())],
                origin.as_str(),
            )
            .await
            .unwrap();
        assert_eq!(
            provider
                .list_rrset(txt.as_str(), DnsRecordType::TXT, origin.as_str())
                .await
                .unwrap(),
            vec![DnsRecord::TXT("second".to_string())]
        );

        let long_txt = "v=DKIM1; k=rsa; p=".to_string() + &"A".repeat(400);
        provider
            .set_rrset(
                txt.as_str(),
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(long_txt.clone())],
                origin.as_str(),
            )
            .await
            .unwrap();
        assert_eq!(
            provider
                .list_rrset(txt.as_str(), DnsRecordType::TXT, origin.as_str())
                .await
                .unwrap(),
            vec![DnsRecord::TXT(long_txt)],
            "long TXT values are stored verbatim"
        );

        provider
            .set_rrset(
                txt.as_str(),
                DnsRecordType::TXT,
                300,
                vec![],
                origin.as_str(),
            )
            .await
            .unwrap();
        assert!(
            provider
                .list_rrset(txt.as_str(), DnsRecordType::TXT, origin.as_str())
                .await
                .unwrap()
                .is_empty()
        );
    }
}
