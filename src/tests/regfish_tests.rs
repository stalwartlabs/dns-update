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
    use crate::{
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, SRVRecord, TLSARecord,
        TlsaCertUsage, TlsaMatching, TlsaSelector, providers::regfish::RegfishProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> RegfishProvider {
        RegfishProvider::new("regfish-mock-api-key", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn mock_zone_found(server: &mut ServerGuard, zone: &str) -> Mock {
        server
            .mock("GET", format!("/dns/zones/{zone}").as_str())
            .match_header("x-api-key", "regfish-mock-api-key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"code":0,"response":{"domain":"example.com"}}"#)
            .create()
    }

    fn mock_zone_missing(server: &mut ServerGuard, zone: &str) -> Mock {
        server
            .mock("GET", format!("/dns/zones/{zone}").as_str())
            .match_header("x-api-key", "regfish-mock-api-key")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":false,"code":13001,"message":"zone not found"}"#)
            .create()
    }

    fn mock_list_records(server: &mut ServerGuard, zone: &str, records: serde_json::Value) -> Mock {
        mock_zone_found(server, zone);
        let body = json!({
            "success": true,
            "code": 0,
            "response": records,
        });
        server
            .mock("GET", format!("/dns/{zone}/rr").as_str())
            .match_header("x-api-key", "regfish-mock-api-key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body.to_string())
            .create()
    }

    fn mock_create_record(server: &mut ServerGuard, expected_body: serde_json::Value) -> Mock {
        server
            .mock("POST", "/dns/rr")
            .match_header("x-api-key", "regfish-mock-api-key")
            .match_body(Matcher::Json(expected_body))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"code":0,"response":{"id":1}}"#)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_records(&mut server, "example.com", json!([]));

        let create = mock_create_record(
            &mut server,
            json!({
                "type": "A",
                "name": "www.example.com.",
                "data": "1.2.3.4",
                "ttl": 300,
            }),
        );

        let provider = setup_provider(server.url());
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
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_records(
            &mut server,
            "example.com",
            json!([
                {"id": 1, "type": "A", "name": "www.example.com.", "data": "1.2.3.4", "ttl": 300},
            ]),
        );
        let no_create = server.mock("POST", "/dns/rr").expect(0).create();
        let no_patch = server
            .mock("PATCH", Matcher::Regex(r"^/dns/rr/\d+$".to_string()))
            .expect(0)
            .create();
        let no_delete = server
            .mock("DELETE", Matcher::Regex(r"^/dns/rr/\d+$".to_string()))
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
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
        list.assert();
        no_create.assert();
        no_patch.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_stale_creates_new_and_updates_ttl() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_records(
            &mut server,
            "example.com",
            json!([
                {"id": 11, "type": "A", "name": "host.example.com.", "data": "1.1.1.1", "ttl": 300},
                {"id": 22, "type": "A", "name": "host.example.com.", "data": "9.9.9.9", "ttl": 300},
                {"id": 33, "type": "A", "name": "host.example.com.", "data": "8.8.8.8", "ttl": 60},
            ]),
        );

        let delete_stale = server
            .mock("DELETE", "/dns/rr/22")
            .match_header("x-api-key", "regfish-mock-api-key")
            .with_status(200)
            .with_body(r#"{"success":true,"code":0,"response":null}"#)
            .create();
        let delete_stale_2 = server
            .mock("DELETE", "/dns/rr/11")
            .match_header("x-api-key", "regfish-mock-api-key")
            .with_status(200)
            .with_body(r#"{"success":true,"code":0,"response":null}"#)
            .create();

        let patch_ttl = server
            .mock("PATCH", "/dns/rr/33")
            .match_body(Matcher::Json(json!({
                "type": "A",
                "name": "host.example.com.",
                "data": "8.8.8.8",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(r#"{"success":true,"code":0,"response":{"id":33}}"#)
            .create();

        let create_new = mock_create_record(
            &mut server,
            json!({
                "type": "A",
                "name": "host.example.com.",
                "data": "7.7.7.7",
                "ttl": 300,
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("8.8.8.8".parse().unwrap()),
                    DnsRecord::A("7.7.7.7".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        delete_stale.assert();
        delete_stale_2.assert();
        patch_ttl.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_with_empty_records_deletes_rrset() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_records(
            &mut server,
            "example.com",
            json!([
                {"id": 1, "type": "TXT", "name": "www.example.com.", "data": "hello", "ttl": 300},
                {"id": 2, "type": "A", "name": "www.example.com.", "data": "1.2.3.4", "ttl": 300},
            ]),
        );
        let delete = server
            .mock("DELETE", "/dns/rr/1")
            .with_status(200)
            .with_body(r#"{"success":true,"code":0,"response":null}"#)
            .create();
        let no_create = server.mock("POST", "/dns/rr").expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        delete.assert();
        no_create.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_creates_only_missing_records() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_records(
            &mut server,
            "example.com",
            json!([
                {"id": 1, "type": "A", "name": "www.example.com.", "data": "1.2.3.4", "ttl": 300},
            ]),
        );
        let create = mock_create_record(
            &mut server,
            json!({
                "type": "A",
                "name": "www.example.com.",
                "data": "5.6.7.8",
                "ttl": 600,
            }),
        );
        let no_delete = server
            .mock("DELETE", Matcher::Regex(r"^/dns/rr/\d+$".to_string()))
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![
                    DnsRecord::A("1.2.3.4".parse().unwrap()),
                    DnsRecord::A("5.6.7.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        list.assert();
        create.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_records() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_records(
            &mut server,
            "example.com",
            json!([
                {"id": 1, "type": "A", "name": "www.example.com.", "data": "1.2.3.4", "ttl": 300},
                {"id": 2, "type": "A", "name": "www.example.com.", "data": "5.6.7.8", "ttl": 300},
            ]),
        );
        let delete = server
            .mock("DELETE", "/dns/rr/1")
            .with_status(200)
            .with_body(r#"{"success":true,"code":0,"response":null}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_tolerates_already_deleted_record() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_records(
            &mut server,
            "example.com",
            json!([
                {"id": 1, "type": "A", "name": "www.example.com.", "data": "1.2.3.4", "ttl": 300},
            ]),
        );
        let delete = server
            .mock("DELETE", "/dns/rr/1")
            .with_status(404)
            .with_body(r#"{"success":false,"message":"DNS zone or records not found","error":"DNS zone or records not found"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_filtered_records() {
        let mut server = mockito::Server::new_async().await;
        let records = json!([
                {"id": 140, "type": "A", "name": "host.example.com.", "data": "1.1.1.1", "ttl": 300},
                {"id": 141, "type": "A", "name": "host.example.com.", "data": "2.2.2.2", "ttl": 300},
                {"id": 142, "type": "TXT", "name": "host.example.com.", "data": "ignored-txt", "ttl": 300},
                {"id": 143, "type": "A", "name": "other.example.com.", "data": "9.9.9.9", "ttl": 300},
                {"id": 144, "type": "MX", "name": "@", "data": "mx1.example.com.", "priority": 10, "ttl": 3600},
        ]);
        let list = mock_list_records(&mut server, "example.com", records.clone());
        let list_mx = mock_list_records(&mut server, "example.com", records);

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");

        assert_eq!(result.len(), 2, "expected 2 A records, got {result:?}");
        assert!(result.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));

        let mx = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .expect("list_rrset MX failed");
        assert_eq!(
            mx,
            vec![DnsRecord::MX(MXRecord {
                exchange: "mx1.example.com".to_string(),
                priority: 10,
            })]
        );
        list.assert();
        list_mx.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_sends_priority_for_mx_records() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_records(&mut server, "example.com", json!([]));
        let create = mock_create_record(
            &mut server,
            json!({
                "type": "MX",
                "name": "example.com.",
                "data": "mx1.example.com.",
                "ttl": 3600,
                "priority": 10,
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mx1.example.com".to_string(),
                    priority: 10,
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_matches_apex_record_returned_as_at() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_records(
            &mut server,
            "example.com",
            json!([
                {"id": 7, "type": "A", "name": "@", "data": "1.2.3.4", "ttl": 300},
            ]),
        );
        let no_create = server.mock("POST", "/dns/rr").expect(0).create();
        let no_delete = server
            .mock("DELETE", Matcher::Regex(r"^/dns/rr/\d+$".to_string()))
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        no_create.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_sends_structured_fields_for_caa() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_records(&mut server, "example.com", json!([]));
        let create = mock_create_record(
            &mut server,
            json!({
                "type": "CAA",
                "name": "example.com.",
                "data": "letsencrypt.org",
                "ttl": 300,
                "flags": 0,
                "tag": "issue",
            }),
        );

        let provider = setup_provider(server.url());
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
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_sends_raw_txt_data() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_records(&mut server, "example.com", json!([]));
        let create = mock_create_record(
            &mut server,
            json!({
                "type": "TXT",
                "name": "_dmarc.example.com.",
                "data": "v=DMARC1; p=none",
                "ttl": 300,
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_dmarc.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("v=DMARC1; p=none".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_unsupported_record_types_are_rejected_without_requests() {
        let mut server = mockito::Server::new_async().await;
        for method in ["GET", "POST", "PATCH", "PUT", "DELETE"] {
            server.mock(method, Matcher::Any).expect(0).create();
        }

        let provider = setup_provider(server.url());
        let cases: Vec<(DnsRecordType, DnsRecord)> = vec![(
            DnsRecordType::NS,
            DnsRecord::NS("ns2.example.com".to_string()),
        )];

        for (record_type, record) in cases {
            let set = provider
                .set_rrset(
                    "www.example.com",
                    record_type,
                    300,
                    vec![record.clone()],
                    "example.com",
                )
                .await;
            assert!(
                matches!(set, Err(Error::Unsupported(_))),
                "set_rrset {record_type:?} should be Unsupported, got {set:?}"
            );

            let add = provider
                .add_to_rrset(
                    "www.example.com",
                    record_type,
                    300,
                    vec![record.clone()],
                    "example.com",
                )
                .await;
            assert!(
                matches!(add, Err(Error::Unsupported(_))),
                "add_to_rrset {record_type:?} should be Unsupported, got {add:?}"
            );

            let remove = provider
                .remove_from_rrset("www.example.com", record_type, vec![record], "example.com")
                .await;
            assert!(
                matches!(remove, Err(Error::Unsupported(_))),
                "remove_from_rrset {record_type:?} should be Unsupported, got {remove:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_set_rrset_sends_structured_fields_for_srv() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_records(&mut server, "example.com", json!([]));
        let create = mock_create_record(
            &mut server,
            json!({
                "type": "SRV",
                "name": "_sip._tcp.example.com.",
                "data": "sip.example.com.",
                "ttl": 300,
                "priority": 10,
                "weight": 5,
                "port": 5060,
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                300,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 5060,
                    target: "sip.example.com".to_string(),
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_sends_structured_fields_for_tlsa() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_records(&mut server, "example.com", json!([]));
        let create = mock_create_record(
            &mut server,
            json!({
                "type": "TLSA",
                "name": "_25._tcp.mail.example.com.",
                "data": "ab".repeat(32),
                "ttl": 300,
                "usage": 3,
                "selector": 1,
                "matching_type": 1,
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xab; 32],
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_matches_srv_and_tlsa_returned_with_structured_fields() {
        let mut server = mockito::Server::new_async().await;
        let records = json!([
            {"id": 51, "type": "SRV", "name": "_sip._tcp.example.com.", "data": "sip.example.com.", "priority": 10, "weight": 5, "port": 5060, "ttl": 300},
            {"id": 52, "type": "TLSA", "name": "_25._tcp.mail.example.com.", "data": "ab".repeat(32), "usage": 3, "selector": 1, "matching_type": 1, "ttl": 300},
        ]);
        let list_srv = mock_list_records(&mut server, "example.com", records.clone());
        let list_tlsa = mock_list_records(&mut server, "example.com", records);
        let no_create = server.mock("POST", "/dns/rr").expect(0).create();
        let no_patch = server
            .mock("PATCH", Matcher::Regex(r"^/dns/rr/\d+$".to_string()))
            .expect(0)
            .create();
        let no_delete = server
            .mock("DELETE", Matcher::Regex(r"^/dns/rr/\d+$".to_string()))
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let srv = provider
            .set_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                300,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 5060,
                    target: "sip.example.com".to_string(),
                })],
                "example.com",
            )
            .await;
        assert!(srv.is_ok(), "set_rrset SRV returned: {srv:?}");

        let tlsa = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xab; 32],
                })],
                "example.com",
            )
            .await;
        assert!(tlsa.is_ok(), "set_rrset TLSA returned: {tlsa:?}");

        list_srv.assert();
        list_tlsa.assert();
        no_create.assert();
        no_patch.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn test_origin_subdomain_walks_up_to_hosted_zone() {
        let mut server = mockito::Server::new_async().await;
        let zone_miss = mock_zone_missing(&mut server, "sub.example.com");
        let list = mock_list_records(&mut server, "example.com", json!([]));
        let create = mock_create_record(
            &mut server,
            json!({
                "type": "A",
                "name": "host.sub.example.com.",
                "data": "1.2.3.4",
                "ttl": 300,
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.sub.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "sub.example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone_miss.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_unhosted_origin_returns_not_found() {
        let mut server = mockito::Server::new_async().await;
        mock_zone_missing(&mut server, "ghost.example.com");
        mock_zone_missing(&mut server, "example.com");
        mock_zone_missing(&mut server, "com");
        let no_create = server.mock("POST", "/dns/rr").expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.ghost.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "ghost.example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::NotFound)),
            "expected NotFound, got {result:?}"
        );
        no_create.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_maps_to_error() {
        let mut server = mockito::Server::new_async().await;
        let unauth = server
            .mock("GET", "/dns/zones/example.com")
            .match_header("x-api-key", "regfish-mock-api-key")
            .with_status(401)
            .with_body(r#"{"success":false,"message":"Unauthorized","error":"Unauthorized"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
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
        unauth.assert();
    }

    #[tokio::test]
    async fn test_api_error_envelope_maps_to_error() {
        let mut server = mockito::Server::new_async().await;
        mock_zone_found(&mut server, "example.com");
        let list = server
            .mock("GET", "/dns/example.com/rr")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":false,"message":"zone not found","error":"zone not found"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Api error, got {result:?}"
        );
        list.assert();
    }

    #[test]
    fn provider_creation() {
        let provider = RegfishProvider::new("regfish-mock-api-key", Some(Duration::from_secs(1)));

        assert!(provider.is_ok());
    }

    #[test]
    fn provider_creation_rejects_empty_api_key() {
        let provider = RegfishProvider::new("", Some(Duration::from_secs(1)));

        assert!(provider.is_err());
    }

    #[test]
    fn dns_updater_creation() {
        let updater =
            DnsUpdater::new_regfish("regfish-mock-api-key", Some(Duration::from_secs(30)));

        assert!(
            matches!(updater, Ok(DnsUpdater::Regfish(..))),
            "Expected Regfish updater to provide a Regfish provider"
        );
    }

    #[tokio::test]
    #[ignore = "Requires REGFISH_API_KEY and REGFISH_ORIGIN"]
    async fn integration_test() {
        let api_key = std::env::var("REGFISH_API_KEY").unwrap_or_default();
        let origin = std::env::var("REGFISH_ORIGIN").unwrap_or_default();
        assert!(!api_key.is_empty(), "Set REGFISH_API_KEY");
        assert!(!origin.is_empty(), "Set REGFISH_ORIGIN (e.g. example.com)");

        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let label = format!("dnsupdate-poc-{run_id}.{origin}");

        let updater = DnsUpdater::new_regfish(&api_key, Some(Duration::from_secs(30))).unwrap();

        updater
            .set_rrset(
                &label,
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                &origin,
            )
            .await
            .unwrap_or_else(|err| panic!("set_rrset failed: {err}"));

        let listed = updater
            .list_rrset(&label, DnsRecordType::A, &origin)
            .await
            .unwrap_or_else(|err| panic!("list_rrset failed: {err}"));
        assert!(
            listed.contains(&DnsRecord::A("192.0.2.1".parse().unwrap())),
            "expected created A record in {listed:?}"
        );

        updater
            .set_rrset(&label, DnsRecordType::A, 300, vec![], &origin)
            .await
            .unwrap_or_else(|err| panic!("cleanup set_rrset failed: {err}"));

        let listed = updater
            .list_rrset(&label, DnsRecordType::A, &origin)
            .await
            .unwrap_or_else(|err| panic!("list_rrset after cleanup failed: {err}"));
        assert!(listed.is_empty(), "expected empty RRSet, got {listed:?}");

        let srv_label = format!("_dnsupdate-poc-{run_id}._tcp.{origin}");
        let srv = DnsRecord::SRV(SRVRecord {
            priority: 10,
            weight: 5,
            port: 5060,
            target: label.clone(),
        });
        updater
            .set_rrset(
                &srv_label,
                DnsRecordType::SRV,
                300,
                vec![srv.clone()],
                &origin,
            )
            .await
            .unwrap_or_else(|err| panic!("set_rrset SRV failed: {err}"));
        let listed = updater
            .list_rrset(&srv_label, DnsRecordType::SRV, &origin)
            .await
            .unwrap_or_else(|err| panic!("list_rrset SRV failed: {err}"));
        assert!(
            listed.contains(&srv),
            "expected created SRV record in {listed:?}"
        );
        updater
            .set_rrset(&srv_label, DnsRecordType::SRV, 300, vec![], &origin)
            .await
            .unwrap_or_else(|err| panic!("cleanup set_rrset SRV failed: {err}"));

        let tlsa_label = format!("_25._tcp.dnsupdate-poc-{run_id}.{origin}");
        let tlsa = DnsRecord::TLSA(TLSARecord {
            cert_usage: TlsaCertUsage::DaneEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            cert_data: vec![0xab; 32],
        });
        updater
            .set_rrset(
                &tlsa_label,
                DnsRecordType::TLSA,
                300,
                vec![tlsa.clone()],
                &origin,
            )
            .await
            .unwrap_or_else(|err| panic!("set_rrset TLSA failed: {err}"));
        let listed = updater
            .list_rrset(&tlsa_label, DnsRecordType::TLSA, &origin)
            .await
            .unwrap_or_else(|err| panic!("list_rrset TLSA failed: {err}"));
        assert!(
            listed.contains(&tlsa),
            "expected created TLSA record in {listed:?}"
        );
        updater
            .set_rrset(&tlsa_label, DnsRecordType::TLSA, 300, vec![], &origin)
            .await
            .unwrap_or_else(|err| panic!("cleanup set_rrset TLSA failed: {err}"));
    }
}
