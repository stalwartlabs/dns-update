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
        CAARecord, DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord,
        providers::simply::{ExistingDnsRecord, SimplyProvider, SimplyRecordContent},
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn test_content_from_mx_splits_priority() {
        let content = SimplyRecordContent::try_from(DnsRecord::MX(MXRecord {
            exchange: "mail.example.com.".to_string(),
            priority: 10,
        }))
        .unwrap();
        assert_eq!(content.record_type, "MX");
        assert_eq!(content.data, "mail.example.com");
        assert_eq!(content.priority, Some(10));
    }

    #[test]
    fn test_content_from_srv_packs_weight_port_target() {
        let content = SimplyRecordContent::try_from(DnsRecord::SRV(SRVRecord {
            priority: 10,
            weight: 5,
            port: 993,
            target: "mail.example.com.".to_string(),
        }))
        .unwrap();
        assert_eq!(content.record_type, "SRV");
        assert_eq!(content.data, "5 993 mail.example.com");
        assert_eq!(content.priority, Some(10));
    }

    #[test]
    fn test_content_from_caa_uses_bind_string() {
        let content = SimplyRecordContent::try_from(DnsRecord::CAA(CAARecord::Issue {
            issuer_critical: false,
            name: Some("letsencrypt.org".to_string()),
            options: vec![],
        }))
        .unwrap();
        assert_eq!(content.record_type, "CAA");
        assert_eq!(content.data, "0 issue \"letsencrypt.org\"");
        assert_eq!(content.priority, None);
    }

    #[test]
    fn test_content_from_tlsa_uses_display_string() {
        let record = crate::utils::parse_tlsa("3 1 1 0123af").unwrap();
        let content = SimplyRecordContent::try_from(record).unwrap();
        assert_eq!(content.record_type, "TLSA");
        assert_eq!(content.data, "3 1 1 0123af");
    }

    #[test]
    fn test_existing_srv_record_parses_back() {
        let record = DnsRecord::try_from(ExistingDnsRecord {
            record_id: 1,
            name: "_imaps._tcp".to_string(),
            record_type: "SRV".to_string(),
            data: "5 993 mail.example.com".to_string(),
            priority: Some(10),
        })
        .unwrap();
        match record {
            DnsRecord::SRV(srv) => {
                assert_eq!(srv.priority, 10);
                assert_eq!(srv.weight, 5);
                assert_eq!(srv.port, 993);
                assert_eq!(srv.target, "mail.example.com");
            }
            other => panic!("expected SRV, got {other:?}"),
        }
    }

    #[test]
    fn test_existing_caa_record_parses_back() {
        let record = DnsRecord::try_from(ExistingDnsRecord {
            record_id: 2,
            name: "@".to_string(),
            record_type: "CAA".to_string(),
            data: "0 issue \"letsencrypt.org\"".to_string(),
            priority: None,
        })
        .unwrap();
        match record {
            DnsRecord::CAA(CAARecord::Issue {
                issuer_critical,
                name,
                ..
            }) => {
                assert!(!issuer_critical);
                assert_eq!(name.as_deref(), Some("letsencrypt.org"));
            }
            other => panic!("expected CAA Issue, got {other:?}"),
        }
    }

    const AUTH: &str = "Basic UzEyMzQ1Njp0ZXN0a2V5";

    fn setup_provider(endpoint: String) -> SimplyProvider {
        SimplyProvider::new("S123456", "testkey", Some(Duration::from_secs(1)))
            .with_endpoint(endpoint)
    }

    fn mock_products(server: &mut ServerGuard) -> Mock {
        server
            .mock("GET", "/my/products/")
            .match_header("authorization", AUTH)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::to_string(&json!({
                    "products": [
                        {
                            "object": "example.com",
                            "name": "example.com",
                            "domain": {"name": "example.com", "name_idn": "example.com"}
                        },
                        {
                            "object": "customer-handle-42",
                            "name": "customer-handle-42",
                            "domain": {"name": "xn--blbr-yra.dk", "name_idn": "bl\u{e5}b\u{e6}r.dk"}
                        }
                    ],
                    "status": 200,
                    "message": "success"
                }))
                .unwrap(),
            )
            .create()
    }

    fn mock_list(server: &mut ServerGuard, object: &str, records: serde_json::Value) -> Mock {
        server
            .mock(
                "GET",
                format!("/my/products/{object}/dns/records/").as_str(),
            )
            .match_header("authorization", AUTH)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::to_string(&json!({
                    "records": records,
                    "status": 200,
                    "message": "success"
                }))
                .unwrap(),
            )
            .create()
    }

    fn mock_create(server: &mut ServerGuard, object: &str, body: serde_json::Value) -> Mock {
        server
            .mock(
                "POST",
                format!("/my/products/{object}/dns/records/").as_str(),
            )
            .match_header("authorization", AUTH)
            .match_body(Matcher::Json(body))
            .with_status(200)
            .with_body(r#"{"record":{"id":1},"status":200,"message":"success"}"#)
            .create()
    }

    fn mock_delete(server: &mut ServerGuard, object: &str, id: i64) -> Mock {
        server
            .mock(
                "DELETE",
                format!("/my/products/{object}/dns/records/{id}/").as_str(),
            )
            .match_header("authorization", AUTH)
            .with_status(200)
            .with_body(r#"{"status":200,"message":"success"}"#)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_zone_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let products = mock_products(&mut server);
        let list = mock_list(&mut server, "example.com", json!([]));
        let create = mock_create(
            &mut server,
            "example.com",
            json!({"type": "A", "name": "www", "data": "1.2.3.4", "ttl": 300}),
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
        products.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let _products = mock_products(&mut server);
        let list = mock_list(
            &mut server,
            "example.com",
            json!([
                {"record_id": 1, "name": "www", "type": "A", "data": "1.2.3.4", "ttl": 300, "priority": 0, "comment": null}
            ]),
        );
        let _no_post = server
            .mock("POST", "/my/products/example.com/dns/records/")
            .expect(0)
            .create();
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex("^/my/products/example.com/dns/records/".to_string()),
            )
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
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_creates_missing() {
        let mut server = mockito::Server::new_async().await;
        let _products = mock_products(&mut server);
        let list = mock_list(
            &mut server,
            "example.com",
            json!([
                {"record_id": 11, "name": "host", "type": "A", "data": "1.1.1.1", "ttl": 300},
                {"record_id": 22, "name": "host", "type": "A", "data": "9.9.9.9", "ttl": 300}
            ]),
        );
        let delete_stale = mock_delete(&mut server, "example.com", 22);
        let create_new = mock_create(
            &mut server,
            "example.com",
            json!({"type": "A", "name": "host", "data": "8.8.8.8", "ttl": 300}),
        );

        let provider = setup_provider(server.url());
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
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_all_at_owner_and_type() {
        let mut server = mockito::Server::new_async().await;
        let _products = mock_products(&mut server);
        let list = mock_list(
            &mut server,
            "example.com",
            json!([
                {"record_id": 33, "name": "gone", "type": "A", "data": "1.2.3.4", "ttl": 300},
                {"record_id": 44, "name": "gone", "type": "A", "data": "5.6.7.8", "ttl": 300}
            ]),
        );
        let del33 = mock_delete(&mut server, "example.com", 33);
        let del44 = mock_delete(&mut server, "example.com", 44);

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
        del33.assert();
        del44.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing_and_creates_new() {
        let mut server = mockito::Server::new_async().await;
        let _products = mock_products(&mut server);
        let list = mock_list(
            &mut server,
            "example.com",
            json!([
                {"record_id": 101, "name": "_acme-challenge", "type": "TXT", "data": "existing", "ttl": 60}
            ]),
        );
        let create_new = mock_create(
            &mut server,
            "example.com",
            json!({"type": "TXT", "name": "_acme-challenge", "data": "new-token", "ttl": 60}),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                60,
                vec![
                    DnsRecord::TXT("existing".to_string()),
                    DnsRecord::TXT("new-token".to_string()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        list.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_input_is_short_circuit() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let _products = mock_products(&mut server);
        let list = mock_list(
            &mut server,
            "example.com",
            json!([
                {"record_id": 200, "name": "_acme-challenge", "type": "TXT", "data": "keep-me", "ttl": 60},
                {"record_id": 201, "name": "_acme-challenge", "type": "TXT", "data": "drop-me", "ttl": 60}
            ]),
        );
        let delete = mock_delete(&mut server, "example.com", 201);

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop-me".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_input_is_short_circuit() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let _no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_apex_uses_at_sign() {
        let mut server = mockito::Server::new_async().await;
        let _products = mock_products(&mut server);
        let _list = mock_list(&mut server, "example.com", json!([]));
        let create = mock_create(
            &mut server,
            "example.com",
            json!({"type": "A", "name": "@", "data": "1.2.3.4", "ttl": 300}),
        );

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
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_sends_priority_field() {
        let mut server = mockito::Server::new_async().await;
        let _products = mock_products(&mut server);
        let _list = mock_list(&mut server, "example.com", json!([]));
        let create = mock_create(
            &mut server,
            "example.com",
            json!({"type": "MX", "name": "@", "data": "mail.example.com", "ttl": 3600, "priority": 10}),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_packs_data_and_priority() {
        let mut server = mockito::Server::new_async().await;
        let _products = mock_products(&mut server);
        let _list = mock_list(&mut server, "example.com", json!([]));
        let create = mock_create(
            &mut server,
            "example.com",
            json!({"type": "SRV", "name": "_imaps._tcp", "data": "5 993 mail.example.com", "ttl": 3600, "priority": 10}),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_imaps._tcp.example.com",
                DnsRecordType::SRV,
                3600,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 993,
                    target: "mail.example.com".to_string(),
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        create.assert();
    }

    #[tokio::test]
    async fn test_object_resolution_uses_handle_when_it_differs_from_domain() {
        let mut server = mockito::Server::new_async().await;
        let _products = mock_products(&mut server);
        let _list = mock_list(&mut server, "customer-handle-42", json!([]));
        let create = mock_create(
            &mut server,
            "customer-handle-42",
            json!({"type": "A", "name": "www", "data": "1.2.3.4", "ttl": 300}),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.xn--blbr-yra.dk",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "xn--blbr-yra.dk",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        create.assert();
    }

    #[tokio::test]
    async fn test_object_resolution_walks_labels_for_subdomain_origin() {
        let mut server = mockito::Server::new_async().await;
        let _products = mock_products(&mut server);
        let _list = mock_list(&mut server, "example.com", json!([]));
        let create = mock_create(
            &mut server,
            "example.com",
            json!({"type": "A", "name": "printer.office", "data": "10.0.0.9", "ttl": 300}),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "printer.office.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("10.0.0.9".parse().unwrap())],
                "office.example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        create.assert();
    }

    #[tokio::test]
    async fn test_unknown_origin_returns_not_found() {
        let mut server = mockito::Server::new_async().await;
        let _products = mock_products(&mut server);

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.unknown.org",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "unknown.org",
            )
            .await;

        assert!(
            matches!(result, Err(Error::NotFound)),
            "expected NotFound, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_empty_zone_response_without_records_key() {
        let mut server = mockito::Server::new_async().await;
        let _products = mock_products(&mut server);
        let _list = server
            .mock("GET", "/my/products/example.com/dns/records/")
            .match_header("authorization", AUTH)
            .with_status(200)
            .with_body(r#"{"status":200,"message":"success"}"#)
            .create();
        let create = mock_create(
            &mut server,
            "example.com",
            json!({"type": "A", "name": "www", "data": "1.2.3.4", "ttl": 300}),
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
        create.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("GET", "/my/products/")
            .with_status(401)
            .with_body("")
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

        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
        unauthorized.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_typed_records() {
        let mut server = mockito::Server::new_async().await;
        let _products = mock_products(&mut server);
        let list = mock_list(
            &mut server,
            "example.com",
            json!([
                {"record_id": 80, "name": "host", "type": "A", "data": "1.1.1.1", "ttl": 300},
                {"record_id": 81, "name": "host", "type": "A", "data": "2.2.2.2", "ttl": 300},
                {"record_id": 82, "name": "other", "type": "A", "data": "9.9.9.9", "ttl": 300},
                {"record_id": 83, "name": "host", "type": "TXT", "data": "not-an-a", "ttl": 300}
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 2);
        for r in &records {
            assert_eq!(r.as_type(), DnsRecordType::A);
        }
        list.assert();
    }
}
