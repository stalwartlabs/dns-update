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
    use crate::providers::domeneshop::DomeneshopProvider;
    use crate::{CAARecord, DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord};
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const DOMAINS_JSON: &str = r#"[
        {"id": 42, "domain": "example.com"}
    ]"#;

    fn setup_provider(endpoint: &str) -> DomeneshopProvider {
        DomeneshopProvider::new("token", "secret", Some(Duration::from_secs(2)))
            .with_endpoint(endpoint)
    }

    fn basic_auth_value() -> String {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        format!("Basic {}", BASE64.encode(b"token:secret"))
    }

    fn mock_domains(server: &mut ServerGuard) -> Mock {
        server
            .mock("GET", "/domains")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(DOMAINS_JSON)
            .create()
    }

    fn mock_list(
        server: &mut ServerGuard,
        host: &str,
        record_type: &str,
        body: serde_json::Value,
    ) -> Mock {
        server
            .mock("GET", "/domains/42/dns")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("host".into(), host.into()),
                Matcher::UrlEncoded("type".into(), record_type.into()),
            ]))
            .match_header("authorization", basic_auth_value().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    fn mock_post(server: &mut ServerGuard, body: serde_json::Value) -> Mock {
        server
            .mock("POST", "/domains/42/dns")
            .match_header("authorization", basic_auth_value().as_str())
            .match_body(Matcher::Json(body))
            .with_status(201)
            .with_body(r#"{"id": 1}"#)
            .create()
    }

    fn mock_delete(server: &mut ServerGuard, id: i64) -> Mock {
        server
            .mock("DELETE", format!("/domains/42/dns/{id}").as_str())
            .match_header("authorization", basic_auth_value().as_str())
            .with_status(204)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(&mut server, "www", "A", json!([]));
        let create = mock_post(
            &mut server,
            json!({
                "host": "www",
                "type": "A",
                "data": "1.2.3.4",
                "ttl": 300,
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
        domains.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(
            &mut server,
            "www",
            "A",
            json!([
                {"id": 1, "host": "www", "type": "A", "data": "1.2.3.4"}
            ]),
        );
        let _no_post = server.mock("POST", "/domains/42/dns").expect(0).create();
        let _no_delete = server
            .mock("DELETE", Matcher::Regex("^/domains/42/dns/".into()))
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
        domains.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_creates_missing() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(
            &mut server,
            "host",
            "A",
            json!([
                {"id": 11, "host": "host", "type": "A", "data": "1.1.1.1"},
                {"id": 22, "host": "host", "type": "A", "data": "9.9.9.9"}
            ]),
        );
        let delete_stale = mock_delete(&mut server, 22);
        let create_new = mock_post(
            &mut server,
            json!({
                "host": "host",
                "type": "A",
                "data": "8.8.8.8",
                "ttl": 300,
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
        domains.assert();
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_all_at_owner_and_type() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(
            &mut server,
            "gone",
            "A",
            json!([
                {"id": 33, "host": "gone", "type": "A", "data": "1.2.3.4"},
                {"id": 44, "host": "gone", "type": "A", "data": "5.6.7.8"}
            ]),
        );
        let del33 = mock_delete(&mut server, 33);
        let del44 = mock_delete(&mut server, 44);

        let provider = setup_provider(server.url().as_str());
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
        domains.assert();
        list.assert();
        del33.assert();
        del44.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_on_empty_owner_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(&mut server, "absent", "A", json!([]));
        let _no_delete = server
            .mock("DELETE", Matcher::Regex("^/domains/42/dns/".into()))
            .expect(0)
            .create();
        let _no_post = server.mock("POST", "/domains/42/dns").expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "absent.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domains.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing_and_creates_new() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(
            &mut server,
            "_acme",
            "TXT",
            json!([
                {"id": 101, "host": "_acme", "type": "TXT", "data": "existing"}
            ]),
        );
        let create_new = mock_post(
            &mut server,
            json!({
                "host": "_acme",
                "type": "TXT",
                "data": "new-token",
                "ttl": 60,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "_acme.example.com",
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
        domains.assert();
        list.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_input_is_short_circuit() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url().as_str());
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
    async fn test_add_to_rrset_is_full_noop_when_everything_present() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(
            &mut server,
            "test",
            "A",
            json!([
                {"id": 70, "host": "test", "type": "A", "data": "1.1.1.1"},
                {"id": 71, "host": "test", "type": "A", "data": "8.8.8.8"}
            ]),
        );
        let _no_post = server.mock("POST", "/domains/42/dns").expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("8.8.8.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        domains.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(
            &mut server,
            "_acme",
            "TXT",
            json!([
                {"id": 200, "host": "_acme", "type": "TXT", "data": "keep-me"},
                {"id": 201, "host": "_acme", "type": "TXT", "data": "drop-me"}
            ]),
        );
        let delete = mock_delete(&mut server, 201);

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop-me".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        domains.assert();
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_noop_when_value_absent() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(
            &mut server,
            "test",
            "A",
            json!([
                {"id": 300, "host": "test", "type": "A", "data": "1.1.1.1"}
            ]),
        );
        let _no_delete = server
            .mock("DELETE", Matcher::Regex("^/domains/42/dns/".into()))
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        domains.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_input_is_short_circuit() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let _no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_returns_api_error() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not-an-A".to_string())],
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_uses_server_side_host_type_filter() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = server
            .mock("GET", "/domains/42/dns")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("host".into(), "shared".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body("[]")
            .expect(1)
            .create();

        let _txt_must_not_fire = server
            .mock("GET", "/domains/42/dns")
            .match_query(Matcher::UrlEncoded("type".into(), "TXT".into()))
            .with_status(500)
            .expect(0)
            .create();

        let create = mock_post(
            &mut server,
            json!({
                "host": "shared",
                "type": "A",
                "data": "1.1.1.1",
                "ttl": 300,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "shared.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domains.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation_filters_client_side() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = server
            .mock("GET", "/domains/42/dns")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("host".into(), "shared".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!([
                    {"id": 1, "host": "shared", "type": "A", "data": "1.1.1.1"},
                    {"id": 2, "host": "shared", "type": "TXT", "data": "keep-me"}
                ]))
                .unwrap(),
            )
            .create();
        let _no_delete_txt = server
            .mock("DELETE", "/domains/42/dns/2")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "shared.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domains.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_with_priority_field() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(&mut server, "@", "MX", json!([]));
        let create = mock_post(
            &mut server,
            json!({
                "host": "@",
                "type": "MX",
                "data": "mail.example.com",
                "ttl": 3600,
                "priority": 10,
            }),
        );

        let provider = setup_provider(server.url().as_str());
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
        domains.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_with_flat_fields() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(&mut server, "_imaps._tcp", "SRV", json!([]));
        let create = mock_post(
            &mut server,
            json!({
                "host": "_imaps._tcp",
                "type": "SRV",
                "data": "mail.example.com",
                "ttl": 3600,
                "priority": 10,
                "weight": 5,
                "port": 993,
            }),
        );

        let provider = setup_provider(server.url().as_str());
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
        domains.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_uses_flat_flags_tag_data() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(&mut server, "@", "CAA", json!([]));
        let create = mock_post(
            &mut server,
            json!({
                "host": "@",
                "type": "CAA",
                "data": "letsencrypt.org",
                "ttl": 3600,
                "flags": 0,
                "tag": "issue",
            }),
        );

        let provider = setup_provider(server.url().as_str());
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
        domains.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_replaces_two_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(
            &mut server,
            "host",
            "A",
            json!([
                {"id": 50, "host": "host", "type": "A", "data": "1.1.1.1"},
                {"id": 51, "host": "host", "type": "A", "data": "1.1.1.2"}
            ]),
        );
        let del50 = mock_delete(&mut server, 50);
        let del51 = mock_delete(&mut server, 51);
        let create1 = mock_post(
            &mut server,
            json!({
                "host": "host", "type": "A", "data": "2.2.2.1", "ttl": 300,
            }),
        );
        let create2 = mock_post(
            &mut server,
            json!({
                "host": "host", "type": "A", "data": "2.2.2.2", "ttl": 300,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("2.2.2.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domains.assert();
        list.assert();
        del50.assert();
        del51.assert();
        create1.assert();
        create2.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_typed_records() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(
            &mut server,
            "host",
            "A",
            json!([
                {"id": 80, "host": "host", "type": "A", "data": "1.1.1.1"},
                {"id": 81, "host": "host", "type": "A", "data": "2.2.2.2"}
            ]),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 2);
        for r in &records {
            assert_eq!(r.as_type(), DnsRecordType::A);
        }
        domains.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_filters_off_name_or_off_type_records() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(
            &mut server,
            "host",
            "A",
            json!([
                {"id": 90, "host": "host", "type": "A", "data": "1.1.1.1"},
                {"id": 91, "host": "other", "type": "A", "data": "9.9.9.9"},
                {"id": 92, "host": "host", "type": "TXT", "data": "foo"}
            ]),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 1);
        match &records[0] {
            DnsRecord::A(addr) => assert_eq!(addr.to_string(), "1.1.1.1"),
            other => panic!("expected A, got {other:?}"),
        }
        domains.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_apex_uses_at_sign_as_host() {
        let mut server = mockito::Server::new_async().await;
        let domains = mock_domains(&mut server);
        let list = mock_list(&mut server, "@", "A", json!([]));
        let create = mock_post(
            &mut server,
            json!({
                "host": "@",
                "type": "A",
                "data": "1.2.3.4",
                "ttl": 300,
            }),
        );

        let provider = setup_provider(server.url().as_str());
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
        domains.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized_on_set() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("GET", "/domains")
            .with_status(401)
            .with_body(r#"{"message":"invalid credentials"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
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
        unauthorized.assert();
    }

    #[tokio::test]
    #[ignore = "Requires Domeneshop API credentials"]
    async fn integration_test() {
        let token = "";
        let secret = "";
        let origin = "";
        let name = "";

        assert!(!token.is_empty(), "Set DOMENESHOP_API_TOKEN");
        assert!(!secret.is_empty(), "Set DOMENESHOP_API_SECRET");
        assert!(!origin.is_empty(), "Set origin");
        assert!(!name.is_empty(), "Set name");

        let provider = DomeneshopProvider::new(token, secret, Some(Duration::from_secs(30)));
        assert!(
            provider
                .set_rrset(
                    name,
                    DnsRecordType::A,
                    3600,
                    vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                    origin,
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .add_to_rrset(
                    name,
                    DnsRecordType::A,
                    3600,
                    vec![DnsRecord::A("2.2.2.2".parse().unwrap())],
                    origin,
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .remove_from_rrset(
                    name,
                    DnsRecordType::A,
                    vec![DnsRecord::A("2.2.2.2".parse().unwrap())],
                    origin,
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .set_rrset(name, DnsRecordType::A, 3600, vec![], origin)
                .await
                .is_ok()
        );
    }
}
