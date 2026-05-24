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
        providers::digitalocean::DigitalOceanProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const DOMAIN: &str = "example.com";

    fn setup_provider(endpoint: String) -> DigitalOceanProvider {
        DigitalOceanProvider::new("test_token", Some(Duration::from_secs(1)))
            .with_endpoint(endpoint)
    }

    fn list_path() -> String {
        format!("/v2/domains/{DOMAIN}/records")
    }

    fn mock_list(
        server: &mut ServerGuard,
        name: &str,
        record_type: &str,
        records: serde_json::Value,
    ) -> Mock {
        server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), name.into()),
                Matcher::UrlEncoded("type".into(), record_type.into()),
                Matcher::UrlEncoded("per_page".into(), "200".into()),
                Matcher::UrlEncoded("page".into(), "1".into()),
            ]))
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::to_string(&json!({
                    "domain_records": records,
                    "links": {},
                    "meta": {"total": 0}
                }))
                .unwrap(),
            )
            .create()
    }

    fn mock_delete(server: &mut ServerGuard, id: i64) -> Mock {
        server
            .mock(
                "DELETE",
                format!("/v2/domains/{DOMAIN}/records/{id}").as_str(),
            )
            .match_header("authorization", "Bearer test_token")
            .with_status(204)
            .create()
    }

    fn mock_post_match(server: &mut ServerGuard, body: serde_json::Value) -> Mock {
        server
            .mock("POST", format!("/v2/domains/{DOMAIN}/records").as_str())
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(body))
            .with_status(201)
            .with_body(r#"{"domain_record":{"id":1}}"#)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, "www.example.com", "A", json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "ttl": 300,
                "name": "www",
                "type": "A",
                "data": "1.2.3.4",
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
        let list = mock_list(
            &mut server,
            "www.example.com",
            "A",
            json!([
                {"id": 1, "ttl": 300, "name": "www", "type": "A", "data": "1.2.3.4"}
            ]),
        );
        let _no_post = server
            .mock("POST", format!("/v2/domains/{DOMAIN}/records").as_str())
            .expect(0)
            .create();
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex(format!("^/v2/domains/{DOMAIN}/records/")),
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
        let list = mock_list(
            &mut server,
            "host.example.com",
            "A",
            json!([
                {"id": 11, "ttl": 300, "name": "host", "type": "A", "data": "1.1.1.1"},
                {"id": 22, "ttl": 300, "name": "host", "type": "A", "data": "9.9.9.9"}
            ]),
        );
        let delete_stale = mock_delete(&mut server, 22);
        let create_new = mock_post_match(
            &mut server,
            json!({
                "ttl": 300,
                "name": "host",
                "type": "A",
                "data": "8.8.8.8",
            }),
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
        let list = mock_list(
            &mut server,
            "gone.example.com",
            "A",
            json!([
                {"id": 33, "ttl": 300, "name": "gone", "type": "A", "data": "1.2.3.4"},
                {"id": 44, "ttl": 300, "name": "gone", "type": "A", "data": "5.6.7.8"}
            ]),
        );
        let del33 = mock_delete(&mut server, 33);
        let del44 = mock_delete(&mut server, 44);

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
        let list = mock_list(
            &mut server,
            "_acme.example.com",
            "TXT",
            json!([
                {"id": 101, "ttl": 60, "name": "_acme", "type": "TXT", "data": "existing"}
            ]),
        );
        let create_new = mock_post_match(
            &mut server,
            json!({
                "ttl": 60,
                "name": "_acme",
                "type": "TXT",
                "data": "new-token",
            }),
        );

        let provider = setup_provider(server.url());
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
        let list = mock_list(
            &mut server,
            "_acme.example.com",
            "TXT",
            json!([
                {"id": 200, "ttl": 60, "name": "_acme", "type": "TXT", "data": "keep-me"},
                {"id": 201, "ttl": 60, "name": "_acme", "type": "TXT", "data": "drop-me"}
            ]),
        );
        let delete = mock_delete(&mut server, 201);

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
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
    async fn test_remove_from_rrset_noop_when_value_absent() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "test.example.com",
            "A",
            json!([
                {"id": 300, "ttl": 300, "name": "test", "type": "A", "data": "1.1.1.1"}
            ]),
        );
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex(format!("^/v2/domains/{DOMAIN}/records/")),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
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
    async fn test_set_rrset_type_mismatch_returns_api_error() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
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
    async fn test_set_rrset_filters_by_type_for_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "shared.example.com".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
                Matcher::UrlEncoded("per_page".into(), "200".into()),
                Matcher::UrlEncoded("page".into(), "1".into()),
            ]))
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "domain_records": [],
                    "links": {}
                }))
                .unwrap(),
            )
            .expect(1)
            .create();

        let _txt_must_not_fire = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::UrlEncoded("type".into(), "TXT".into()))
            .with_status(500)
            .expect(0)
            .create();

        let create = mock_post_match(
            &mut server,
            json!({
                "ttl": 300,
                "name": "shared",
                "type": "A",
                "data": "1.1.1.1",
            }),
        );

        let provider = setup_provider(server.url());
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
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_with_priority_field() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, "example.com", "MX", json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "ttl": 3600,
                "name": "@",
                "type": "MX",
                "data": "mail.example.com.",
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
                    exchange: "mail.example.com".to_string(),
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
    async fn test_set_rrset_srv_with_flat_fields() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, "_imaps._tcp.example.com", "SRV", json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "ttl": 3600,
                "name": "_imaps._tcp",
                "type": "SRV",
                "data": "mail.example.com.",
                "priority": 10,
                "port": 993,
                "weight": 5,
            }),
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
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_uses_flat_flags_tag_data() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, "example.com", "CAA", json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "ttl": 3600,
                "name": "@",
                "type": "CAA",
                "data": "letsencrypt.org",
                "flags": 0,
                "tag": "issue",
            }),
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
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_cname_target_normalized_with_trailing_dot() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, "alias.example.com", "CNAME", json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "ttl": 300,
                "name": "alias",
                "type": "CNAME",
                "data": "target.example.org.",
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "alias.example.com",
                DnsRecordType::CNAME,
                300,
                vec![DnsRecord::CNAME("target.example.org".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_replaces_two_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "host.example.com",
            "A",
            json!([
                {"id": 50, "ttl": 300, "name": "host", "type": "A", "data": "1.1.1.1"},
                {"id": 51, "ttl": 300, "name": "host", "type": "A", "data": "1.1.1.2"}
            ]),
        );
        let del50 = mock_delete(&mut server, 50);
        let del51 = mock_delete(&mut server, 51);
        let create1 = mock_post_match(
            &mut server,
            json!({
                "ttl": 300, "name": "host", "type": "A", "data": "2.2.2.1",
            }),
        );
        let create2 = mock_post_match(
            &mut server,
            json!({
                "ttl": 300, "name": "host", "type": "A", "data": "2.2.2.2",
            }),
        );

        let provider = setup_provider(server.url());
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
        list.assert();
        del50.assert();
        del51.assert();
        create1.assert();
        create2.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_is_full_noop_when_everything_present() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "test.example.com",
            "A",
            json!([
                {"id": 70, "ttl": 300, "name": "test", "type": "A", "data": "1.1.1.1"},
                {"id": 71, "ttl": 300, "name": "test", "type": "A", "data": "8.8.8.8"}
            ]),
        );
        let _no_post = server
            .mock("POST", format!("/v2/domains/{DOMAIN}/records").as_str())
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
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
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_typed_records() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "host.example.com",
            "A",
            json!([
                {"id": 80, "ttl": 300, "name": "host", "type": "A", "data": "1.1.1.1"},
                {"id": 81, "ttl": 300, "name": "host", "type": "A", "data": "2.2.2.2"}
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

    #[tokio::test]
    async fn test_list_filter_ignores_off_name_or_off_type_records() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "host.example.com",
            "A",
            json!([
                {"id": 90, "ttl": 300, "name": "host", "type": "A", "data": "1.1.1.1"},
                {"id": 91, "ttl": 300, "name": "other", "type": "A", "data": "9.9.9.9"}
            ]),
        );

        let provider = setup_provider(server.url());
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
        list.assert();
    }

    #[tokio::test]
    async fn test_list_paginates_when_next_link_present() {
        let mut server = mockito::Server::new_async().await;

        let mut page1_records: Vec<serde_json::Value> = Vec::new();
        for i in 0..200u32 {
            page1_records.push(json!({
                "id": i as i64,
                "ttl": 300,
                "name": "host",
                "type": "A",
                "data": format!("10.0.{}.{}", i / 256, i % 256),
            }));
        }
        let page1 = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "host.example.com".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
                Matcher::UrlEncoded("per_page".into(), "200".into()),
                Matcher::UrlEncoded("page".into(), "1".into()),
            ]))
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "domain_records": page1_records,
                    "links": {"pages": {"next": "https://api.digitalocean.com/v2/domains/example.com/records?page=2&per_page=200"}}
                }))
                .unwrap(),
            )
            .create();

        let page2 = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "host.example.com".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
                Matcher::UrlEncoded("per_page".into(), "200".into()),
                Matcher::UrlEncoded("page".into(), "2".into()),
            ]))
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "domain_records": [
                        {"id": 999, "ttl": 300, "name": "host", "type": "A", "data": "10.99.0.1"}
                    ],
                    "links": {}
                }))
                .unwrap(),
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await;
        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 201);
        page1.assert();
        page2.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::Any)
            .with_status(401)
            .with_body(r#"{"id":"unauthorized","message":"Unable to authenticate"}"#)
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
        unauthorized.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_apex_uses_at_sign_as_subdomain() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, "example.com", "A", json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "ttl": 300,
                "name": "@",
                "type": "A",
                "data": "1.2.3.4",
            }),
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
        list.assert();
        create.assert();
    }
}
