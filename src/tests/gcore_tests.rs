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
    use crate::{DnsRecord, DnsRecordType, Error, MXRecord, providers::gcore::GcoreProvider};
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> GcoreProvider {
        GcoreProvider::new("test_token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    fn mock_zone_lookup(server: &mut ServerGuard, zone: &str) -> Mock {
        server
            .mock("GET", format!("/v2/zones/{zone}").as_str())
            .match_header("authorization", "APIKey test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(r#"{{"name":"{zone}"}}"#))
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let delete = server
            .mock("DELETE", "/v2/zones/example.com/test.example.com/A")
            .match_header("authorization", "APIKey test_token")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                3600,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_swallows_404() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let delete = server
            .mock("DELETE", "/v2/zones/example.com/test.example.com/A")
            .with_status(404)
            .with_body(r#"{"error":"not found"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                3600,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_non_empty_puts_full_set() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let put = server
            .mock("PUT", "/v2/zones/example.com/test.example.com/A")
            .match_body(Matcher::Json(json!({
                "ttl": 300,
                "resource_records": [
                    {"content": ["1.1.1.1"]},
                    {"content": ["2.2.2.2"]},
                ],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_falls_back_to_post_on_404() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let put = server
            .mock("PUT", "/v2/zones/example.com/test.example.com/A")
            .with_status(404)
            .with_body(r#"{"error":"not found"}"#)
            .create();
        let post = server
            .mock("POST", "/v2/zones/example.com/test.example.com/A")
            .match_body(Matcher::Json(json!({
                "ttl": 300,
                "resource_records": [{"content": ["1.1.1.1"]}],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        put.assert();
        post.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_errors() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());

        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("hello".to_string())],
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("type mismatch")),
            "expected type mismatch error, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
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
    async fn test_add_to_rrset_skips_duplicates() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let get = server
            .mock("GET", "/v2/zones/example.com/test.example.com/A")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "ttl": 300,
                    "resource_records": [
                        {"content": ["1.1.1.1"]}
                    ]
                }"#,
            )
            .create();
        let put = server
            .mock("PUT", "/v2/zones/example.com/test.example.com/A")
            .match_body(Matcher::Json(json!({
                "ttl": 300,
                "resource_records": [
                    {"content": ["1.1.1.1"]},
                    {"content": ["2.2.2.2"]},
                ],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        zone.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_all_duplicates_noops_when_existed() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let get = server
            .mock("GET", "/v2/zones/example.com/test.example.com/A")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "ttl": 300,
                    "resource_records": [
                        {"content": ["1.1.1.1"]}
                    ]
                }"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        zone.assert();
        get.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_posts_when_absent() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let get = server
            .mock("GET", "/v2/zones/example.com/test.example.com/A")
            .with_status(404)
            .with_body(r#"{"error":"not found"}"#)
            .create();
        let put = server
            .mock("PUT", "/v2/zones/example.com/test.example.com/A")
            .with_status(404)
            .with_body(r#"{"error":"not found"}"#)
            .create();
        let post = server
            .mock("POST", "/v2/zones/example.com/test.example.com/A")
            .match_body(Matcher::Json(json!({
                "ttl": 300,
                "resource_records": [{"content": ["1.1.1.1"]}],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        zone.assert();
        get.assert();
        put.assert();
        post.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());

        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_filters_and_puts() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let get = server
            .mock("GET", "/v2/zones/example.com/test.example.com/A")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "ttl": 600,
                    "resource_records": [
                        {"content": ["1.1.1.1"]},
                        {"content": ["2.2.2.2"]}
                    ]
                }"#,
            )
            .create();
        let put = server
            .mock("PUT", "/v2/zones/example.com/test.example.com/A")
            .match_body(Matcher::Json(json!({
                "ttl": 600,
                "resource_records": [{"content": ["2.2.2.2"]}],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        zone.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_when_filtered_empty() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let get = server
            .mock("GET", "/v2/zones/example.com/test.example.com/A")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "ttl": 600,
                    "resource_records": [
                        {"content": ["1.1.1.1"]}
                    ]
                }"#,
            )
            .create();
        let delete = server
            .mock("DELETE", "/v2/zones/example.com/test.example.com/A")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        zone.assert();
        get.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_absent_value_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let get = server
            .mock("GET", "/v2/zones/example.com/test.example.com/A")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "ttl": 600,
                    "resource_records": [
                        {"content": ["2.2.2.2"]}
                    ]
                }"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        zone.assert();
        get.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_missing_rrset_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let get = server
            .mock("GET", "/v2/zones/example.com/test.example.com/A")
            .with_status(404)
            .with_body(r#"{"error":"not found"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        zone.assert();
        get.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_a_records() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let get = server
            .mock("GET", "/v2/zones/example.com/test.example.com/A")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "ttl": 300,
                    "resource_records": [
                        {"content": ["1.1.1.1"]},
                        {"content": ["2.2.2.2"]}
                    ]
                }"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("test.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();

        assert_eq!(
            result,
            vec![
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                DnsRecord::A("2.2.2.2".parse().unwrap()),
            ]
        );
        zone.assert();
        get.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_empty_on_404() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let get = server
            .mock("GET", "/v2/zones/example.com/test.example.com/A")
            .with_status(404)
            .with_body(r#"{"error":"not found"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("test.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();

        assert!(result.is_empty());
        zone.assert();
        get.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_mx_records() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let get = server
            .mock("GET", "/v2/zones/example.com/example.com/MX")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "ttl": 300,
                    "resource_records": [
                        {"content": [10, "mail.example.com"]},
                        {"content": [20, "mail2.example.com"]}
                    ]
                }"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .unwrap();

        assert_eq!(
            result,
            vec![
                DnsRecord::MX(MXRecord {
                    priority: 10,
                    exchange: "mail.example.com".to_string(),
                }),
                DnsRecord::MX(MXRecord {
                    priority: 20,
                    exchange: "mail2.example.com".to_string(),
                }),
            ]
        );
        zone.assert();
        get.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let put = server
            .mock("PUT", "/v2/zones/example.com/test.example.com/A")
            .match_body(Matcher::Json(json!({
                "ttl": 300,
                "resource_records": [{"content": ["1.1.1.1"]}],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        put.assert();
    }
}
