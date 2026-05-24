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
    use crate::{DnsRecord, DnsRecordType, Error, providers::gandiv5::GandiV5Provider};
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> GandiV5Provider {
        GandiV5Provider::new("test_token", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_set_rrset_puts_all_values_in_single_call() {
        let mut server = mockito::Server::new_async().await;
        let put = server
            .mock("PUT", "/domains/example.com/records/host/A")
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "rrset_ttl": 300,
                "rrset_values": ["1.1.1.1", "8.8.8.8"],
            })))
            .with_status(201)
            .with_body(r#"{"message":"ok"}"#)
            .create();

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
        put.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_rrset() {
        let mut server = mockito::Server::new_async().await;
        let delete = server
            .mock("DELETE", "/domains/example.com/records/gone/A")
            .match_header("authorization", "Bearer test_token")
            .with_status(204)
            .create();

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
        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_treats_404_as_success() {
        let mut server = mockito::Server::new_async().await;
        let delete = server
            .mock("DELETE", "/domains/example.com/records/missing/A")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"not found"}"#)
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
        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_type_mismatch() {
        let server = mockito::Server::new_async().await;
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
    async fn test_set_rrset_cross_type_isolation_only_touches_url_for_type() {
        let mut server = mockito::Server::new_async().await;
        let put = server
            .mock("PUT", "/domains/example.com/records/host/AAAA")
            .match_body(Matcher::Json(json!({
                "rrset_ttl": 300,
                "rrset_values": ["::1"],
            })))
            .with_status(201)
            .with_body(r#"{"message":"ok"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::AAAA,
                300,
                vec![DnsRecord::AAAA("::1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        put.assert();
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
    async fn test_add_to_rrset_merges_non_duplicates() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/domains/example.com/records/host/A")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"rrset_name":"host","rrset_type":"A","rrset_ttl":300,"rrset_values":["1.1.1.1"]}"#,
            )
            .create();

        let put = server
            .mock("PUT", "/domains/example.com/records/host/A")
            .match_body(Matcher::Json(json!({
                "rrset_ttl": 300,
                "rrset_values": ["1.1.1.1", "8.8.8.8"],
            })))
            .with_status(201)
            .with_body(r#"{"message":"ok"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                600,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("8.8.8.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_all_duplicates_skips_put() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/domains/example.com/records/host/A")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"rrset_name":"host","rrset_type":"A","rrset_ttl":300,"rrset_values":["1.1.1.1"]}"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        get.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_creates_when_absent() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/domains/example.com/records/host/A")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"not found"}"#)
            .create();

        let put = server
            .mock("PUT", "/domains/example.com/records/host/A")
            .match_body(Matcher::Json(json!({
                "rrset_ttl": 600,
                "rrset_values": ["1.1.1.1"],
            })))
            .with_status(201)
            .with_body(r#"{"message":"ok"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        get.assert();
        put.assert();
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
        let get_values = server
            .mock("GET", "/domains/example.com/records/host/A")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"rrset_name":"host","rrset_type":"A","rrset_ttl":500,"rrset_values":["1.1.1.1","8.8.8.8"]}"#,
            )
            .expect_at_least(1)
            .create();

        let put = server
            .mock("PUT", "/domains/example.com/records/host/A")
            .match_body(Matcher::Json(json!({
                "rrset_ttl": 500,
                "rrset_values": ["1.1.1.1"],
            })))
            .with_status(201)
            .with_body(r#"{"message":"ok"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("8.8.8.8".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        get_values.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_when_filtered_empty() {
        let mut server = mockito::Server::new_async().await;
        let get_values = server
            .mock("GET", "/domains/example.com/records/host/A")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"rrset_name":"host","rrset_type":"A","rrset_ttl":300,"rrset_values":["1.1.1.1"]}"#,
            )
            .create();

        let delete = server
            .mock("DELETE", "/domains/example.com/records/host/A")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        get_values.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_absent_records_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let get_values = server
            .mock("GET", "/domains/example.com/records/host/A")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"not found"}"#)
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
        get_values.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_values() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/domains/example.com/records/host/A")
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"rrset_name":"host","rrset_type":"A","rrset_ttl":300,"rrset_values":["1.1.1.1","8.8.8.8"]}"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(
            records,
            vec![
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                DnsRecord::A("8.8.8.8".parse().unwrap()),
            ]
        );
        get.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_txt_unquoted() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/domains/example.com/records/_acme/TXT")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"rrset_name":"_acme","rrset_type":"TXT","rrset_ttl":300,"rrset_values":["\"hello\""]}"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("_acme.example.com", DnsRecordType::TXT, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        assert_eq!(result.unwrap(), vec![DnsRecord::TXT("hello".to_string())]);
        get.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_404_returns_empty() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/domains/example.com/records/nope/A")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"not found"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("nope.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        assert!(result.unwrap().is_empty());
        get.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_rejects_type_mismatch() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
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
    async fn test_remove_from_rrset_rejects_type_mismatch() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::TXT("not-an-A".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }
}
