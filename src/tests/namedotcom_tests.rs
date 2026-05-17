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
        DnsRecord, DnsRecordType, DnsUpdater, Error,
        providers::namedotcom::NameDotComProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> NameDotComProvider {
        NameDotComProvider::new("user", "token", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn basic_auth_value() -> String {
        let credentials = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "user:token",
        );
        format!("Basic {credentials}")
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let post = server
            .mock("POST", "/v4/domains/example.com/records")
            .match_header("authorization", basic_auth_value().as_str())
            .match_header("content-type", "application/json")
            .match_body(Matcher::Json(json!({
                "host": "www",
                "type": "A",
                "answer": "1.2.3.4",
                "ttl": 600,
            })))
            .with_status(200)
            .with_body(r#"{"id":42}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        post.assert();
    }

    #[tokio::test]
    async fn test_update_looks_up_record_id_then_puts() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/v4/domains/example.com/records?page=1")
            .match_header("authorization", basic_auth_value().as_str())
            .with_status(200)
            .with_body(
                r#"{"records":[{"id":7,"host":"www","fqdn":"www.example.com.","type":"A"}],"nextPage":0}"#,
            )
            .create();

        let put = server
            .mock("PUT", "/v4/domains/example.com/records/7")
            .match_body(Matcher::Json(json!({
                "host": "www",
                "type": "A",
                "answer": "8.8.8.8",
                "ttl": 600,
            })))
            .with_status(200)
            .with_body(r#"{"id":7}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "www.example.com",
                DnsRecord::A("8.8.8.8".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update returned: {result:?}");
        list.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_delete_looks_up_record_id_then_deletes() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/v4/domains/example.com/records?page=1")
            .with_status(200)
            .with_body(
                r#"{"records":[{"id":11,"host":"www","fqdn":"www.example.com.","type":"TXT"}],"nextPage":0}"#,
            )
            .create();

        let delete = server
            .mock("DELETE", "/v4/domains/example.com/records/11")
            .match_header("authorization", basic_auth_value().as_str())
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("www.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete returned: {result:?}");
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_record_lookup_missing_returns_api_error() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/v4/domains/example.com/records?page=1")
            .with_status(200)
            .with_body(r#"{"records":[],"nextPage":0}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("missing.example.com", "example.com", DnsRecordType::A)
            .await;

        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
        list.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("POST", "/v4/domains/example.com/records")
            .with_status(401)
            .with_body(r#"{"message":"Unauthorized"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                600,
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
    #[ignore = "Requires NAMECOM_USERNAME, NAMECOM_API_TOKEN, NAMECOM_ORIGIN, NAMECOM_FQDN"]
    async fn integration_test() {
        let user = std::env::var("NAMECOM_USERNAME").unwrap_or_default();
        let token = std::env::var("NAMECOM_API_TOKEN").unwrap_or_default();
        let origin = std::env::var("NAMECOM_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("NAMECOM_FQDN").unwrap_or_default();

        assert!(!user.is_empty(), "Set NAMECOM_USERNAME to run this test");
        assert!(!token.is_empty(), "Set NAMECOM_API_TOKEN to run this test");
        assert!(!origin.is_empty(), "Set NAMECOM_ORIGIN to run this test");
        assert!(!fqdn.is_empty(), "Set NAMECOM_FQDN to run this test");

        let updater =
            DnsUpdater::new_namedotcom(user, token, Some(Duration::from_secs(30))).unwrap();

        let create_result = updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 600, &origin)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");

        let update_result = updater
            .update(&fqdn, DnsRecord::A([8, 8, 8, 8].into()), 600, &origin)
            .await;
        assert!(update_result.is_ok(), "update failed: {update_result:?}");

        let delete_result = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
