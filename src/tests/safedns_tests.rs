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
    use crate::providers::safedns::SafeDnsProvider;
    use crate::{DnsRecord, DnsRecordType, Error, MXRecord};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> SafeDnsProvider {
        SafeDnsProvider::new("auth_token", Some(Duration::from_secs(2))).with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_txt_record() {
        let mut server = mockito::Server::new_async().await;
        let expected_body = json!({
            "name": "_acme-challenge.example.com",
            "type": "TXT",
            "content": "\"abc123\"",
            "ttl": 120,
        });
        let mock = server
            .mock("POST", "/zones/example.com/records")
            .match_header("authorization", "auth_token")
            .match_body(mockito::Matcher::Json(expected_body))
            .with_status(201)
            .with_body(r#"{"data": {"id": 1234567, "name":"_acme-challenge.example.com","type":"TXT"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("abc123".to_string()),
                120,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_a_record() {
        let mut server = mockito::Server::new_async().await;
        let expected_body = json!({
            "name": "host.example.com",
            "type": "A",
            "content": "1.2.3.4",
            "ttl": 300,
        });
        let mock = server
            .mock("POST", "/zones/example.com/records")
            .match_body(mockito::Matcher::Json(expected_body))
            .with_status(201)
            .with_body(r#"{"data": {"id": 1, "name":"host.example.com","type":"A"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "host.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_mx_record() {
        let mut server = mockito::Server::new_async().await;
        let expected_body = json!({
            "name": "example.com",
            "type": "MX",
            "content": "mail.example.com",
            "ttl": 3600,
            "priority": 10,
        });
        let mock = server
            .mock("POST", "/zones/example.com/records")
            .match_body(mockito::Matcher::Json(expected_body))
            .with_status(201)
            .with_body(r#"{"data":{"id":2,"name":"example.com","type":"MX"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_record() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("GET", "/zones/example.com/records")
            .with_status(200)
            .with_body(
                r#"{"data":[{"id":99,"name":"host.example.com","type":"A"}]}"#,
            )
            .create();
        let expected_body = json!({
            "name": "host.example.com",
            "type": "A",
            "content": "9.9.9.9",
            "ttl": 600,
        });
        let patch_mock = server
            .mock("PATCH", "/zones/example.com/records/99")
            .match_body(mockito::Matcher::Json(expected_body))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "host.example.com",
                DnsRecord::A("9.9.9.9".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        list_mock.assert();
        patch_mock.assert();
    }

    #[tokio::test]
    async fn test_delete_record() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("GET", "/zones/example.com/records")
            .with_status(200)
            .with_body(
                r#"{"data":[{"id":101,"name":"host.example.com","type":"TXT"}]}"#,
            )
            .create();
        let delete_mock = server
            .mock("DELETE", "/zones/example.com/records/101")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("host.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "{:?}", result);
        list_mock.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    async fn test_create_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/zones/example.com/records")
            .with_status(401)
            .with_body(r#"{"message":"Unauthorized"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "host.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Unauthorized)), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    #[ignore = "Requires SafeDNS auth token"]
    async fn integration_test() {
        let token = "";
        let origin = "";
        let name = "";

        assert!(!token.is_empty(), "Set SAFEDNS_AUTH_TOKEN");
        assert!(!origin.is_empty(), "Set origin");
        assert!(!name.is_empty(), "Set name");

        let provider = SafeDnsProvider::new(token, Some(Duration::from_secs(30)));
        assert!(
            provider
                .create(name, DnsRecord::A("1.1.1.1".parse().unwrap()), 300, origin)
                .await
                .is_ok()
        );
        assert!(
            provider
                .delete(name, origin, DnsRecordType::A)
                .await
                .is_ok()
        );
    }
}
