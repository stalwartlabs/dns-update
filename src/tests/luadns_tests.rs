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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::luadns::LuaDnsProvider,
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> LuaDnsProvider {
        LuaDnsProvider::new("user@example.com", "secret_token", Some(Duration::from_secs(5)))
            .with_endpoint(endpoint)
    }

    fn zones_response() -> String {
        r#"[
            {"id": 1, "name": "example.com"},
            {"id": 2, "name": "example.net"}
        ]"#
        .to_string()
    }

    #[tokio::test]
    async fn test_create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;
        let zones_mock = server
            .mock("GET", "/v1/zones")
            .match_header("authorization", "Basic dXNlckBleGFtcGxlLmNvbTpzZWNyZXRfdG9rZW4=")
            .with_status(200)
            .with_body(zones_response())
            .create();

        let expected = json!({
            "name": "test.example.com.",
            "type": "TXT",
            "content": "\"hello\"",
            "ttl": 300,
        });
        let create_mock = server
            .mock("POST", "/v1/zones/1/records")
            .match_header("authorization", "Basic dXNlckBleGFtcGxlLmNvbTpzZWNyZXRfdG9rZW4=")
            .match_body(mockito::Matcher::Json(expected))
            .with_status(200)
            .with_body(
                r#"{"id": 100, "name": "test.example.com.", "type": "TXT", "content": "\"hello\"", "ttl": 300, "zone_id": 1}"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::TXT("hello".to_string()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create failed: {result:?}");
        zones_mock.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn test_update_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let zones_mock = server
            .mock("GET", "/v1/zones")
            .with_status(200)
            .with_body(zones_response())
            .expect_at_least(1)
            .create();

        let records_mock = server
            .mock("GET", "/v1/zones/1/records")
            .with_status(200)
            .with_body(
                r#"[{"id": 42, "name": "test.example.com.", "type": "A", "content": "1.1.1.1", "ttl": 300, "zone_id": 1}]"#,
            )
            .create();

        let expected = json!({
            "name": "test.example.com.",
            "type": "A",
            "content": "8.8.8.8",
            "ttl": 600,
        });
        let update_mock = server
            .mock("PUT", "/v1/zones/1/records/42")
            .match_body(mockito::Matcher::Json(expected))
            .with_status(200)
            .with_body(
                r#"{"id": 42, "name": "test.example.com.", "type": "A", "content": "8.8.8.8", "ttl": 600, "zone_id": 1}"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("8.8.8.8".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update failed: {result:?}");
        zones_mock.assert();
        records_mock.assert();
        update_mock.assert();
    }

    #[tokio::test]
    async fn test_delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let _zones_mock = server
            .mock("GET", "/v1/zones")
            .with_status(200)
            .with_body(zones_response())
            .create();

        let _records_mock = server
            .mock("GET", "/v1/zones/1/records")
            .with_status(200)
            .with_body(
                r#"[{"id": 7, "name": "test.example.com.", "type": "TXT", "content": "\"x\"", "ttl": 300, "zone_id": 1}]"#,
            )
            .create();

        let delete_mock = server
            .mock("DELETE", "/v1/zones/1/records/7")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete failed: {result:?}");
        delete_mock.assert();
    }

    #[tokio::test]
    async fn test_create_zone_not_found() {
        let mut server = mockito::Server::new_async().await;
        let _zones_mock = server
            .mock("GET", "/v1/zones")
            .with_status(200)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(_))));
    }

    #[tokio::test]
    #[ignore = "Requires LuaDNS API username, token, zone, and FQDN"]
    async fn integration_test() {
        let user = std::env::var("LUADNS_API_USERNAME").unwrap_or_default();
        let token = std::env::var("LUADNS_API_TOKEN").unwrap_or_default();
        let origin = std::env::var("LUADNS_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("LUADNS_FQDN").unwrap_or_default();

        assert!(!user.is_empty() && !token.is_empty());
        assert!(!origin.is_empty());
        assert!(!fqdn.is_empty());

        let updater =
            DnsUpdater::new_luadns(user, token, Some(Duration::from_secs(30))).unwrap();
        let create = updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 300, &origin)
            .await;
        assert!(create.is_ok(), "create failed: {create:?}");
        let update = updater
            .update(&fqdn, DnsRecord::A([8, 8, 8, 8].into()), 300, &origin)
            .await;
        assert!(update.is_ok(), "update failed: {update:?}");
        let delete = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete.is_ok(), "delete failed: {delete:?}");
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_luadns(
            "user",
            "token",
            Some(Duration::from_secs(30)),
        );
        assert!(matches!(updater, Ok(DnsUpdater::LuaDns(..))));
    }
}
