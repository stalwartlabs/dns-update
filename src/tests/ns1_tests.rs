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
        DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, providers::ns1::Ns1Provider,
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> Ns1Provider {
        Ns1Provider::new("test_key", Some(Duration::from_secs(5))).with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let expected = json!({
            "zone": "example.com",
            "domain": "test.example.com",
            "type": "A",
            "ttl": 300,
            "answers": [{"answer": ["1.1.1.1"]}],
        });

        let mock = server
            .mock("PUT", "/zones/example.com/test.example.com/A")
            .match_header("x-nsone-key", "test_key")
            .match_body(mockito::Matcher::Json(expected))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
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

        assert!(result.is_ok(), "create failed: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_mx_record_success() {
        let mut server = mockito::Server::new_async().await;
        let expected = json!({
            "zone": "example.com",
            "domain": "example.com",
            "type": "MX",
            "ttl": 600,
            "answers": [{"answer": ["10", "mail.example.com"]}],
        });

        let mock = server
            .mock("POST", "/zones/example.com/example.com/MX")
            .match_header("x-nsone-key", "test_key")
            .match_body(mockito::Matcher::Json(expected))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                }),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update failed: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("DELETE", "/zones/example.com/test.example.com/TXT")
            .match_header("x-nsone-key", "test_key")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete failed: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("PUT", "/zones/example.com/test.example.com/A")
            .with_status(401)
            .with_body(r#"{"message": "Unauthorized"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Unauthorized)));
        mock.assert();
    }

    #[tokio::test]
    #[ignore = "Requires NS1 API key, zone, and FQDN"]
    async fn integration_test() {
        let api_key = std::env::var("NS1_API_KEY").unwrap_or_default();
        let origin = std::env::var("NS1_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("NS1_FQDN").unwrap_or_default();

        assert!(!api_key.is_empty(), "Set NS1_API_KEY to run this test");
        assert!(!origin.is_empty(), "Set NS1_ORIGIN to run this test");
        assert!(!fqdn.is_empty(), "Set NS1_FQDN to run this test");

        let updater = DnsUpdater::new_ns1(api_key, Some(Duration::from_secs(30))).unwrap();
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
    fn provider_creation() {
        let provider = Ns1Provider::new("mock", Some(Duration::from_secs(1)));
        let _ = provider;
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_ns1("mock", Some(Duration::from_secs(30)));
        assert!(matches!(updater, Ok(DnsUpdater::Ns1(..))));
    }
}
