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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::plesk::PleskProvider,
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> PleskProvider {
        PleskProvider::new(endpoint, "test_api_key", Some(Duration::from_secs(1)))
            .with_endpoint(endpoint)
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_plesk(
            "https://plesk.example.com:8443",
            "test_api_key",
            Some(Duration::from_secs(30)),
        );

        assert!(matches!(updater, Ok(DnsUpdater::Plesk(..))));
    }

    #[tokio::test]
    async fn create_record_success() {
        let mut server = mockito::Server::new_async().await;

        let domain_mock = server
            .mock("GET", "/api/v2/domains")
            .match_query(mockito::Matcher::UrlEncoded(
                "name".into(),
                "example.com".into(),
            ))
            .match_header("x-api-key", "test_api_key")
            .with_status(200)
            .with_body(r#"[{"id": 42, "name": "example.com"}]"#)
            .create();

        let create_mock = server
            .mock("POST", "/api/v2/dns/records")
            .match_header("x-api-key", "test_api_key")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "siteId": 42,
                "type": "A",
                "host": "test",
                "value": "1.1.1.1",
                "ttl": 3600
            })))
            .with_status(200)
            .with_body(r#"{"id": 1001}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        domain_mock.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let domain_mock = server
            .mock("GET", "/api/v2/domains")
            .match_query(mockito::Matcher::UrlEncoded(
                "name".into(),
                "example.com".into(),
            ))
            .with_status(200)
            .with_body(r#"[{"id": 42, "name": "example.com"}]"#)
            .expect_at_least(1)
            .create();

        let list_mock = server
            .mock("GET", "/api/v2/dns/records")
            .match_query(mockito::Matcher::UrlEncoded("siteId".into(), "42".into()))
            .with_status(200)
            .with_body(
                r#"[
                    {"id": 1001, "siteId": 42, "type": "TXT", "host": "_acme-challenge.example.com", "value": "abc", "opt": ""},
                    {"id": 1002, "siteId": 42, "type": "A", "host": "www.example.com", "value": "1.1.1.1", "opt": ""}
                ]"#,
            )
            .create();

        let delete_mock = server
            .mock("DELETE", "/api/v2/dns/records/1001")
            .match_header("x-api-key", "test_api_key")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete(
                "_acme-challenge.example.com",
                "example.com",
                DnsRecordType::TXT,
            )
            .await;

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        domain_mock.assert();
        list_mock.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    async fn update_record_replaces_existing() {
        let mut server = mockito::Server::new_async().await;

        let domain_mock = server
            .mock("GET", "/api/v2/domains")
            .match_query(mockito::Matcher::UrlEncoded(
                "name".into(),
                "example.com".into(),
            ))
            .expect_at_least(2)
            .with_status(200)
            .with_body(r#"[{"id": 42, "name": "example.com"}]"#)
            .create();

        let list_mock = server
            .mock("GET", "/api/v2/dns/records")
            .match_query(mockito::Matcher::UrlEncoded("siteId".into(), "42".into()))
            .with_status(200)
            .with_body(
                r#"[{"id": 2001, "siteId": 42, "type": "A", "host": "test.example.com", "value": "1.1.1.1", "opt": ""}]"#,
            )
            .create();

        let delete_mock = server
            .mock("DELETE", "/api/v2/dns/records/2001")
            .with_status(204)
            .create();

        let create_mock = server
            .mock("POST", "/api/v2/dns/records")
            .match_body(mockito::Matcher::Json(json!({
                "siteId": 42,
                "type": "A",
                "host": "test",
                "value": "2.2.2.2",
                "ttl": 300
            })))
            .with_status(200)
            .with_body(r#"{"id": 2002}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("2.2.2.2".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        domain_mock.assert();
        list_mock.assert();
        delete_mock.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_not_found() {
        let mut server = mockito::Server::new_async().await;

        let _domain_mock = server
            .mock("GET", "/api/v2/domains")
            .match_query(mockito::Matcher::UrlEncoded(
                "name".into(),
                "example.com".into(),
            ))
            .with_status(200)
            .with_body(r#"[{"id": 42, "name": "example.com"}]"#)
            .expect_at_least(1)
            .create();

        let _list_mock = server
            .mock("GET", "/api/v2/dns/records")
            .match_query(mockito::Matcher::UrlEncoded("siteId".into(), "42".into()))
            .with_status(200)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("missing.example.com", "example.com", DnsRecordType::A)
            .await;

        assert!(matches!(result, Err(Error::NotFound)));
    }

    #[tokio::test]
    #[ignore = "Requires Plesk server URL and API key configuration"]
    async fn integration_test() {
        let base_url = std::env::var("PLESK_BASE_URL").unwrap_or_default();
        let api_key = std::env::var("PLESK_API_KEY").unwrap_or_default();
        let origin = std::env::var("PLESK_ORIGIN").unwrap_or_default();
        let domain = std::env::var("PLESK_DOMAIN").unwrap_or_default();

        assert!(
            !base_url.is_empty(),
            "Please configure PLESK_BASE_URL (e.g. https://plesk.example.com:8443)"
        );
        assert!(!api_key.is_empty(), "Please configure PLESK_API_KEY");
        assert!(
            !origin.is_empty(),
            "Please configure PLESK_ORIGIN (zone name)"
        );
        assert!(
            !domain.is_empty(),
            "Please configure PLESK_DOMAIN (FQDN to add record under)"
        );

        let updater =
            DnsUpdater::new_plesk(base_url, api_key, Some(Duration::from_secs(30))).unwrap();

        assert!(
            updater
                .create(&domain, DnsRecord::A([1, 1, 1, 1].into()), 300, &origin)
                .await
                .is_ok()
        );
        assert!(
            updater
                .update(&domain, DnsRecord::A([8, 8, 8, 8].into()), 300, &origin)
                .await
                .is_ok()
        );
        assert!(updater.delete(&domain, &origin, DnsRecordType::A).await.is_ok());
    }
}
