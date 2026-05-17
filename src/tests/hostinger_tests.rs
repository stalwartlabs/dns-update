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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::hostinger::HostingerProvider,
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> HostingerProvider {
        HostingerProvider::new("test_token", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_hostinger("test_token", Some(Duration::from_secs(30)));
        assert!(updater.is_ok());
        assert!(matches!(updater, Ok(DnsUpdater::Hostinger(..))));
    }

    #[test]
    fn empty_token_rejected() {
        let result = HostingerProvider::new("", None);
        assert!(matches!(result, Err(Error::Api(msg)) if msg.contains("empty")));
    }

    #[tokio::test]
    async fn create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;

        let zone_get = server
            .mock("GET", "/api/dns/v1/zones/example.com")
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_body("[]")
            .create();

        let put_mock = server
            .mock("PUT", "/api/dns/v1/zones/example.com")
            .match_header("authorization", "Bearer test_token")
            .match_body(mockito::Matcher::Json(json!({
                "overwrite": true,
                "zone": [{
                    "name": "_acme-challenge",
                    "type": "TXT",
                    "ttl": 300,
                    "records": [{ "content": "token-value" }]
                }]
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("token-value".to_string()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        zone_get.assert();
        put_mock.assert();
    }

    #[tokio::test]
    async fn create_a_record_success() {
        let mut server = mockito::Server::new_async().await;

        let zone_get = server
            .mock("GET", "/api/dns/v1/zones/example.com")
            .with_status(200)
            .with_body("[]")
            .create();

        let put_mock = server
            .mock("PUT", "/api/dns/v1/zones/example.com")
            .match_body(mockito::Matcher::Json(json!({
                "overwrite": true,
                "zone": [{
                    "name": "www",
                    "type": "A",
                    "ttl": 3600,
                    "records": [{ "content": "1.1.1.1" }]
                }]
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        zone_get.assert();
        put_mock.assert();
    }

    #[tokio::test]
    async fn update_record_success() {
        let mut server = mockito::Server::new_async().await;

        let put_mock = server
            .mock("PUT", "/api/dns/v1/zones/example.com")
            .match_header("authorization", "Bearer test_token")
            .match_body(mockito::Matcher::Json(json!({
                "overwrite": true,
                "zone": [{
                    "name": "www",
                    "type": "AAAA",
                    "ttl": 3600,
                    "records": [{ "content": "2001:db8::2" }]
                }]
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .update(
                "www.example.com",
                DnsRecord::AAAA("2001:db8::2".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        put_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let delete_mock = server
            .mock("DELETE", "/api/dns/v1/zones/example.com")
            .match_header("authorization", "Bearer test_token")
            .match_body(mockito::Matcher::Json(json!({
                "filters": [{ "name": "www", "type": "TXT" }]
            })))
            .with_status(204)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .delete("www.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok());
        delete_mock.assert();
    }

    #[tokio::test]
    async fn unauthorized_response() {
        let mut server = mockito::Server::new_async().await;

        let _zone_get = server
            .mock("GET", "/api/dns/v1/zones/example.com")
            .with_status(401)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "x.example.com",
                DnsRecord::TXT("v".to_string()),
                300,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Unauthorized)));
    }

    #[tokio::test]
    #[ignore = "Requires Hostinger API token and configured domain"]
    async fn integration_test() {
        let token = "";
        let origin = "";
        let subdomain = "";

        assert!(!token.is_empty(), "Configure token in the integration test");
        assert!(
            !origin.is_empty(),
            "Configure origin in the integration test"
        );
        assert!(
            !subdomain.is_empty(),
            "Configure subdomain in the integration test"
        );

        let provider = HostingerProvider::new(token, Some(Duration::from_secs(30))).unwrap();

        assert!(
            provider
                .create(
                    subdomain,
                    DnsRecord::TXT("integration".to_string()),
                    300,
                    origin
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .delete(subdomain, origin, DnsRecordType::TXT)
                .await
                .is_ok()
        );
    }
}
