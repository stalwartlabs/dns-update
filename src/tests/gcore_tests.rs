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
        DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord,
        providers::gcore::GcoreProvider,
    };
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
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let create = server
            .mock("POST", "/v2/zones/example.com/test.example.com/A")
            .match_header("authorization", "APIKey test_token")
            .match_body(Matcher::Json(json!({
                "ttl": 3600,
                "resource_records": [{"content": ["1.1.1.1"]}],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        zone.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_update_replaces_rrset() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let update = server
            .mock("PUT", "/v2/zones/example.com/test.example.com/A")
            .match_body(Matcher::Json(json!({
                "ttl": 3600,
                "resource_records": [{"content": ["8.8.8.8"]}],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("8.8.8.8".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update returned: {result:?}");
        zone.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_delete_removes_rrset() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let delete = server
            .mock("DELETE", "/v2/zones/example.com/test.example.com/TXT")
            .match_header("authorization", "APIKey test_token")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete returned: {result:?}");
        zone.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("GET", "/v2/zones/example.com")
            .with_status(401)
            .with_body(r#"{"error":"unauthorized"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
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
    async fn test_create_mx_record_sends_priority_and_exchange() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let create = server
            .mock("POST", "/v2/zones/example.com/example.com/MX")
            .match_body(Matcher::Json(json!({
                "ttl": 3600,
                "resource_records": [{"content": [10, "mail.example.com"]}],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
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

        assert!(result.is_ok(), "create returned: {result:?}");
        zone.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_zone_walks_up_when_subdomain_not_found() {
        let mut server = mockito::Server::new_async().await;
        let zone_miss = server
            .mock("GET", "/v2/zones/sub.example.com")
            .with_status(404)
            .with_body(r#"{"error":"not found"}"#)
            .create();
        let zone_hit = mock_zone_lookup(&mut server, "example.com");
        let create = server
            .mock("POST", "/v2/zones/example.com/host.sub.example.com/A")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "host.sub.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                3600,
                "sub.example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        zone_miss.assert();
        zone_hit.assert();
        create.assert();
    }

    #[tokio::test]
    #[ignore = "Requires Gcore permanent API token, zone, and FQDN"]
    async fn integration_test() {
        let token = std::env::var("GCORE_PERMANENT_API_TOKEN").unwrap_or_default();
        let origin = std::env::var("GCORE_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("GCORE_FQDN").unwrap_or_default();

        assert!(
            !token.is_empty(),
            "Set GCORE_PERMANENT_API_TOKEN to run this test"
        );
        assert!(!origin.is_empty(), "Set GCORE_ORIGIN to run this test");
        assert!(!fqdn.is_empty(), "Set GCORE_FQDN to run this test");

        let updater = DnsUpdater::new_gcore(token, Some(Duration::from_secs(30))).unwrap();

        let create_result = updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 300, &origin)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");

        let update_result = updater
            .update(&fqdn, DnsRecord::A([8, 8, 8, 8].into()), 300, &origin)
            .await;
        assert!(update_result.is_ok(), "update failed: {update_result:?}");

        let delete_result = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
