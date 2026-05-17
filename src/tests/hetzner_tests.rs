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
        providers::hetzner::HetznerProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> HetznerProvider {
        HetznerProvider::new("test_token", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_txt_record_posts_rrset() {
        let mut server = mockito::Server::new_async().await;
        let post = server
            .mock("POST", "/zones/example.com/rrsets")
            .match_header("authorization", "Bearer test_token")
            .match_header("content-type", "application/json")
            .match_body(Matcher::Json(json!({
                "name": "_acme-challenge",
                "type": "TXT",
                "ttl": 600,
                "records": [{"value": "\"foo\""}],
                "zone": "example.com",
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"rrset":{}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("foo".to_string()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        post.assert();
    }

    #[tokio::test]
    async fn test_update_a_record_puts_rrset() {
        let mut server = mockito::Server::new_async().await;
        let put = server
            .mock("PUT", "/zones/example.com/rrsets/www/A")
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "ttl": 3600,
                "records": [{"value": "1.2.3.4"}],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"rrset":{}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "www.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update returned: {result:?}");
        put.assert();
    }

    #[tokio::test]
    async fn test_delete_rrset() {
        let mut server = mockito::Server::new_async().await;
        let delete = server
            .mock("DELETE", "/zones/example.com/rrsets/www/A")
            .match_header("authorization", "Bearer test_token")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("www.example.com", "example.com", DnsRecordType::A)
            .await;

        assert!(result.is_ok(), "delete returned: {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn test_apex_uses_at_sign() {
        let mut server = mockito::Server::new_async().await;
        let post = server
            .mock("POST", "/zones/example.com/rrsets")
            .match_body(Matcher::Json(json!({
                "name": "@",
                "type": "A",
                "ttl": 600,
                "records": [{"value": "1.2.3.4"}],
                "zone": "example.com",
            })))
            .with_status(201)
            .with_body(r#"{"rrset":{}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        post.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("POST", "/zones/example.com/rrsets")
            .with_status(401)
            .with_body(r#"{"error":{"code":"unauthorized","message":"bad token"}}"#)
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
    async fn test_api_error_propagates() {
        let mut server = mockito::Server::new_async().await;
        let failure = server
            .mock("POST", "/zones/example.com/rrsets")
            .with_status(422)
            .with_body(r#"{"error":{"code":"invalid_input","message":"bad value"}}"#)
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
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
        failure.assert();
    }

    #[tokio::test]
    #[ignore = "Requires HETZNER_API_TOKEN, HETZNER_ORIGIN, HETZNER_FQDN"]
    async fn integration_test() {
        let token = std::env::var("HETZNER_API_TOKEN").unwrap_or_default();
        let origin = std::env::var("HETZNER_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("HETZNER_FQDN").unwrap_or_default();

        assert!(!token.is_empty(), "Set HETZNER_API_TOKEN to run this test");
        assert!(!origin.is_empty(), "Set HETZNER_ORIGIN to run this test");
        assert!(!fqdn.is_empty(), "Set HETZNER_FQDN to run this test");

        let updater = DnsUpdater::new_hetzner(token, Some(Duration::from_secs(30))).unwrap();

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
