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
        providers::godaddy::GodaddyProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> GodaddyProvider {
        GodaddyProvider::new("test_key", "test_secret", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let put = server
            .mock("PUT", "/v1/domains/example.com/records/A/www")
            .match_header("authorization", "sso-key test_key:test_secret")
            .match_header("content-type", "application/json")
            .match_body(Matcher::Json(json!([{
                "data": "1.2.3.4",
                "ttl": 600,
            }])))
            .with_status(200)
            .with_body("[]")
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
        put.assert();
    }

    #[tokio::test]
    async fn test_update_mx_record_includes_priority() {
        let mut server = mockito::Server::new_async().await;
        let put = server
            .mock("PUT", "/v1/domains/example.com/records/MX/@")
            .match_body(Matcher::Json(json!([{
                "data": "mail.example.com",
                "ttl": 3600,
                "priority": 10,
            }])))
            .with_status(200)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update returned: {result:?}");
        put.assert();
    }

    #[tokio::test]
    async fn test_delete_calls_delete_endpoint() {
        let mut server = mockito::Server::new_async().await;
        let delete = server
            .mock("DELETE", "/v1/domains/example.com/records/TXT/_acme-challenge")
            .match_header("authorization", "sso-key test_key:test_secret")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete(
                "_acme-challenge.example.com",
                "example.com",
                DnsRecordType::TXT,
            )
            .await;

        assert!(result.is_ok(), "delete returned: {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn test_tlsa_record_is_unsupported() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());

        let result = provider
            .create(
                "_443._tcp.example.com",
                DnsRecord::TLSA(crate::TLSARecord {
                    cert_usage: crate::TlsaCertUsage::DaneEe,
                    selector: crate::TlsaSelector::Spki,
                    matching: crate::TlsaMatching::Sha256,
                    cert_data: vec![0xab, 0xcd],
                }),
                300,
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api for TLSA, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("PUT", "/v1/domains/example.com/records/A/www")
            .with_status(401)
            .with_body(r#"{"code":"UNAUTHORIZED","message":"Unauthorized"}"#)
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
    #[ignore = "Requires GODADDY_API_KEY, GODADDY_API_SECRET, GODADDY_ORIGIN, GODADDY_FQDN"]
    async fn integration_test() {
        let key = std::env::var("GODADDY_API_KEY").unwrap_or_default();
        let secret = std::env::var("GODADDY_API_SECRET").unwrap_or_default();
        let origin = std::env::var("GODADDY_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("GODADDY_FQDN").unwrap_or_default();

        assert!(!key.is_empty(), "Set GODADDY_API_KEY to run this test");
        assert!(!secret.is_empty(), "Set GODADDY_API_SECRET to run this test");
        assert!(!origin.is_empty(), "Set GODADDY_ORIGIN to run this test");
        assert!(!fqdn.is_empty(), "Set GODADDY_FQDN to run this test");

        let updater =
            DnsUpdater::new_godaddy(key, secret, Some(Duration::from_secs(30))).unwrap();

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
