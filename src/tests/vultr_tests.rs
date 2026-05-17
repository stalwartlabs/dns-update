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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::vultr::VultrProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const RECORD_ID: &str = "rec-123";

    fn setup_provider(endpoint: String) -> VultrProvider {
        VultrProvider::new("test_token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    fn mock_records_list(server: &mut ServerGuard, sub: &str, rtype: &str) -> Mock {
        server
            .mock("GET", "/domains/example.com/records")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"records":[{{"id":"{RECORD_ID}","type":"{rtype}","name":"{sub}","data":"x"}}]}}"#
            ))
            .create()
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let create = server
            .mock("POST", "/domains/example.com/records")
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "name": "test",
                "type": "A",
                "data": "1.1.1.1",
                "ttl": 3600,
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"record":{"id":"rec-123"}}"#)
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
        create.assert();
    }

    #[tokio::test]
    async fn test_update_resolves_record_id() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_records_list(&mut server, "test", "A");
        let update = server
            .mock(
                "PATCH",
                format!("/domains/example.com/records/{RECORD_ID}").as_str(),
            )
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "name": "test",
                "data": "8.8.8.8",
                "ttl": 3600,
            })))
            .with_status(204)
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
        list.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_delete_resolves_record_id() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_records_list(&mut server, "test", "TXT");
        let delete = server
            .mock(
                "DELETE",
                format!("/domains/example.com/records/{RECORD_ID}").as_str(),
            )
            .match_header("authorization", "Bearer test_token")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete returned: {result:?}");
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("POST", "/domains/example.com/records")
            .with_status(401)
            .with_body(r#"{"error":"Invalid token"}"#)
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
    async fn test_update_returns_api_error_when_record_missing() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/domains/example.com/records")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"records":[]}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "missing.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
        list.assert();
    }

    #[tokio::test]
    #[ignore = "Requires Vultr API key, domain, and FQDN"]
    async fn integration_test() {
        let key = std::env::var("VULTR_API_KEY").unwrap_or_default();
        let origin = std::env::var("VULTR_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("VULTR_FQDN").unwrap_or_default();

        assert!(!key.is_empty(), "Set VULTR_API_KEY to run this test");
        assert!(!origin.is_empty(), "Set VULTR_ORIGIN to run this test");
        assert!(!fqdn.is_empty(), "Set VULTR_FQDN to run this test");

        let updater = DnsUpdater::new_vultr(key, Some(Duration::from_secs(30))).unwrap();

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
