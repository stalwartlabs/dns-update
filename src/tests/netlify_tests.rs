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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::netlify::NetlifyProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> NetlifyProvider {
        NetlifyProvider::new("test-token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let create = server
            .mock("POST", "/dns_zones/example_com/dns_records")
            .match_header("authorization", "Bearer test-token")
            .match_body(Matcher::Json(json!({
                "hostname": "test.example.com",
                "type": "A",
                "value": "1.2.3.4",
                "ttl": 300
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"rec-1","hostname":"test.example.com","type":"A","value":"1.2.3.4"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        create.assert();
    }

    #[tokio::test]
    async fn test_delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let list = server
            .mock("GET", "/dns_zones/example_com/dns_records")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"[{"id":"rec-1","hostname":"test.example.com","type":"TXT","value":"abc"}]"#,
            )
            .create();

        let delete = server
            .mock("DELETE", "/dns_zones/example_com/dns_records/rec-1")
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
    async fn test_update_deletes_then_recreates() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/dns_zones/example_com/dns_records")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"[{"id":"rec-9","hostname":"test.example.com","type":"A","value":"1.1.1.1"}]"#,
            )
            .create();
        let delete = server
            .mock("DELETE", "/dns_zones/example_com/dns_records/rec-9")
            .with_status(204)
            .create();
        let create = server
            .mock("POST", "/dns_zones/example_com/dns_records")
            .match_body(Matcher::PartialJson(
                json!({"hostname": "test.example.com", "type": "A", "value": "8.8.8.8"}),
            ))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"rec-10","hostname":"test.example.com","type":"A","value":"8.8.8.8"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("8.8.8.8".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "update returned: {result:?}");
        list.assert();
        delete.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_update_returns_error_when_record_missing() {
        let mut server = mockito::Server::new_async().await;
        let _list = server
            .mock("GET", "/dns_zones/example_com/dns_records")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "missing.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    #[ignore = "Requires NETLIFY_TOKEN, NETLIFY_ORIGIN, NETLIFY_FQDN env vars"]
    async fn integration_test() {
        let token = std::env::var("NETLIFY_TOKEN").unwrap_or_default();
        let origin = std::env::var("NETLIFY_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("NETLIFY_FQDN").unwrap_or_default();
        assert!(!token.is_empty(), "Set NETLIFY_TOKEN");
        assert!(!origin.is_empty(), "Set NETLIFY_ORIGIN");
        assert!(!fqdn.is_empty(), "Set NETLIFY_FQDN");

        let updater = DnsUpdater::new_netlify(token, Some(Duration::from_secs(30))).unwrap();
        let create_result = updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 300, &origin)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");

        let delete_result = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
