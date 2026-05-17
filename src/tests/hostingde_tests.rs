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
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, Error, providers::hostingde::HostingDeProvider};
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> HostingDeProvider {
        HostingDeProvider::new("auth-token", Some(Duration::from_secs(1)))
            .with_endpoint(endpoint)
    }

    fn zone_find_response() -> String {
        json!({
            "status": "success",
            "errors": [],
            "response": {
                "data": [{
                    "id": "zone-1",
                    "name": "example.com",
                    "status": "active"
                }]
            }
        })
        .to_string()
    }

    #[tokio::test]
    async fn test_create_record_success() {
        let mut server = mockito::Server::new_async().await;
        let zone = server
            .mock("POST", "/zoneConfigsFind")
            .match_body(Matcher::PartialJson(json!({"authToken": "auth-token"})))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(zone_find_response())
            .create();

        let update = server
            .mock("POST", "/zoneUpdate")
            .match_body(Matcher::PartialJson(json!({
                "authToken": "auth-token",
                "recordsToAdd": [{
                    "name": "test.example.com",
                    "type": "A",
                    "content": "1.2.3.4",
                    "ttl": 300
                }]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"success","errors":[],"response":{}}"#)
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
        zone.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let zone = server
            .mock("POST", "/zoneConfigsFind")
            .with_status(200)
            .with_body(zone_find_response())
            .create();

        let records_find = server
            .mock("POST", "/recordsFind")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"status":"success","errors":[],"response":{"data":[{"id":"rec-1","name":"test.example.com","type":"TXT","content":"\"abc\""}]}}"#,
            )
            .create();

        let update = server
            .mock("POST", "/zoneUpdate")
            .match_body(Matcher::PartialJson(json!({
                "recordsToDelete": [{
                    "id": "rec-1",
                    "name": "test.example.com",
                    "type": "TXT",
                    "content": "\"abc\""
                }]
            })))
            .with_status(200)
            .with_body(r#"{"status":"success","errors":[],"response":{}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;
        assert!(result.is_ok(), "delete returned: {result:?}");
        zone.assert();
        records_find.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_zone_not_active_returns_error() {
        let mut server = mockito::Server::new_async().await;
        let _zone = server
            .mock("POST", "/zoneConfigsFind")
            .with_status(200)
            .with_body(
                r#"{"status":"success","errors":[],"response":{"data":[{"id":"z","name":"example.com","status":"pending"}]}}"#,
            )
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
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    #[ignore = "Requires HOSTINGDE_API_KEY, HOSTINGDE_ORIGIN, HOSTINGDE_FQDN env vars"]
    async fn integration_test() {
        let api_key = std::env::var("HOSTINGDE_API_KEY").unwrap_or_default();
        let origin = std::env::var("HOSTINGDE_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("HOSTINGDE_FQDN").unwrap_or_default();
        assert!(!api_key.is_empty(), "Set HOSTINGDE_API_KEY");
        assert!(!origin.is_empty(), "Set HOSTINGDE_ORIGIN");
        assert!(!fqdn.is_empty(), "Set HOSTINGDE_FQDN");

        let updater = DnsUpdater::new_hostingde(api_key, Some(Duration::from_secs(30))).unwrap();
        let create_result = updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 300, &origin)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");

        let delete_result = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
