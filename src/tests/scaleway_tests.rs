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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::scaleway::ScalewayProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> ScalewayProvider {
        ScalewayProvider::new("test_token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let create = server
            .mock("PATCH", "/dns-zones/example.com/records")
            .match_header("x-auth-token", "test_token")
            .match_body(Matcher::Json(json!({
                "return_all_records": false,
                "disallow_new_zone_creation": true,
                "changes": [{
                    "add": {
                        "records": [{
                            "name": "test.example.com",
                            "type": "A",
                            "data": "1.1.1.1",
                            "ttl": 3600,
                        }]
                    }
                }]
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
        create.assert();
    }

    #[tokio::test]
    async fn test_update_sends_set_change() {
        let mut server = mockito::Server::new_async().await;
        let update = server
            .mock("PATCH", "/dns-zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "return_all_records": false,
                "disallow_new_zone_creation": true,
                "changes": [{
                    "set": {
                        "id_fields": {"name": "test.example.com", "type": "A"},
                        "records": [{
                            "name": "test.example.com",
                            "type": "A",
                            "data": "8.8.8.8",
                            "ttl": 3600,
                        }]
                    }
                }]
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
        update.assert();
    }

    #[tokio::test]
    async fn test_delete_sends_delete_change() {
        let mut server = mockito::Server::new_async().await;
        let delete = server
            .mock("PATCH", "/dns-zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "return_all_records": false,
                "disallow_new_zone_creation": true,
                "changes": [{
                    "delete": {
                        "id_fields": {"name": "test.example.com", "type": "TXT"}
                    }
                }]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete returned: {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("PATCH", "/dns-zones/example.com/records")
            .with_status(401)
            .with_body(r#"{"message":"denied authentication"}"#)
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
    async fn test_create_txt_record_quotes_value() {
        let mut server = mockito::Server::new_async().await;
        let create = server
            .mock("PATCH", "/dns-zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "return_all_records": false,
                "disallow_new_zone_creation": true,
                "changes": [{
                    "add": {
                        "records": [{
                            "name": "test.example.com",
                            "type": "TXT",
                            "data": "\"v=spf1 -all\"",
                            "ttl": 300,
                        }]
                    }
                }]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::TXT("v=spf1 -all".to_string()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        create.assert();
    }

    #[tokio::test]
    #[ignore = "Requires Scaleway API token, zone, and FQDN"]
    async fn integration_test() {
        let token = std::env::var("SCALEWAY_API_TOKEN").unwrap_or_default();
        let origin = std::env::var("SCALEWAY_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("SCALEWAY_FQDN").unwrap_or_default();

        assert!(!token.is_empty(), "Set SCALEWAY_API_TOKEN to run this test");
        assert!(!origin.is_empty(), "Set SCALEWAY_ORIGIN to run this test");
        assert!(!fqdn.is_empty(), "Set SCALEWAY_FQDN to run this test");

        let updater = DnsUpdater::new_scaleway(token, Some(Duration::from_secs(30))).unwrap();

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
