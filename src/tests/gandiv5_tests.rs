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
        providers::gandiv5::GandiV5Provider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> GandiV5Provider {
        GandiV5Provider::new("test_token", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let put = server
            .mock("PUT", "/domains/example.com/records/test/A")
            .match_header("authorization", "Bearer test_token")
            .match_header("content-type", "application/json")
            .match_body(Matcher::Json(json!({
                "rrset_ttl": 600,
                "rrset_values": ["1.2.3.4"],
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"DNS Record Created"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        put.assert();
    }

    #[tokio::test]
    async fn test_update_txt_quotes_value() {
        let mut server = mockito::Server::new_async().await;
        let put = server
            .mock("PUT", "/domains/example.com/records/_acme-challenge/TXT")
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "rrset_ttl": 600,
                "rrset_values": ["\"abc\""],
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"DNS Record Created"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "_acme-challenge.example.com",
                DnsRecord::TXT("abc".to_string()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update returned: {result:?}");
        put.assert();
    }

    #[tokio::test]
    async fn test_create_mx_includes_priority_and_trailing_dot() {
        let mut server = mockito::Server::new_async().await;
        let put = server
            .mock("PUT", "/domains/example.com/records/@/MX")
            .match_body(Matcher::Json(json!({
                "rrset_ttl": 3600,
                "rrset_values": ["10 mail.example.com."],
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"ok"}"#)
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
        put.assert();
    }

    #[tokio::test]
    async fn test_delete_calls_delete_endpoint() {
        let mut server = mockito::Server::new_async().await;
        let delete = server
            .mock("DELETE", "/domains/example.com/records/test/A")
            .match_header("authorization", "Bearer test_token")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::A)
            .await;

        assert!(result.is_ok(), "delete returned: {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("PUT", "/domains/example.com/records/test/A")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"Unauthorized"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
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
    async fn test_bad_request_surfaces_api_error() {
        let mut server = mockito::Server::new_async().await;
        let failure = server
            .mock("PUT", "/domains/example.com/records/test/A")
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"Invalid value"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
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
    #[ignore = "Requires GANDIV5_PERSONAL_ACCESS_TOKEN, GANDIV5_ORIGIN, GANDIV5_FQDN"]
    async fn integration_test() {
        let token = std::env::var("GANDIV5_PERSONAL_ACCESS_TOKEN").unwrap_or_default();
        let origin = std::env::var("GANDIV5_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("GANDIV5_FQDN").unwrap_or_default();

        assert!(
            !token.is_empty(),
            "Set GANDIV5_PERSONAL_ACCESS_TOKEN to run this test"
        );
        assert!(!origin.is_empty(), "Set GANDIV5_ORIGIN to run this test");
        assert!(!fqdn.is_empty(), "Set GANDIV5_FQDN to run this test");

        let updater = DnsUpdater::new_gandiv5(token, Some(Duration::from_secs(30))).unwrap();

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
