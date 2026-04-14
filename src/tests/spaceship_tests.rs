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
        DnsRecord, DnsRecordType, DnsUpdater, MXRecord,
        providers::spaceship::SpaceshipProvider,
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> SpaceshipProvider {
        SpaceshipProvider::new(
            "test_api_key",
            "test_api_secret",
            Some(Duration::from_secs(1)),
        )
        .with_endpoint(endpoint)
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_spaceship(
            "test_api_key",
            "test_api_secret",
            Some(Duration::from_secs(30)),
        );

        assert!(updater.is_ok());
        assert!(
            matches!(updater, Ok(DnsUpdater::Spaceship(..))),
            "Expected Spaceship updater to provide a Spaceship provider"
        );
    }

    #[tokio::test]
    async fn create_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("PUT", "/dns/records/example.com")
            .match_header("x-api-key", "test_api_key")
            .match_header("x-api-secret", "test_api_secret")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "items": [
                    {
                        "type": "A",
                        "name": "test",
                        "address": "1.1.1.1",
                        "ttl": 3600
                    }
                ]
            })))
            .with_status(200)
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
        mock.assert();
    }

    #[tokio::test]
    async fn create_mx_record_uses_preference() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("PUT", "/dns/records/example.com")
            .match_header("x-api-key", "test_api_key")
            .match_header("x-api-secret", "test_api_secret")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "items": [
                    {
                        "type": "MX",
                        "name": "@",
                        "exchange": "mail.example.com",
                        "preference": 10,
                        "ttl": 3600
                    }
                ]
            })))
            .with_status(200)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".into(),
                    priority: 10,
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn update_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("PUT", "/dns/records/example.com")
            .match_header("x-api-key", "test_api_key")
            .match_header("x-api-secret", "test_api_secret")
            .match_body(mockito::Matcher::Json(json!({
                "items": [
                    {
                        "type": "TXT",
                        "name": "_acme-challenge",
                        "value": "txt-value",
                        "ttl": 120
                    }
                ]
            })))
            .with_status(200)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "_acme-challenge.example.com",
                DnsRecord::TXT("txt-value".into()),
                120,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let list_mock = server
            .mock("GET", "/dns/records/example.com")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("take".into(), "100".into()),
                mockito::Matcher::UrlEncoded("skip".into(), "0".into()),
            ]))
            .match_header("x-api-key", "test_api_key")
            .match_header("x-api-secret", "test_api_secret")
            .with_status(200)
            .with_body(r#"{"items":[{"type":"TXT","name":"_acme-challenge","value":"abc","ttl":120},{"type":"A","name":"www","address":"1.1.1.1","ttl":300}],"total":2}"#)
            .create();

        let delete_mock = server
            .mock("DELETE", "/dns/records/example.com")
            .match_header("x-api-key", "test_api_key")
            .match_header("x-api-secret", "test_api_secret")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!([
                {"type":"TXT","name":"_acme-challenge","value":"abc"}
            ])))
            .with_status(200)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete(
                "_acme-challenge.example.com",
                "example.com",
                DnsRecordType::TXT,
            )
            .await;

        assert!(result.is_ok());
        list_mock.assert();
        delete_mock.assert();
    }
}
