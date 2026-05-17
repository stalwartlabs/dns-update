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

#![cfg(any(feature = "ring", feature = "aws-lc-rs"))]

#[cfg(test)]
mod tests {
    use crate::{
        DnsRecord, DnsRecordType, DnsUpdater,
        providers::volcengine::{VolcengineConfig, VolcengineProvider},
    };
    use serde_json::json;
    use std::time::Duration;

    fn config() -> VolcengineConfig {
        VolcengineConfig {
            access_key: "AKID-test".into(),
            secret_key: "secret-test".into(),
            region: Some("cn-north-1".into()),
            host: None,
            scheme: Some("http".into()),
            request_timeout: Some(Duration::from_secs(2)),
        }
    }

    fn setup_provider(endpoint: &str) -> VolcengineProvider {
        VolcengineProvider::new(config())
            .expect("provider")
            .with_endpoint(endpoint)
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_volcengine(config());
        assert!(matches!(updater, Ok(DnsUpdater::Volcengine(..))));
    }

    #[test]
    fn missing_credentials_rejected() {
        let cfg = VolcengineConfig {
            access_key: String::new(),
            secret_key: String::new(),
            region: None,
            host: None,
            scheme: None,
            request_timeout: None,
        };
        assert!(VolcengineProvider::new(cfg).is_err());
    }

    #[tokio::test]
    async fn create_record_success() {
        let mut server = mockito::Server::new_async().await;
        let host = server.host_with_port();

        let list_zones = server
            .mock("POST", "/")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("Action".into(), "ListZones".into()),
                mockito::Matcher::UrlEncoded("Version".into(), "2018-08-01".into()),
            ]))
            .match_header("host", host.as_str())
            .with_status(200)
            .with_body(
                json!({
                    "Result": {
                        "Total": 1,
                        "Zones": [{"ZID": 42, "ZoneName": "example.com"}]
                    }
                })
                .to_string(),
            )
            .create();

        let create_mock = server
            .mock("POST", "/")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("Action".into(), "CreateRecord".into()),
                mockito::Matcher::UrlEncoded("Version".into(), "2018-08-01".into()),
            ]))
            .match_body(mockito::Matcher::JsonString(
                json!({
                    "ZID": 42,
                    "Host": "test",
                    "Type": "A",
                    "Value": "1.1.1.1",
                    "TTL": 300
                })
                .to_string(),
            ))
            .with_status(200)
            .with_body(json!({"Result": {"RecordID": "rec-1"}}).to_string())
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create failed: {result:?}");
        list_zones.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let list_zones = server
            .mock("POST", "/")
            .match_query(mockito::Matcher::UrlEncoded(
                "Action".into(),
                "ListZones".into(),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "Result": {
                        "Total": 1,
                        "Zones": [{"ZID": 7, "ZoneName": "example.com"}]
                    }
                })
                .to_string(),
            )
            .create();

        let list_records = server
            .mock("POST", "/")
            .match_query(mockito::Matcher::UrlEncoded(
                "Action".into(),
                "ListRecords".into(),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "Result": {
                        "Records": [
                            {"RecordID": "rec-99", "Host": "test", "Type": "A"}
                        ]
                    }
                })
                .to_string(),
            )
            .create();

        let delete_mock = server
            .mock("POST", "/")
            .match_query(mockito::Matcher::UrlEncoded(
                "Action".into(),
                "DeleteRecord".into(),
            ))
            .match_body(mockito::Matcher::JsonString(
                json!({"RecordID": "rec-99"}).to_string(),
            ))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::A)
            .await;
        assert!(result.is_ok(), "delete failed: {result:?}");
        list_zones.assert();
        list_records.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    async fn list_zones_returns_error_propagates() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_query(mockito::Matcher::UrlEncoded(
                "Action".into(),
                "ListZones".into(),
            ))
            .with_status(403)
            .with_body("forbidden")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(crate::Error::Unauthorized)));
        mock.assert();
    }

    #[tokio::test]
    #[ignore = "Requires VOLC_ACCESSKEY, VOLC_SECRETKEY, VOLC_ORIGIN, VOLC_FQDN"]
    async fn integration_test() {
        let access_key = std::env::var("VOLC_ACCESSKEY").unwrap_or_default();
        let secret_key = std::env::var("VOLC_SECRETKEY").unwrap_or_default();
        let origin = std::env::var("VOLC_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("VOLC_FQDN").unwrap_or_default();
        assert!(!access_key.is_empty() && !secret_key.is_empty());
        assert!(!origin.is_empty() && !fqdn.is_empty());

        let updater = DnsUpdater::new_volcengine(VolcengineConfig {
            access_key,
            secret_key,
            region: None,
            host: None,
            scheme: None,
            request_timeout: Some(Duration::from_secs(30)),
        })
        .unwrap();

        let create = updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 300, &origin)
            .await;
        assert!(create.is_ok(), "create failed: {create:?}");
        let delete = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete.is_ok(), "delete failed: {delete:?}");
    }
}
