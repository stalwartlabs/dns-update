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
        providers::yandexcloud::{YandexCloudConfig, YandexCloudProvider},
    };
    use serde_json::json;
    use std::time::Duration;

    fn config() -> YandexCloudConfig {
        let key_json = json!({
            "id": "key-id",
            "service_account_id": "svc-account",
            "private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        });
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            key_json.to_string().as_bytes(),
        );
        YandexCloudConfig {
            iam_token_b64: encoded,
            folder_id: "folder-1".into(),
            request_timeout: Some(Duration::from_secs(2)),
        }
    }

    fn setup_provider(iam: &str, dns: &str) -> YandexCloudProvider {
        YandexCloudProvider::new(config())
            .expect("provider")
            .with_endpoints(iam, dns)
            .with_cached_token("cached-token")
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_yandexcloud(config());
        assert!(matches!(updater, Ok(DnsUpdater::YandexCloud(..))));
    }

    #[test]
    fn missing_folder_rejected() {
        let cfg = YandexCloudConfig {
            iam_token_b64: "abc".into(),
            folder_id: String::new(),
            request_timeout: None,
        };
        assert!(YandexCloudProvider::new(cfg).is_err());
    }

    #[tokio::test]
    async fn create_record_success() {
        let mut server = mockito::Server::new_async().await;

        let zones_mock = server
            .mock("GET", "/dns/v1/zones")
            .match_query(mockito::Matcher::UrlEncoded(
                "folderId".into(),
                "folder-1".into(),
            ))
            .match_header("authorization", "Bearer cached-token")
            .with_status(200)
            .with_body(
                json!({
                    "dnsZones": [
                        {"id": "zone-1", "zone": "example.com."}
                    ]
                })
                .to_string(),
            )
            .create();

        let get_rs_mock = server
            .mock("GET", "/dns/v1/zones/zone-1:getRecordSet")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "test".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(404)
            .with_body("{}")
            .create();

        let update_mock = server
            .mock("POST", "/dns/v1/zones/zone-1:updateRecordSets")
            .match_header("authorization", "Bearer cached-token")
            .match_body(mockito::Matcher::Json(json!({
                "additions": [{
                    "name": "test",
                    "type": "A",
                    "ttl": 300,
                    "data": ["1.1.1.1"]
                }]
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create failed: {result:?}");
        zones_mock.assert();
        get_rs_mock.assert();
        update_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let zones_mock = server
            .mock("GET", "/dns/v1/zones")
            .match_query(mockito::Matcher::UrlEncoded(
                "folderId".into(),
                "folder-1".into(),
            ))
            .with_status(200)
            .with_body(
                json!({"dnsZones": [{"id": "zone-1", "zone": "example.com."}]}).to_string(),
            )
            .create();

        let get_rs_mock = server
            .mock("GET", "/dns/v1/zones/zone-1:getRecordSet")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "test".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(
                json!({
                    "name": "test",
                    "type": "A",
                    "ttl": 300,
                    "data": ["1.1.1.1"]
                })
                .to_string(),
            )
            .create();

        let update_mock = server
            .mock("POST", "/dns/v1/zones/zone-1:updateRecordSets")
            .match_body(mockito::Matcher::Json(json!({
                "deletions": [{
                    "name": "test",
                    "type": "A",
                    "ttl": 300,
                    "data": ["1.1.1.1"]
                }]
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::A)
            .await;
        assert!(result.is_ok(), "delete failed: {result:?}");
        zones_mock.assert();
        get_rs_mock.assert();
        update_mock.assert();
    }

    #[tokio::test]
    async fn list_zones_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/dns/v1/zones")
            .match_query(mockito::Matcher::Any)
            .with_status(401)
            .create();
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(crate::Error::Unauthorized)),
            "expected Unauthorized, got: {:?}",
            result
        );
        mock.assert();
    }

    #[tokio::test]
    #[ignore = "Requires YANDEX_CLOUD_IAM_TOKEN, YANDEX_CLOUD_FOLDER_ID, YANDEX_CLOUD_ORIGIN, YANDEX_CLOUD_FQDN"]
    async fn integration_test() {
        let iam = std::env::var("YANDEX_CLOUD_IAM_TOKEN").unwrap_or_default();
        let folder = std::env::var("YANDEX_CLOUD_FOLDER_ID").unwrap_or_default();
        let origin = std::env::var("YANDEX_CLOUD_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("YANDEX_CLOUD_FQDN").unwrap_or_default();
        assert!(!iam.is_empty() && !folder.is_empty());
        assert!(!origin.is_empty() && !fqdn.is_empty());

        let updater = DnsUpdater::new_yandexcloud(YandexCloudConfig {
            iam_token_b64: iam,
            folder_id: folder,
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
