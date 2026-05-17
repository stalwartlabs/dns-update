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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::autodns::AutodnsProvider,
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> AutodnsProvider {
        AutodnsProvider::new("user", "pass", Some(4), Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[test]
    fn dns_updater_creation() {
        let updater =
            DnsUpdater::new_autodns("user", "pass", Some(4), Some(Duration::from_secs(30)));
        assert!(updater.is_ok());
        assert!(matches!(updater, Ok(DnsUpdater::Autodns(..))));
    }

    #[test]
    fn empty_credentials_rejected() {
        assert!(matches!(
            AutodnsProvider::new("", "pass", None, None),
            Err(Error::Api(_))
        ));
        assert!(matches!(
            AutodnsProvider::new("user", "", None, None),
            Err(Error::Api(_))
        ));
    }

    #[tokio::test]
    async fn create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/zone/example.com/_stream")
            .match_header("authorization", "Basic dXNlcjpwYXNz")
            .match_header("x-domainrobot-context", "4")
            .match_body(mockito::Matcher::Json(json!({
                "adds": [{
                    "name": "_acme-challenge.example.com.",
                    "ttl": 300,
                    "type": "TXT",
                    "value": "token-value"
                }],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("token-value".to_string()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn create_mx_record_includes_pref() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/zone/example.com/_stream")
            .match_body(mockito::Matcher::Json(json!({
                "adds": [{
                    "name": "example.com.",
                    "ttl": 3600,
                    "type": "MX",
                    "value": "mail.example.com",
                    "pref": 10
                }],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "example.com",
                DnsRecord::MX(crate::MXRecord {
                    exchange: "mail.example.com".to_string(),
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

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(
                r#"{"data":[{"origin":"example.com","resourceRecords":[
                    {"name":"www.example.com.","ttl":3600,"type":"AAAA","value":"2001:db8::1"}
                ]}]}"#,
            )
            .create();

        let stream_mock = server
            .mock("POST", "/zone/example.com/_stream")
            .match_body(mockito::Matcher::Json(json!({
                "adds": [{
                    "name": "www.example.com.",
                    "ttl": 3600,
                    "type": "AAAA",
                    "value": "2001:db8::2"
                }],
                "rems": [{
                    "name": "www.example.com.",
                    "ttl": 3600,
                    "type": "AAAA",
                    "value": "2001:db8::1"
                }],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .update(
                "www.example.com",
                DnsRecord::AAAA("2001:db8::2".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        search_mock.assert();
        stream_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(
                r#"{"data":[{"origin":"example.com","resourceRecords":[
                    {"name":"www.example.com.","ttl":300,"type":"TXT","value":"old-value"}
                ]}]}"#,
            )
            .create();

        let stream_mock = server
            .mock("POST", "/zone/example.com/_stream")
            .match_body(mockito::Matcher::Json(json!({
                "rems": [{
                    "name": "www.example.com.",
                    "ttl": 300,
                    "type": "TXT",
                    "value": "old-value"
                }],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .delete("www.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok());
        search_mock.assert();
        stream_mock.assert();
    }

    #[tokio::test]
    async fn delete_missing_record_returns_error() {
        let mut server = mockito::Server::new_async().await;

        let _search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(r#"{"data":[]}"#)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .delete("www.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(matches!(result, Err(Error::Api(msg)) if msg.contains("not found")));
    }

    #[tokio::test]
    async fn unauthorized_response() {
        let mut server = mockito::Server::new_async().await;

        let _mock = server
            .mock("POST", "/zone/example.com/_stream")
            .with_status(401)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "x.example.com",
                DnsRecord::TXT("v".to_string()),
                300,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Unauthorized)));
    }

    #[tokio::test]
    #[ignore = "Requires AutoDNS account credentials"]
    async fn integration_test() {
        let user = "";
        let pass = "";
        let origin = "";
        let subdomain = "";

        assert!(!user.is_empty(), "Configure user in the integration test");
        assert!(!pass.is_empty(), "Configure pass in the integration test");
        assert!(
            !origin.is_empty(),
            "Configure origin in the integration test"
        );
        assert!(
            !subdomain.is_empty(),
            "Configure subdomain in the integration test"
        );

        let provider =
            AutodnsProvider::new(user, pass, None, Some(Duration::from_secs(30))).unwrap();

        assert!(
            provider
                .create(
                    subdomain,
                    DnsRecord::TXT("integration".to_string()),
                    300,
                    origin
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .delete(subdomain, origin, DnsRecordType::TXT)
                .await
                .is_ok()
        );
    }
}
