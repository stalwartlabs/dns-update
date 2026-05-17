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
    use crate::providers::arvancloud::ArvanCloudProvider;
    use crate::{DnsRecord, DnsRecordType, Error, MXRecord};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> ArvanCloudProvider {
        ArvanCloudProvider::new(
            "Apikey 12345678-1234-1234-1234-123456789abc",
            Some(Duration::from_secs(2)),
        )
        .with_endpoint(endpoint)
    }

    fn auth_header() -> &'static str {
        "Apikey 12345678-1234-1234-1234-123456789abc"
    }

    #[tokio::test]
    async fn test_create_txt_record() {
        let mut server = mockito::Server::new_async().await;
        let expected_body = json!({
            "type": "txt",
            "name": "_acme-challenge",
            "value": {"text": "abc"},
            "ttl": 600,
            "upstream_https": "default",
            "ip_filter_mode": {"count":"single","order":"none","geo_filter":"none"}
        });
        let mock = server
            .mock("POST", "/cdn/4.0/domains/example.com/dns-records")
            .match_header("authorization", auth_header())
            .match_body(mockito::Matcher::Json(expected_body))
            .with_status(201)
            .with_body(r#"{"data":{"id":"abc","name":"_acme-challenge","type":"txt"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("abc".to_string()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_a_record() {
        let mut server = mockito::Server::new_async().await;
        let expected_body = json!({
            "type": "a",
            "name": "www",
            "value": [{"ip": "1.2.3.4"}],
            "ttl": 600,
            "upstream_https": "default",
            "ip_filter_mode": {"count":"single","order":"none","geo_filter":"none"}
        });
        let mock = server
            .mock("POST", "/cdn/4.0/domains/example.com/dns-records")
            .match_body(mockito::Matcher::Json(expected_body))
            .with_status(201)
            .with_body(r#"{"data":{"id":"id1","name":"www","type":"a"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_mx_record() {
        let mut server = mockito::Server::new_async().await;
        let expected_body = json!({
            "type": "mx",
            "name": "@",
            "value": {"host":"mail.example.com","priority":10},
            "ttl": 3600,
            "upstream_https": "default",
            "ip_filter_mode": {"count":"single","order":"none","geo_filter":"none"}
        });
        let mock = server
            .mock("POST", "/cdn/4.0/domains/example.com/dns-records")
            .match_body(mockito::Matcher::Json(expected_body))
            .with_status(201)
            .with_body(r#"{"data":{"id":"mx1","name":"@","type":"mx"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
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

        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_record() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("GET", "/cdn/4.0/domains/example.com/dns-records")
            .with_status(200)
            .with_body(r#"{"data":[{"id":"r-1","name":"www","type":"a"}]}"#)
            .create();
        let expected_body = json!({
            "type": "a",
            "name": "www",
            "value": [{"ip": "5.6.7.8"}],
            "ttl": 600,
            "upstream_https": "default",
            "ip_filter_mode": {"count":"single","order":"none","geo_filter":"none"}
        });
        let put_mock = server
            .mock("PUT", "/cdn/4.0/domains/example.com/dns-records/r-1")
            .match_body(mockito::Matcher::Json(expected_body))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "www.example.com",
                DnsRecord::A("5.6.7.8".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        list_mock.assert();
        put_mock.assert();
    }

    #[tokio::test]
    async fn test_delete_record() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("GET", "/cdn/4.0/domains/example.com/dns-records")
            .with_status(200)
            .with_body(r#"{"data":[{"id":"r-9","name":"www","type":"txt"}]}"#)
            .create();
        let delete_mock = server
            .mock("DELETE", "/cdn/4.0/domains/example.com/dns-records/r-9")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("www.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "{:?}", result);
        list_mock.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    async fn test_create_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/cdn/4.0/domains/example.com/dns-records")
            .with_status(401)
            .with_body(r#"{"message":"invalid api key"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Unauthorized)), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn test_tlsa_unsupported() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "tls.example.com",
                DnsRecord::TLSA(crate::TLSARecord {
                    cert_usage: crate::TlsaCertUsage::DaneEe,
                    selector: crate::TlsaSelector::Spki,
                    matching: crate::TlsaMatching::Sha256,
                    cert_data: vec![0xab],
                }),
                600,
                "example.com",
            )
            .await;
        match result {
            Err(Error::Api(msg)) => assert!(msg.contains("TLSA")),
            other => panic!("expected Error::Api for TLSA, got {:?}", other),
        }
    }

    #[tokio::test]
    #[ignore = "Requires ArvanCloud API key"]
    async fn integration_test() {
        let api_key = "";
        let origin = "";
        let name = "";

        assert!(!api_key.is_empty(), "Set ARVANCLOUD_API_KEY");
        assert!(!origin.is_empty(), "Set origin");
        assert!(!name.is_empty(), "Set name");

        let provider = ArvanCloudProvider::new(api_key, Some(Duration::from_secs(30)));
        assert!(
            provider
                .create(
                    name,
                    DnsRecord::TXT("integration-test".to_string()),
                    600,
                    origin
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .delete(name, origin, DnsRecordType::TXT)
                .await
                .is_ok()
        );
    }
}
