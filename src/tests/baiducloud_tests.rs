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
        DnsRecord, DnsRecordType, Error, MXRecord, TLSARecord, TlsaCertUsage, TlsaMatching,
        TlsaSelector, providers::baiducloud::BaiduCloudProvider,
    };
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> BaiduCloudProvider {
        BaiduCloudProvider::new("AKID", "SECRET", Some(Duration::from_secs(2)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/v1/dns/zone/example.com/record")
            .match_query(mockito::Matcher::Regex("clientToken=.+".to_string()))
            .match_header(
                "authorization",
                mockito::Matcher::Regex(
                    "^bce-auth-v1/AKID/[0-9TZ:-]+/1800/host/[0-9a-f]+$".to_string(),
                ),
            )
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"rr":"test","type":"A","value":"1.2.3.4","ttl":300}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_create_mx_record_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/v1/dns/zone/example.com/record")
            .match_query(mockito::Matcher::Any)
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"rr":"@","type":"MX","value":"mx.example.com.","ttl":300,"priority":10}"#
                    .to_string(),
            ))
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mx.example.com".to_string(),
                    priority: 10,
                }),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/v1/dns/zone/example.com/record")
            .match_query(mockito::Matcher::Any)
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"rr":"_acme","type":"TXT","value":"hello","ttl":120}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "_acme.example.com",
                DnsRecord::TXT("hello".to_string()),
                120,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_update_record_success() {
        let mut server = mockito::Server::new_async().await;

        let _list = server
            .mock("GET", "/v1/dns/zone/example.com/record")
            .with_status(200)
            .with_body(
                r#"{"records":[{"id":"rid1","rr":"test","type":"A"}],"isTruncated":false}"#,
            )
            .create_async()
            .await;

        let put_mock = server
            .mock("PUT", "/v1/dns/zone/example.com/record/rid1")
            .match_query(mockito::Matcher::Any)
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"rr":"test","type":"A","value":"5.6.7.8","ttl":600}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("5.6.7.8".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        put_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let _list = server
            .mock("GET", "/v1/dns/zone/example.com/record")
            .with_status(200)
            .with_body(
                r#"{"records":[{"id":"rid1","rr":"test","type":"TXT"}],"isTruncated":false}"#,
            )
            .create_async()
            .await;

        let delete_mock = server
            .mock("DELETE", "/v1/dns/zone/example.com/record/rid1")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        delete_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_tlsa_not_supported() {
        let provider = setup_provider("http://127.0.0.1:1");
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xab, 0xcd],
                }),
                300,
                "example.com",
            )
            .await;
        match result {
            Err(Error::Api(msg)) => assert!(msg.contains("TLSA"), "unexpected: {msg}"),
            other => panic!("expected TLSA error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_record_not_found_on_delete() {
        let mut server = mockito::Server::new_async().await;

        let _list = server
            .mock("GET", "/v1/dns/zone/example.com/record")
            .with_status(200)
            .with_body(r#"{"records":[],"isTruncated":false}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("missing.example.com", "example.com", DnsRecordType::A)
            .await;
        match result {
            Err(Error::Api(msg)) => assert!(msg.contains("not found"), "unexpected: {msg}"),
            other => panic!("expected Api error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_missing_credentials() {
        let result = BaiduCloudProvider::new("", "", Some(Duration::from_secs(1)));
        match result {
            Err(Error::Api(msg)) => assert!(msg.contains("credentials"), "unexpected: {msg}"),
            Err(other) => panic!("expected credentials error, got {:?}", other),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    #[ignore = "Requires BAIDUCLOUD_ACCESS_KEY_ID, BAIDUCLOUD_SECRET_ACCESS_KEY, BAIDUCLOUD_DOMAIN"]
    async fn integration_test() {
        let ak = std::env::var("BAIDUCLOUD_ACCESS_KEY_ID").unwrap_or_default();
        let sk = std::env::var("BAIDUCLOUD_SECRET_ACCESS_KEY").unwrap_or_default();
        let domain = std::env::var("BAIDUCLOUD_DOMAIN").unwrap_or_default();
        assert!(!ak.is_empty());
        assert!(!sk.is_empty());
        assert!(!domain.is_empty());

        let provider = BaiduCloudProvider::new(ak, sk, Some(Duration::from_secs(30))).unwrap();
        let test_name = format!("dnsupdate-test.{}", domain);
        provider
            .create(
                &test_name,
                DnsRecord::TXT("hello world".to_string()),
                300,
                &domain,
            )
            .await
            .unwrap();
        provider
            .delete(&test_name, &domain, DnsRecordType::TXT)
            .await
            .unwrap();
    }
}
