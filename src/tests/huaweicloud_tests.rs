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
        TlsaSelector, providers::huaweicloud::HuaweiCloudProvider,
    };
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> HuaweiCloudProvider {
        HuaweiCloudProvider::new(
            "AKID",
            "SECRET",
            "cn-north-4",
            Some(Duration::from_secs(2)),
        )
        .unwrap()
        .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;

        let zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::UrlEncoded(
                "name".to_string(),
                "example.com.".to_string(),
            ))
            .match_header("x-sdk-date", mockito::Matcher::Any)
            .match_header("authorization", mockito::Matcher::Regex(
                "^SDK-HMAC-SHA256 Access=AKID, SignedHeaders=content-type;host;x-sdk-date, Signature=[0-9a-f]+$".to_string(),
            ))
            .with_status(200)
            .with_body(
                r#"{"zones":[{"id":"zone123","name":"example.com."}]}"#,
            )
            .create_async()
            .await;

        let create_mock = server
            .mock("POST", "/v2/zones/zone123/recordsets/")
            .match_header("authorization", mockito::Matcher::Regex(
                "^SDK-HMAC-SHA256 ".to_string(),
            ))
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"name":"test.example.com.","type":"A","ttl":300,"records":["1.2.3.4"]}"#
                    .to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"id":"rs1"}"#)
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
        zones_mock.assert_async().await;
        create_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_create_mx_record_success() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"zones":[{"id":"zone123","name":"example.com."}]}"#)
            .create_async()
            .await;

        let create_mock = server
            .mock("POST", "/v2/zones/zone123/recordsets/")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"name":"mail.example.com.","type":"MX","ttl":300,"records":["10 mx.example.com."]}"#
                    .to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"id":"rs1"}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "mail.example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mx.example.com".to_string(),
                    priority: 10,
                }),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        create_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"zones":[{"id":"zone1","name":"example.com."}]}"#)
            .create_async()
            .await;

        let create_mock = server
            .mock("POST", "/v2/zones/zone1/recordsets/")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"name":"_acme.example.com.","type":"TXT","ttl":120,"records":["\"hello\""]}"#
                    .to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"id":"rs1"}"#)
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
        create_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_update_record_success() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"zones":[{"id":"zoneA","name":"example.com."}]}"#)
            .create_async()
            .await;

        let _list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".to_string(), "test.example.com.".to_string()),
                mockito::Matcher::UrlEncoded("type".to_string(), "A".to_string()),
            ]))
            .with_status(200)
            .with_body(
                r#"{"recordsets":[{"id":"rs9","name":"test.example.com.","type":"A"}]}"#,
            )
            .create_async()
            .await;

        let put_mock = server
            .mock("PUT", "/v2/zones/zoneA/recordsets/rs9/")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"name":"test.example.com.","type":"A","ttl":600,"records":["5.6.7.8"]}"#
                    .to_string(),
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

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"zones":[{"id":"zoneA","name":"example.com."}]}"#)
            .create_async()
            .await;

        let _list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".to_string(), "test.example.com.".to_string()),
                mockito::Matcher::UrlEncoded("type".to_string(), "TXT".to_string()),
            ]))
            .with_status(200)
            .with_body(
                r#"{"recordsets":[{"id":"rs77","name":"test.example.com.","type":"TXT"}]}"#,
            )
            .create_async()
            .await;

        let delete_mock = server
            .mock("DELETE", "/v2/zones/zoneA/recordsets/rs77/")
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
    async fn test_zone_not_found() {
        let mut server = mockito::Server::new_async().await;

        let zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"zones":[]}"#)
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

        match result {
            Err(Error::Api(msg)) => {
                assert!(msg.contains("zone"), "unexpected: {msg}");
            }
            other => panic!("expected Api error, got {:?}", other),
        }
        zones_mock.assert_async().await;
    }

    #[tokio::test]
    #[ignore = "Requires HUAWEICLOUD_ACCESS_KEY_ID, HUAWEICLOUD_SECRET_ACCESS_KEY, HUAWEICLOUD_REGION, HUAWEICLOUD_DOMAIN"]
    async fn integration_test() {
        let ak = std::env::var("HUAWEICLOUD_ACCESS_KEY_ID").unwrap_or_default();
        let sk = std::env::var("HUAWEICLOUD_SECRET_ACCESS_KEY").unwrap_or_default();
        let region = std::env::var("HUAWEICLOUD_REGION").unwrap_or_default();
        let domain = std::env::var("HUAWEICLOUD_DOMAIN").unwrap_or_default();
        assert!(!ak.is_empty());
        assert!(!sk.is_empty());
        assert!(!region.is_empty());
        assert!(!domain.is_empty());

        let provider =
            HuaweiCloudProvider::new(ak, sk, region, Some(Duration::from_secs(30))).unwrap();
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
