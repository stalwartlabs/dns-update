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
        DnsRecord, DnsRecordType, Error, TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector,
        providers::huaweicloud::HuaweiCloudProvider,
    };
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> HuaweiCloudProvider {
        HuaweiCloudProvider::new("AKID", "SECRET", "cn-north-4", Some(Duration::from_secs(2)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn zones_mock_body(zone_id: &str) -> String {
        format!(r#"{{"zones":[{{"id":"{zone_id}","name":"example.com."}}]}}"#)
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_absent() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let _list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".to_string(), "www.example.com.".to_string()),
                mockito::Matcher::UrlEncoded("type".to_string(), "A".to_string()),
            ]))
            .with_status(200)
            .with_body(r#"{"recordsets":[]}"#)
            .create_async()
            .await;

        let post_mock = server
            .mock("POST", "/v2/zones/zoneA/recordsets/")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "name": "www.example.com.",
                "type": "A",
                "ttl": 300,
                "records": ["1.1.1.1", "2.2.2.2"],
            })))
            .with_status(202)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        post_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_set_rrset_puts_when_present() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let _list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".to_string(), "www.example.com.".to_string()),
                mockito::Matcher::UrlEncoded("type".to_string(), "A".to_string()),
            ]))
            .with_status(200)
            .with_body(
                r#"{"recordsets":[{"id":"rsX","name":"www.example.com.","type":"A","ttl":300,"records":["1.1.1.1"]}]}"#,
            )
            .create_async()
            .await;

        let put_mock = server
            .mock("PUT", "/v2/zones/zoneA/recordsets/rsX/")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "name": "www.example.com.",
                "type": "A",
                "ttl": 600,
                "records": ["3.3.3.3"],
            })))
            .with_status(202)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("3.3.3.3".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        put_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_existing() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let _list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".to_string(), "www.example.com.".to_string()),
                mockito::Matcher::UrlEncoded("type".to_string(), "A".to_string()),
            ]))
            .with_status(200)
            .with_body(
                r#"{"recordsets":[{"id":"rsKill","name":"www.example.com.","type":"A","ttl":300,"records":["1.1.1.1"]}]}"#,
            )
            .create_async()
            .await;

        let delete_mock = server
            .mock("DELETE", "/v2/zones/zoneA/recordsets/rsKill/")
            .with_status(202)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        delete_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_set_rrset_empty_when_absent_is_noop() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"recordsets":[]}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        list_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_returns_error() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("foo".to_string())],
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("RRSet record type mismatch")),
            "expected mismatch error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_tlsa() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_25._tcp.mx.example.com",
                DnsRecordType::TLSA,
                300,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0x00],
                })],
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("TLSA")),
            "expected TLSA rejection, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_posts_when_absent() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let _list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"recordsets":[]}"#)
            .create_async()
            .await;

        let post_mock = server
            .mock("POST", "/v2/zones/zoneA/recordsets/")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "name": "www.example.com.",
                "type": "A",
                "ttl": 300,
                "records": ["9.9.9.9"],
            })))
            .with_status(202)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {result:?}");
        post_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_add_to_rrset_merges_with_existing() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let _list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(
                r#"{"recordsets":[{"id":"rsM","name":"www.example.com.","type":"A","ttl":300,"records":["1.1.1.1"]}]}"#,
            )
            .create_async()
            .await;

        let put_mock = server
            .mock("PUT", "/v2/zones/zoneA/recordsets/rsM/")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "name": "www.example.com.",
                "type": "A",
                "ttl": 300,
                "records": ["1.1.1.1", "2.2.2.2"],
            })))
            .with_status(202)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("2.2.2.2".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {result:?}");
        put_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_add_to_rrset_dedupes_already_present() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let _list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(
                r#"{"recordsets":[{"id":"rsD","name":"www.example.com.","type":"A","ttl":300,"records":["1.1.1.1","2.2.2.2"]}]}"#,
            )
            .create_async()
            .await;

        let put_mock = server
            .mock("PUT", "/v2/zones/zoneA/recordsets/rsD/")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "name": "www.example.com.",
                "type": "A",
                "ttl": 300,
                "records": ["1.1.1.1", "2.2.2.2"],
            })))
            .with_status(202)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {result:?}");
        put_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("www.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "expected ok, got {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_absent_recordset_is_noop() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"recordsets":[]}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {result:?}");
        list_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_remove_from_rrset_puts_filtered() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let _list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(
                r#"{"recordsets":[{"id":"rsR","name":"www.example.com.","type":"A","ttl":120,"records":["1.1.1.1","2.2.2.2"]}]}"#,
            )
            .create_async()
            .await;

        let put_mock = server
            .mock("PUT", "/v2/zones/zoneA/recordsets/rsR/")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "name": "www.example.com.",
                "type": "A",
                "ttl": 120,
                "records": ["1.1.1.1"],
            })))
            .with_status(202)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("2.2.2.2".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {result:?}");
        put_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_when_drained() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let _list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(
                r#"{"recordsets":[{"id":"rsZ","name":"www.example.com.","type":"A","ttl":120,"records":["1.1.1.1"]}]}"#,
            )
            .create_async()
            .await;

        let delete_mock = server
            .mock("DELETE", "/v2/zones/zoneA/recordsets/rsZ/")
            .with_status(202)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {result:?}");
        delete_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_remove_from_rrset_absent_value_is_noop() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(
                r#"{"recordsets":[{"id":"rsN","name":"www.example.com.","type":"A","ttl":120,"records":["1.1.1.1"]}]}"#,
            )
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {result:?}");
        list_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_list_rrset_returns_parsed_records() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let _list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".to_string(), "www.example.com.".to_string()),
                mockito::Matcher::UrlEncoded("type".to_string(), "A".to_string()),
            ]))
            .with_status(200)
            .with_body(
                r#"{"recordsets":[{"id":"rsL","name":"www.example.com.","type":"A","ttl":300,"records":["1.1.1.1","2.2.2.2"]}]}"#,
            )
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");
        assert_eq!(
            result,
            vec![
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                DnsRecord::A("2.2.2.2".parse().unwrap()),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_rrset_missing_returns_empty() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let _list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"recordsets":[]}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_list_rrset_parses_txt_unquoted() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let _list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(
                r#"{"recordsets":[{"id":"rsT","name":"x.example.com.","type":"TXT","ttl":120,"records":["\"hello world\""]}]}"#,
            )
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("x.example.com", DnsRecordType::TXT, "example.com")
            .await
            .expect("list_rrset failed");
        assert_eq!(result, vec![DnsRecord::TXT("hello world".to_string())]);
    }

    #[tokio::test]
    async fn test_find_recordset_filters_fuzzy_matches() {
        let mut server = mockito::Server::new_async().await;

        let _zones_mock = server
            .mock("GET", "/v2/zones/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(zones_mock_body("zoneA"))
            .create_async()
            .await;

        let _list_mock = server
            .mock("GET", "/v2/zones/zoneA/recordsets/")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(
                r#"{"recordsets":[
                    {"id":"wrong1","name":"other.example.com.","type":"A","ttl":300,"records":["8.8.8.8"]},
                    {"id":"wrong2","name":"www.example.com.","type":"AAAA","ttl":300,"records":["::1"]},
                    {"id":"good","name":"www.example.com.","type":"A","ttl":300,"records":["1.1.1.1"]}
                ]}"#,
            )
            .create_async()
            .await;

        let put_mock = server
            .mock("PUT", "/v2/zones/zoneA/recordsets/good/")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"name":"www.example.com.","type":"A","ttl":600,"records":["5.5.5.5"]}"#
                    .to_string(),
            ))
            .with_status(202)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("5.5.5.5".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {result:?}");
        put_mock.assert_async().await;
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
            .set_rrset(
                &test_name,
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("hello world".to_string())],
                &domain,
            )
            .await
            .unwrap();
        let listed = provider
            .list_rrset(&test_name, DnsRecordType::TXT, &domain)
            .await
            .unwrap();
        assert_eq!(listed, vec![DnsRecord::TXT("hello world".to_string())]);
        provider
            .set_rrset(&test_name, DnsRecordType::TXT, 300, vec![], &domain)
            .await
            .unwrap();
    }
}
