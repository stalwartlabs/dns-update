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
        DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord,
        providers::baiducloud::BaiduCloudProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> BaiduCloudProvider {
        BaiduCloudProvider::new("AKID", "SECRET", Some(Duration::from_secs(2)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn auth_regex() -> Matcher {
        Matcher::Regex("^bce-auth-v1/AKID/[0-9TZ:-]+/1800/content-type;host/[0-9a-f]+$".to_string())
    }

    fn mock_list(server: &mut ServerGuard, zone: &str, rr: &str, body: serde_json::Value) -> Mock {
        server
            .mock("GET", format!("/v1/dns/zone/{zone}/record").as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("rr".into(), rr.into()),
                Matcher::UrlEncoded("maxKeys".into(), "1000".into()),
            ]))
            .match_header("authorization", auth_regex())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
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
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "host",
            serde_json::json!({"records": [], "isTruncated": false}),
        );

        let create = server
            .mock("POST", "/v1/dns/zone/example.com/record")
            .match_query(Matcher::Regex("clientToken=.+".to_string()))
            .match_body(Matcher::PartialJsonString(
                r#"{"rr":"host","type":"A","value":"1.1.1.1","ttl":300}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        list.assert_async().await;
        create.assert_async().await;
    }

    #[tokio::test]
    async fn test_set_rrset_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "host",
            serde_json::json!({
                "records": [{"id": "rec-1", "rr": "host", "type": "A", "value": "1.1.1.1"}],
                "isTruncated": false
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        list.assert_async().await;
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_adds_new() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "host",
            serde_json::json!({
                "records": [
                    {"id": "keep", "rr": "host", "type": "A", "value": "1.1.1.1"},
                    {"id": "stale", "rr": "host", "type": "A", "value": "9.9.9.9"}
                ],
                "isTruncated": false
            }),
        );

        let delete_stale = server
            .mock("DELETE", "/v1/dns/zone/example.com/record/stale")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let create_new = server
            .mock("POST", "/v1/dns/zone/example.com/record")
            .match_query(Matcher::Any)
            .match_body(Matcher::PartialJsonString(
                r#"{"rr":"host","type":"A","value":"8.8.8.8","ttl":300}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("8.8.8.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        list.assert_async().await;
        delete_stale.assert_async().await;
        create_new.assert_async().await;
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_all_of_same_type_only() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "host",
            serde_json::json!({
                "records": [
                    {"id": "a1", "rr": "host", "type": "A", "value": "1.2.3.4"},
                    {"id": "txt1", "rr": "host", "type": "TXT", "value": "leave-me-alone"}
                ],
                "isTruncated": false
            }),
        );

        let del_a = server
            .mock("DELETE", "/v1/dns/zone/example.com/record/a1")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        list.assert_async().await;
        del_a.assert_async().await;
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "_acme",
            serde_json::json!({
                "records": [
                    {"id": "old", "rr": "_acme", "type": "TXT", "value": "existing"}
                ],
                "isTruncated": false
            }),
        );

        let create = server
            .mock("POST", "/v1/dns/zone/example.com/record")
            .match_query(Matcher::Any)
            .match_body(Matcher::PartialJsonString(
                r#"{"rr":"_acme","type":"TXT","value":"new-token","ttl":60}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                60,
                vec![
                    DnsRecord::TXT("existing".to_string()),
                    DnsRecord::TXT("new-token".to_string()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        list.assert_async().await;
        create.assert_async().await;
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_short_circuits_no_http() {
        let provider = setup_provider("http://127.0.0.1:1");
        let result = provider
            .add_to_rrset("x.example.com", DnsRecordType::A, 60, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "expected ok, got {:?}", result);
    }

    #[tokio::test]
    async fn test_remove_from_rrset_only_drops_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "_acme",
            serde_json::json!({
                "records": [
                    {"id": "keep", "rr": "_acme", "type": "TXT", "value": "keep-me"},
                    {"id": "drop", "rr": "_acme", "type": "TXT", "value": "drop-me"}
                ],
                "isTruncated": false
            }),
        );

        let delete = server
            .mock("DELETE", "/v1/dns/zone/example.com/record/drop")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop-me".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        list.assert_async().await;
        delete.assert_async().await;
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_short_circuits() {
        let provider = setup_provider("http://127.0.0.1:1");
        let result = provider
            .remove_from_rrset("x.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "expected ok, got {:?}", result);
    }

    #[tokio::test]
    async fn test_set_rrset_srv_no_top_level_priority() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "_sip._tcp",
            serde_json::json!({"records": [], "isTruncated": false}),
        );

        let create = server
            .mock("POST", "/v1/dns/zone/example.com/record")
            .match_query(Matcher::Any)
            .match_body(Matcher::JsonString(
                r#"{"rr":"_sip._tcp","type":"SRV","value":"10 60 5060 sip.example.com.","ttl":300,"description":"dns-update"}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                300,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 60,
                    port: 5060,
                    target: "sip.example.com".to_string(),
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        list.assert_async().await;
        create.assert_async().await;
    }

    #[tokio::test]
    async fn test_set_rrset_txt_chunks_long_value() {
        let mut server = mockito::Server::new_async().await;
        let long_value: String = "a".repeat(400);
        let first_chunk: String = "a".repeat(255);
        let second_chunk: String = "a".repeat(145);

        let list = mock_list(
            &mut server,
            "example.com",
            "_dkim",
            serde_json::json!({"records": [], "isTruncated": false}),
        );

        let post_first = server
            .mock("POST", "/v1/dns/zone/example.com/record")
            .match_query(Matcher::Any)
            .match_body(Matcher::PartialJsonString(format!(
                r#"{{"rr":"_dkim","type":"TXT","value":"{first_chunk}","ttl":60}}"#
            )))
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let post_second = server
            .mock("POST", "/v1/dns/zone/example.com/record")
            .match_query(Matcher::Any)
            .match_body(Matcher::PartialJsonString(format!(
                r#"{{"rr":"_dkim","type":"TXT","value":"{second_chunk}","ttl":60}}"#
            )))
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_dkim.example.com",
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT(long_value)],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        list.assert_async().await;
        post_first.assert_async().await;
        post_second.assert_async().await;
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "host",
            serde_json::json!({
                "records": [
                    {"id": "txt1", "rr": "host", "type": "TXT", "value": "ignore-me"},
                    {"id": "aaaa1", "rr": "host", "type": "AAAA", "value": "2001:db8::1"}
                ],
                "isTruncated": false
            }),
        );

        let create = server
            .mock("POST", "/v1/dns/zone/example.com/record")
            .match_query(Matcher::Any)
            .match_body(Matcher::PartialJsonString(
                r#"{"rr":"host","type":"A","value":"4.4.4.4","ttl":300}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("4.4.4.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        list.assert_async().await;
        create.assert_async().await;
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_rejected() {
        let provider = setup_provider("http://127.0.0.1:1");
        let result = provider
            .set_rrset(
                "x.example.com",
                DnsRecordType::A,
                60,
                vec![DnsRecord::TXT("not-an-a".to_string())],
                "example.com",
            )
            .await;
        match result {
            Err(Error::Api(msg)) => {
                assert!(msg.contains("mismatch"), "unexpected: {msg}");
            }
            other => panic!("expected mismatch error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_rejected() {
        let provider = setup_provider("http://127.0.0.1:1");
        let result = provider
            .set_rrset(
                "x.example.com",
                DnsRecordType::TLSA,
                60,
                vec![],
                "example.com",
            )
            .await;
        match result {
            Err(Error::Unsupported(msg)) => assert!(msg.contains("TLSA"), "unexpected: {msg}"),
            other => panic!("expected TLSA error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_list_rrset_filters_by_type() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "host",
            serde_json::json!({
                "records": [
                    {"id": "a1", "rr": "host", "type": "A", "value": "1.2.3.4"},
                    {"id": "a2", "rr": "host", "type": "A", "value": "5.6.7.8"},
                    {"id": "txt1", "rr": "host", "type": "TXT", "value": "hello"}
                ],
                "isTruncated": false
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();

        list.assert_async().await;
        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("1.2.3.4".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("5.6.7.8".parse().unwrap())));
    }

    #[tokio::test]
    async fn test_list_rrset_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "missing",
            serde_json::json!({"records": [], "isTruncated": false}),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("missing.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();
        list.assert_async().await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_add_to_rrset_mx_matches_on_priority() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "@",
            serde_json::json!({
                "records": [
                    {"id": "mx1", "rr": "@", "type": "MX", "value": "mx.example.com.", "priority": 10}
                ],
                "isTruncated": false
            }),
        );

        let create = server
            .mock("POST", "/v1/dns/zone/example.com/record")
            .match_query(Matcher::Any)
            .match_body(Matcher::PartialJsonString(
                r#"{"rr":"@","type":"MX","value":"mx.example.com.","ttl":300,"priority":20}"#
                    .to_string(),
            ))
            .with_status(200)
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "example.com",
                DnsRecordType::MX,
                300,
                vec![
                    DnsRecord::MX(MXRecord {
                        exchange: "mx.example.com".to_string(),
                        priority: 10,
                    }),
                    DnsRecord::MX(MXRecord {
                        exchange: "mx.example.com".to_string(),
                        priority: 20,
                    }),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        list.assert_async().await;
        create.assert_async().await;
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
            .set_rrset(
                &test_name,
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("hello world".to_string())],
                &domain,
            )
            .await
            .unwrap();
        provider
            .set_rrset(&test_name, DnsRecordType::TXT, 300, vec![], &domain)
            .await
            .unwrap();
    }
}
