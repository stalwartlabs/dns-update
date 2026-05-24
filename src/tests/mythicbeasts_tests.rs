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
        CAARecord, DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord, TLSARecord, TlsaCertUsage,
        TlsaMatching, TlsaSelector, providers::mythicbeasts::MythicBeastsProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn provider(endpoint: String) -> MythicBeastsProvider {
        MythicBeastsProvider::new("user", "pass", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn mock_token(server: &mut mockito::ServerGuard) -> mockito::Mock {
        server
            .mock("POST", "/auth/login")
            .with_status(200)
            .with_body(r#"{"access_token":"tok","expires_in":3600,"token_type":"bearer"}"#)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_puts_replacement_set() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let put = server
            .mock("PUT", "/dns/v2/zones/example.com/records/www/A")
            .match_header("authorization", "Bearer tok")
            .match_body(Matcher::Json(json!({
                "records": [
                    {"host":"www","ttl":300,"type":"A","data":"1.1.1.1"},
                    {"host":"www","ttl":300,"type":"A","data":"2.2.2.2"}
                ]
            })))
            .with_status(200)
            .with_body(r#"{"records_added":2,"records_removed":0}"#)
            .create();

        let p = provider(server.url());
        let result = p
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
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        token.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_only_this_type() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let del = server
            .mock("DELETE", "/dns/v2/zones/example.com/records/www/A")
            .with_status(200)
            .with_body(r#"{"records_removed":1}"#)
            .create();

        let p = provider(server.url());
        let result = p
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        token.assert();
        del.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_treats_404_as_success() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let del = server
            .mock("DELETE", "/dns/v2/zones/example.com/records/www/A")
            .with_status(404)
            .with_body(r#"{"error":"not found"}"#)
            .create();

        let p = provider(server.url());
        let result = p
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        token.assert();
        del.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_returns_error() {
        let server = mockito::Server::new_async().await;
        let p = provider(server.url());
        let result = p
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
    async fn test_set_rrset_mx_includes_sidecar() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let put = server
            .mock("PUT", "/dns/v2/zones/example.com/records/@/MX")
            .match_body(Matcher::Json(json!({
                "records": [
                    {"host":"@","ttl":300,"type":"MX","data":"mx1.example.com.","mx_priority":10},
                    {"host":"@","ttl":300,"type":"MX","data":"mx2.example.com.","mx_priority":20}
                ]
            })))
            .with_status(200)
            .with_body(r#"{"records_added":2}"#)
            .create();

        let p = provider(server.url());
        let result = p
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                300,
                vec![
                    DnsRecord::MX(MXRecord {
                        priority: 10,
                        exchange: "mx1.example.com".to_string(),
                    }),
                    DnsRecord::MX(MXRecord {
                        priority: 20,
                        exchange: "mx2.example.com".to_string(),
                    }),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        token.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_posts_append() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let post = server
            .mock("POST", "/dns/v2/zones/example.com/records/www/A")
            .match_body(Matcher::Json(json!({
                "records": [{"host":"www","ttl":600,"type":"A","data":"3.3.3.3"}]
            })))
            .with_status(200)
            .with_body(r#"{"records_added":1}"#)
            .create();

        let p = provider(server.url());
        let result = p
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("3.3.3.3".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
        token.assert();
        post.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let p = provider(server.url());
        let result = p
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_type_mismatch_returns_error() {
        let server = mockito::Server::new_async().await;
        let p = provider(server.url());
        let result = p
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![DnsRecord::TXT("v".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("RRSet record type mismatch")),
            "expected mismatch error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let p = provider(server.url());
        let result = p
            .remove_from_rrset("www.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_lists_filters_and_puts_remaining() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let list = server
            .mock("GET", "/dns/v2/zones/example.com/records/www/A")
            .with_status(200)
            .with_body(
                r#"{"records":[
                    {"host":"www","ttl":300,"type":"A","data":"1.1.1.1"},
                    {"host":"www","ttl":300,"type":"A","data":"2.2.2.2"}
                ]}"#,
            )
            .create();

        let put = server
            .mock("PUT", "/dns/v2/zones/example.com/records/www/A")
            .match_body(Matcher::Json(json!({
                "records":[{"host":"www","ttl":300,"type":"A","data":"2.2.2.2"}]
            })))
            .with_status(200)
            .with_body(r#"{"records_added":1,"records_removed":1}"#)
            .create();

        let p = provider(server.url());
        let result = p
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        token.assert();
        list.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_all_records_deletes_rrset() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let list = server
            .mock("GET", "/dns/v2/zones/example.com/records/www/A")
            .with_status(200)
            .with_body(r#"{"records":[{"host":"www","ttl":300,"type":"A","data":"1.1.1.1"}]}"#)
            .create();

        let del = server
            .mock("DELETE", "/dns/v2/zones/example.com/records/www/A")
            .with_status(200)
            .with_body(r#"{"records_removed":1}"#)
            .create();

        let p = provider(server.url());
        let result = p
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        token.assert();
        list.assert();
        del.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_404_on_list_is_success() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let list = server
            .mock("GET", "/dns/v2/zones/example.com/records/www/A")
            .with_status(404)
            .with_body(r#"{"error":"not found"}"#)
            .create();

        let p = provider(server.url());
        let result = p
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        token.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_mx_matches_sidecar_priority() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let list = server
            .mock("GET", "/dns/v2/zones/example.com/records/@/MX")
            .with_status(200)
            .with_body(
                r#"{"records":[
                    {"host":"@","ttl":300,"type":"MX","data":"mx1.example.com.","mx_priority":10},
                    {"host":"@","ttl":300,"type":"MX","data":"mx2.example.com.","mx_priority":20}
                ]}"#,
            )
            .create();

        let put = server
            .mock("PUT", "/dns/v2/zones/example.com/records/@/MX")
            .match_body(Matcher::Json(json!({
                "records":[{"host":"@","ttl":300,"type":"MX","data":"mx2.example.com.","mx_priority":20}]
            })))
            .with_status(200)
            .with_body(r#"{"records_added":1}"#)
            .create();

        let p = provider(server.url());
        let result = p
            .remove_from_rrset(
                "example.com",
                DnsRecordType::MX,
                vec![DnsRecord::MX(MXRecord {
                    priority: 10,
                    exchange: "mx1.example.com".to_string(),
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        token.assert();
        list.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_records() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let list = server
            .mock("GET", "/dns/v2/zones/example.com/records/www/A")
            .match_header("authorization", "Bearer tok")
            .with_status(200)
            .with_body(
                r#"{"records":[
                    {"host":"www","ttl":300,"type":"A","data":"1.1.1.1"},
                    {"host":"www","ttl":300,"type":"A","data":"2.2.2.2"}
                ]}"#,
            )
            .create();

        let p = provider(server.url());
        let result = p
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await;
        assert!(result.is_ok(), "list_rrset returned {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(records.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
        token.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_404_returns_empty() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let list = server
            .mock("GET", "/dns/v2/zones/example.com/records/www/A")
            .with_status(404)
            .with_body(r#"{"error":"not found"}"#)
            .create();

        let p = provider(server.url());
        let result = p
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await;
        assert!(result.is_ok(), "list_rrset returned {result:?}");
        assert!(result.unwrap().is_empty());
        token.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_mx_with_sidecar() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let list = server
            .mock("GET", "/dns/v2/zones/example.com/records/@/MX")
            .with_status(200)
            .with_body(
                r#"{"records":[{"host":"@","ttl":300,"type":"MX","data":"mx.example.com.","mx_priority":10}]}"#,
            )
            .create();

        let p = provider(server.url());
        let result = p
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await;
        assert!(result.is_ok(), "list_rrset returned {result:?}");
        assert_eq!(
            result.unwrap(),
            vec![DnsRecord::MX(MXRecord {
                priority: 10,
                exchange: "mx.example.com".to_string(),
            })]
        );
        token.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_caa_with_split_fields() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let list = server
            .mock("GET", "/dns/v2/zones/example.com/records/@/CAA")
            .with_status(200)
            .with_body(
                r#"{"records":[{"host":"@","ttl":300,"type":"CAA","data":"letsencrypt.org","caa_flags":0,"caa_tag":"issue"}]}"#,
            )
            .create();

        let p = provider(server.url());
        let result = p
            .list_rrset("example.com", DnsRecordType::CAA, "example.com")
            .await;
        assert!(result.is_ok(), "list_rrset returned {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 1);
        match &records[0] {
            DnsRecord::CAA(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            }) => {
                assert!(!issuer_critical);
                assert_eq!(name.as_deref(), Some("letsencrypt.org"));
                assert!(options.is_empty());
            }
            other => panic!("unexpected CAA shape: {other:?}"),
        }
        token.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_tlsa_with_sidecar() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let list = server
            .mock("GET", "/dns/v2/zones/example.com/records/_443._tcp.www/TLSA")
            .with_status(200)
            .with_body(
                r#"{"records":[{"host":"_443._tcp.www","ttl":300,"type":"TLSA","data":"abcd","tlsa_usage":3,"tlsa_selector":1,"tlsa_matching":1}]}"#,
            )
            .create();

        let p = provider(server.url());
        let result = p
            .list_rrset(
                "_443._tcp.www.example.com",
                DnsRecordType::TLSA,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "list_rrset returned {result:?}");
        assert_eq!(
            result.unwrap(),
            vec![DnsRecord::TLSA(TLSARecord {
                cert_usage: TlsaCertUsage::DaneEe,
                selector: TlsaSelector::Spki,
                matching: TlsaMatching::Sha256,
                cert_data: vec![0xab, 0xcd],
            })]
        );
        token.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_srv_with_sidecar() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);

        let list = server
            .mock("GET", "/dns/v2/zones/example.com/records/_sip._tcp/SRV")
            .with_status(200)
            .with_body(
                r#"{"records":[{"host":"_sip._tcp","ttl":300,"type":"SRV","data":"sip.example.com.","srv_priority":10,"srv_weight":20,"srv_port":443}]}"#,
            )
            .create();

        let p = provider(server.url());
        let result = p
            .list_rrset("_sip._tcp.example.com", DnsRecordType::SRV, "example.com")
            .await;
        assert!(result.is_ok(), "list_rrset returned {result:?}");
        assert_eq!(
            result.unwrap(),
            vec![DnsRecord::SRV(SRVRecord {
                priority: 10,
                weight: 20,
                port: 443,
                target: "sip.example.com".to_string(),
            })]
        );
        token.assert();
        list.assert();
    }
}
