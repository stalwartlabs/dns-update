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
    use crate::{DnsRecord, DnsRecordType, Error, MXRecord, providers::netlify::NetlifyProvider};
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> NetlifyProvider {
        NetlifyProvider::new("test-token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_only_matching_type() {
        let mut server = mockito::Server::new_async().await;

        let list = server
            .mock("GET", "/dns_zones/example_com/dns_records")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"[
                    {"id":"rec-a1","hostname":"test.example.com","type":"A","value":"1.1.1.1"},
                    {"id":"rec-a2","hostname":"test.example.com","type":"A","value":"2.2.2.2"},
                    {"id":"rec-txt","hostname":"test.example.com","type":"TXT","value":"keep"},
                    {"id":"rec-other","hostname":"other.example.com","type":"A","value":"9.9.9.9"}
                ]"#,
            )
            .create();
        let del1 = server
            .mock("DELETE", "/dns_zones/example_com/dns_records/rec-a1")
            .with_status(204)
            .create();
        let del2 = server
            .mock("DELETE", "/dns_zones/example_com/dns_records/rec-a2")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        del1.assert();
        del2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_diff_adds_and_removes() {
        let mut server = mockito::Server::new_async().await;

        let list = server
            .mock("GET", "/dns_zones/example_com/dns_records")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"[
                    {"id":"keep","hostname":"test.example.com","type":"A","value":"1.1.1.1"},
                    {"id":"drop","hostname":"test.example.com","type":"A","value":"2.2.2.2"},
                    {"id":"txt","hostname":"test.example.com","type":"TXT","value":"v=spf1"}
                ]"#,
            )
            .create();
        let del = server
            .mock("DELETE", "/dns_zones/example_com/dns_records/drop")
            .with_status(204)
            .create();
        let add = server
            .mock("POST", "/dns_zones/example_com/dns_records")
            .match_body(Matcher::Json(json!({
                "hostname": "test.example.com",
                "type": "A",
                "value": "3.3.3.3",
                "ttl": 300
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"new"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("3.3.3.3".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        del.assert();
        add.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_idempotent_no_changes() {
        let mut server = mockito::Server::new_async().await;

        let list = server
            .mock("GET", "/dns_zones/example_com/dns_records")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"[
                    {"id":"a1","hostname":"test.example.com","type":"A","value":"1.1.1.1"},
                    {"id":"a2","hostname":"test.example.com","type":"A","value":"2.2.2.2"}
                ]"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_present() {
        let mut server = mockito::Server::new_async().await;

        let list = server
            .mock("GET", "/dns_zones/example_com/dns_records")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"[
                    {"id":"a1","hostname":"test.example.com","type":"A","value":"1.1.1.1"}
                ]"#,
            )
            .create();
        let add = server
            .mock("POST", "/dns_zones/example_com/dns_records")
            .match_body(Matcher::Json(json!({
                "hostname": "test.example.com",
                "type": "A",
                "value": "2.2.2.2",
                "ttl": 300
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"new"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        list.assert();
        add.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_ignores_absent() {
        let mut server = mockito::Server::new_async().await;

        let list = server
            .mock("GET", "/dns_zones/example_com/dns_records")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"[
                    {"id":"a1","hostname":"test.example.com","type":"A","value":"1.1.1.1"}
                ]"#,
            )
            .create();
        let del = server
            .mock("DELETE", "/dns_zones/example_com/dns_records/a1")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("9.9.9.9".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
        del.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_with_priority() {
        let mut server = mockito::Server::new_async().await;

        let list = server
            .mock("GET", "/dns_zones/example_com/dns_records")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[]"#)
            .create();
        let add = server
            .mock("POST", "/dns_zones/example_com/dns_records")
            .match_body(Matcher::Json(json!({
                "hostname": "example.com",
                "type": "MX",
                "value": "mail.example.com",
                "priority": 10,
                "ttl": 300
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"mx1"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                300,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset MX returned: {result:?}");
        list.assert();
        add.assert();
    }

    #[tokio::test]
    async fn test_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_tlsa_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::TLSA,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Unsupported(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_list_rrset_filters_by_name_and_type() {
        let mut server = mockito::Server::new_async().await;

        let list = server
            .mock("GET", "/dns_zones/example_com/dns_records")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"[
                    {"id":"a1","hostname":"test.example.com","type":"A","value":"1.1.1.1"},
                    {"id":"a2","hostname":"test.example.com","type":"A","value":"2.2.2.2"},
                    {"id":"txt","hostname":"test.example.com","type":"TXT","value":"abc"},
                    {"id":"other","hostname":"other.example.com","type":"A","value":"3.3.3.3"}
                ]"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("test.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");

        list.assert();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
    }
}
