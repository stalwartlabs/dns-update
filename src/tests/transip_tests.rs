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
    use crate::{DnsRecord, DnsRecordType, Error, providers::transip::TransipProvider};
    use mockito::Matcher;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    const DUMMY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAuYAi\n-----END PRIVATE KEY-----";

    fn provider(endpoint: String) -> TransipProvider {
        TransipProvider::new("johndoe", DUMMY_PEM, true, Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
            .with_cached_token("preset-token")
    }

    #[test]
    fn test_nonce_fits_within_transip_limit() {
        let nonce = crate::providers::transip::generate_nonce();
        assert!(
            (6..=32).contains(&nonce.len()),
            "TransIP nonce must be 6..=32 chars, got {} ({nonce})",
            nonce.len()
        );
    }

    #[tokio::test]
    async fn test_set_rrset_replaces_existing_and_preserves_other_types() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_body(
                r#"{"dnsEntries":[
                    {"name":"www","expire":300,"type":"A","content":"1.1.1.1"},
                    {"name":"www","expire":300,"type":"TXT","content":"old"},
                    {"name":"mail","expire":300,"type":"MX","content":"10 mail.example.com"}
                ]}"#,
            )
            .create();

        let del_old = server
            .mock("DELETE", "/domains/example.com/dns")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"www","expire":300,"type":"TXT","content":"old"}}"#
                    .to_string(),
            ))
            .with_status(204)
            .with_body("")
            .create();

        let post_new_a = server
            .mock("POST", "/domains/example.com/dns")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"www","expire":300,"type":"TXT","content":"new-a"}}"#
                    .to_string(),
            ))
            .with_status(201)
            .with_body("")
            .create();

        let post_new_b = server
            .mock("POST", "/domains/example.com/dns")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"www","expire":300,"type":"TXT","content":"new-b"}}"#
                    .to_string(),
            ))
            .with_status(201)
            .with_body("")
            .create();

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                300,
                vec![
                    DnsRecord::TXT("new-a".to_string()),
                    DnsRecord::TXT("new-b".to_string()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
        del_old.assert();
        post_new_a.assert();
        post_new_b.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_only_target_rrset() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_body(
                r#"{"dnsEntries":[
                    {"name":"www","expire":300,"type":"A","content":"1.1.1.1"},
                    {"name":"www","expire":300,"type":"TXT","content":"old-a"},
                    {"name":"www","expire":300,"type":"TXT","content":"old-b"}
                ]}"#,
            )
            .create();

        let del_a = server
            .mock("DELETE", "/domains/example.com/dns")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"www","expire":300,"type":"TXT","content":"old-a"}}"#
                    .to_string(),
            ))
            .with_status(204)
            .with_body("")
            .create();

        let del_b = server
            .mock("DELETE", "/domains/example.com/dns")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"www","expire":300,"type":"TXT","content":"old-b"}}"#
                    .to_string(),
            ))
            .with_status(204)
            .with_body("")
            .create();

        let unexpected_del_a = server
            .mock("DELETE", "/domains/example.com/dns")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"www","expire":300,"type":"A","content":"1.1.1.1"}}"#
                    .to_string(),
            ))
            .with_status(204)
            .with_body("")
            .expect(0)
            .create();

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
        del_a.assert();
        del_b.assert();
        unexpected_del_a.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_idempotent_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_body(
                r#"{"dnsEntries":[
                    {"name":"www","expire":300,"type":"A","content":"1.1.1.1"}
                ]}"#,
            )
            .create();

        let no_post = server
            .mock("POST", "/domains/example.com/dns")
            .with_status(201)
            .expect(0)
            .create();
        let no_delete = server
            .mock("DELETE", "/domains/example.com/dns")
            .with_status(204)
            .expect(0)
            .create();

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A(Ipv4Addr::new(1, 1, 1, 1))],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
        no_post.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_on_missing_rrset_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_body(
                r#"{"dnsEntries":[
                    {"name":"www","expire":300,"type":"A","content":"1.1.1.1"}
                ]}"#,
            )
            .create();

        let no_delete = server
            .mock("DELETE", "/domains/example.com/dns")
            .with_status(204)
            .expect(0)
            .create();

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_short_circuits() {
        let server = mockito::Server::new_async().await;
        let provider = provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_duplicates() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_body(
                r#"{"dnsEntries":[
                    {"name":"www","expire":300,"type":"TXT","content":"existing"},
                    {"name":"www","expire":300,"type":"A","content":"1.1.1.1"}
                ]}"#,
            )
            .create();

        let post_fresh = server
            .mock("POST", "/domains/example.com/dns")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"www","expire":300,"type":"TXT","content":"fresh"}}"#
                    .to_string(),
            ))
            .with_status(201)
            .with_body("")
            .create();

        let no_post_existing = server
            .mock("POST", "/domains/example.com/dns")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"www","expire":300,"type":"TXT","content":"existing"}}"#
                    .to_string(),
            ))
            .with_status(201)
            .expect(0)
            .create();

        let provider = provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                300,
                vec![
                    DnsRecord::TXT("existing".to_string()),
                    DnsRecord::TXT("fresh".to_string()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
        list.assert();
        post_fresh.assert();
        no_post_existing.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_short_circuits() {
        let server = mockito::Server::new_async().await;
        let provider = provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_body(
                r#"{"dnsEntries":[
                    {"name":"www","expire":300,"type":"TXT","content":"keep"},
                    {"name":"www","expire":300,"type":"TXT","content":"drop"},
                    {"name":"www","expire":300,"type":"A","content":"1.1.1.1"}
                ]}"#,
            )
            .create();

        let del_drop = server
            .mock("DELETE", "/domains/example.com/dns")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"www","expire":300,"type":"TXT","content":"drop"}}"#
                    .to_string(),
            ))
            .with_status(204)
            .with_body("")
            .create();

        let no_del_keep = server
            .mock("DELETE", "/domains/example.com/dns")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"www","expire":300,"type":"TXT","content":"keep"}}"#
                    .to_string(),
            ))
            .with_status(204)
            .expect(0)
            .create();

        let no_del_a = server
            .mock("DELETE", "/domains/example.com/dns")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"www","expire":300,"type":"A","content":"1.1.1.1"}}"#
                    .to_string(),
            ))
            .with_status(204)
            .expect(0)
            .create();

        let provider = provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop".to_string())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        list.assert();
        del_drop.assert();
        no_del_keep.assert();
        no_del_a.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_absent_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_body(
                r#"{"dnsEntries":[
                    {"name":"www","expire":300,"type":"TXT","content":"keep"}
                ]}"#,
            )
            .create();

        let no_delete = server
            .mock("DELETE", "/domains/example.com/dns")
            .with_status(204)
            .expect(0)
            .create();

        let provider = provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("nothing-matches".to_string())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        list.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_filters_by_name_and_type() {
        let mut server = mockito::Server::new_async().await;
        let _list = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_body(
                r#"{"dnsEntries":[
                    {"name":"www","expire":300,"type":"A","content":"1.1.1.1"},
                    {"name":"www","expire":300,"type":"A","content":"2.2.2.2"},
                    {"name":"www","expire":300,"type":"TXT","content":"hello"},
                    {"name":"mail","expire":300,"type":"A","content":"9.9.9.9"}
                ]}"#,
            )
            .create();

        let provider = provider(server.url());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");
        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(result.contains(&DnsRecord::A(Ipv4Addr::new(2, 2, 2, 2))));
    }

    #[tokio::test]
    async fn test_list_rrset_empty_when_no_match() {
        let mut server = mockito::Server::new_async().await;
        let _list = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_body(
                r#"{"dnsEntries":[
                    {"name":"mail","expire":300,"type":"A","content":"9.9.9.9"}
                ]}"#,
            )
            .create();

        let provider = provider(server.url());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref m)) if m.contains("type mismatch")),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_add_to_rrset_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref m)) if m.contains("type mismatch")),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_remove_from_rrset_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref m)) if m.contains("type mismatch")),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_appends_trailing_dot_to_mx_exchange() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_body(r#"{"dnsEntries":[]}"#)
            .create();

        let post = server
            .mock("POST", "/domains/example.com/dns")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"@","expire":300,"type":"MX","content":"10 mail.example.com."}}"#
                    .to_string(),
            ))
            .with_status(201)
            .with_body("")
            .create();

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                300,
                vec![DnsRecord::MX(crate::MXRecord {
                    priority: 10,
                    exchange: "mail.example.com".to_string(),
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
        post.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_idempotent_for_mx_already_dotted() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_body(
                r#"{"dnsEntries":[
                    {"name":"@","expire":300,"type":"MX","content":"10 mail.example.com."}
                ]}"#,
            )
            .create();

        let no_post = server
            .mock("POST", "/domains/example.com/dns")
            .with_status(201)
            .expect(0)
            .create();
        let no_delete = server
            .mock("DELETE", "/domains/example.com/dns")
            .with_status(204)
            .expect(0)
            .create();

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                300,
                vec![DnsRecord::MX(crate::MXRecord {
                    priority: 10,
                    exchange: "mail.example.com".to_string(),
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
        no_post.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_strips_trailing_dot_from_mx() {
        let mut server = mockito::Server::new_async().await;
        let _list = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_body(
                r#"{"dnsEntries":[
                    {"name":"@","expire":300,"type":"MX","content":"10 mail.example.com."}
                ]}"#,
            )
            .create();

        let provider = provider(server.url());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .expect("list_rrset failed");
        assert_eq!(
            result,
            vec![DnsRecord::MX(crate::MXRecord {
                priority: 10,
                exchange: "mail.example.com".to_string(),
            })]
        );
    }

    #[tokio::test]
    async fn test_set_rrset_uses_apex_when_name_equals_origin() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/domains/example.com/dns")
            .with_status(200)
            .with_body(r#"{"dnsEntries":[]}"#)
            .create();

        let post = server
            .mock("POST", "/domains/example.com/dns")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"@","expire":300,"type":"A","content":"7.7.7.7"}}"#
                    .to_string(),
            ))
            .with_status(201)
            .with_body("")
            .create();

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A(Ipv4Addr::new(7, 7, 7, 7))],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
        post.assert();
    }
}
