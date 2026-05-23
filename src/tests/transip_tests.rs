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
        DnsRecord, DnsRecordType, DnsUpdater, Error,
        providers::transip::TransipProvider,
    };
    use mockito::Matcher;
    use std::time::Duration;

    const DUMMY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAuYAi\n-----END PRIVATE KEY-----";

    fn provider(endpoint: String) -> TransipProvider {
        TransipProvider::new("johndoe", DUMMY_PEM, Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
            .with_cached_token("preset-token")
    }

    #[tokio::test]
    async fn test_create_posts_dns_entry_with_bearer() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/domains/example.com/dns")
            .match_header("authorization", "Bearer preset-token")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"_acme","expire":300,"type":"TXT","content":"value"}}"#
                    .to_string(),
            ))
            .with_status(201)
            .with_body("")
            .create();

        let provider = provider(server.url());
        let result = provider
            .create(
                "_acme.example.com",
                DnsRecord::TXT("value".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned {result:?}");
        m.assert();
    }

    #[tokio::test]
    async fn test_update_patches_dns_entry() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("PATCH", "/domains/example.com/dns")
            .match_header("authorization", "Bearer preset-token")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"www","expire":600,"type":"A","content":"5.6.7.8"}}"#
                    .to_string(),
            ))
            .with_status(204)
            .with_body("")
            .create();

        let provider = provider(server.url());
        let result = provider
            .update(
                "www.example.com",
                DnsRecord::A("5.6.7.8".parse().unwrap()),
                600,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "update returned {result:?}");
        m.assert();
    }

    #[tokio::test]
    async fn test_delete_lists_then_deletes_matching_entries() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/domains/example.com/dns")
            .match_header("authorization", "Bearer preset-token")
            .with_status(200)
            .with_body(
                r#"{"dnsEntries":[{"name":"_acme","expire":300,"type":"TXT","content":"v"},{"name":"www","expire":300,"type":"A","content":"1.1.1.1"}]}"#,
            )
            .create();

        let del = server
            .mock("DELETE", "/domains/example.com/dns")
            .match_body(Matcher::PartialJsonString(
                r#"{"dnsEntry":{"name":"_acme","expire":300,"type":"TXT","content":"v"}}"#
                    .to_string(),
            ))
            .with_status(204)
            .with_body("")
            .create();

        let provider = provider(server.url());
        let result = provider
            .delete("_acme.example.com", "example.com", DnsRecordType::TXT)
            .await;
        assert!(result.is_ok(), "delete returned {result:?}");
        list.assert();
        del.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_error_propagates() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/domains/example.com/dns")
            .with_status(401)
            .with_body(r#"{"error":"Unauthorized"}"#)
            .create();

        let provider = provider(server.url());
        let result = provider
            .create(
                "_acme.example.com",
                DnsRecord::TXT("v".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Unauthorized)), "got {result:?}");
        m.assert();
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
    #[ignore = "Requires TRANSIP_LOGIN, TRANSIP_PRIVATE_KEY, TRANSIP_ORIGIN, TRANSIP_FQDN"]
    async fn integration_test() {
        let login = std::env::var("TRANSIP_LOGIN").unwrap_or_default();
        let key = std::env::var("TRANSIP_PRIVATE_KEY").unwrap_or_default();
        let origin = std::env::var("TRANSIP_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("TRANSIP_FQDN").unwrap_or_default();
        assert!(!login.is_empty() && !key.is_empty() && !origin.is_empty() && !fqdn.is_empty());

        let updater =
            DnsUpdater::new_transip(login, key, Some(Duration::from_secs(30))).unwrap();
        updater
            .create(&fqdn, DnsRecord::TXT("v".to_string()), 300, &origin)
            .await
            .unwrap();
        updater
            .delete(&fqdn, &origin, DnsRecordType::TXT)
            .await
            .unwrap();
    }
}
