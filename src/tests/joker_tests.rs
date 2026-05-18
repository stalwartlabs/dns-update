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
        DnsRecord, DnsRecordType, DnsUpdater, Error,
        providers::joker::{JokerAuth, JokerProvider},
    };
    use mockito::Matcher;
    use std::time::Duration;

    fn provider(endpoint: String) -> JokerProvider {
        JokerProvider::new(JokerAuth::api_key("api-key-1"), Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_logs_in_then_writes_zone() {
        let mut server = mockito::Server::new_async().await;
        let login = server
            .mock("POST", "/login")
            .match_body(Matcher::UrlEncoded("api-key".into(), "api-key-1".into()))
            .with_status(200)
            .with_body("Status-Code: 0\nStatus-Text: OK\nAuth-Sid: sid-1\n\n")
            .create();

        let get = server
            .mock("POST", "/dns-zone-get")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("auth-sid".into(), "sid-1".into()),
                Matcher::UrlEncoded("domain".into(), "example.com".into()),
            ]))
            .with_status(200)
            .with_body("Status-Code: 0\nStatus-Text: OK\n\nwww A 0 1.1.1.1 300\n")
            .create();

        let put = server
            .mock("POST", "/dns-zone-put")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("auth-sid".into(), "sid-1".into()),
                Matcher::UrlEncoded("domain".into(), "example.com".into()),
                Matcher::Regex("zone=www\\+A\\+0\\+1\\.1\\.1\\.1\\+300%0A_acme\\+TXT\\+0\\+%22v%22\\+300".into()),
            ]))
            .with_status(200)
            .with_body("Status-Code: 0\nStatus-Text: OK\n\n")
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

        assert!(result.is_ok(), "create returned {result:?}");
        login.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_delete_removes_matching_entries() {
        let mut server = mockito::Server::new_async().await;
        let login = server
            .mock("POST", "/login")
            .with_status(200)
            .with_body("Status-Code: 0\nStatus-Text: OK\nAuth-Sid: sid-2\n\n")
            .create();

        let get = server
            .mock("POST", "/dns-zone-get")
            .with_status(200)
            .with_body(
                "Status-Code: 0\nStatus-Text: OK\n\nwww A 0 1.1.1.1 300\n_acme TXT 0 \"v\" 300\n",
            )
            .create();

        let put = server
            .mock("POST", "/dns-zone-put")
            .match_body(Matcher::Regex(
                "zone=www\\+A\\+0\\+1\\.1\\.1\\.1\\+300".into(),
            ))
            .with_status(200)
            .with_body("Status-Code: 0\nStatus-Text: OK\n\n")
            .create();

        let provider = provider(server.url());
        let result = provider
            .delete("_acme.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete returned {result:?}");
        login.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_login_error_maps_to_api_error() {
        let mut server = mockito::Server::new_async().await;
        let login = server
            .mock("POST", "/login")
            .with_status(200)
            .with_body("Status-Code: 1000\nStatus-Text: bad credentials\n\n")
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
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
        login.assert();
    }

    #[tokio::test]
    #[ignore = "Requires JOKER_API_KEY, JOKER_ORIGIN, JOKER_FQDN"]
    async fn integration_test() {
        let key = std::env::var("JOKER_API_KEY").unwrap_or_default();
        let origin = std::env::var("JOKER_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("JOKER_FQDN").unwrap_or_default();
        assert!(!key.is_empty() && !origin.is_empty() && !fqdn.is_empty());

        let updater =
            DnsUpdater::new_joker(JokerAuth::api_key(key), Some(Duration::from_secs(30))).unwrap();
        updater
            .create(&fqdn, DnsRecord::TXT("x".to_string()), 300, &origin)
            .await
            .unwrap();
        updater
            .delete(&fqdn, &origin, DnsRecordType::TXT)
            .await
            .unwrap();
    }
}
