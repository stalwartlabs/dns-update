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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::ultradns::UltraDnsProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup(server_url: &str) -> UltraDnsProvider {
        UltraDnsProvider::new(
            "user",
            "pass",
            Some(server_url.to_string()),
            Some(Duration::from_secs(2)),
        )
        .expect("provider")
        .with_endpoint(server_url)
        .with_cached_token("cached-token")
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_ultradns("user", "pass", None, Some(Duration::from_secs(1)));
        assert!(matches!(updater, Ok(DnsUpdater::UltraDns(..))));
    }

    #[tokio::test]
    async fn set_rrset_puts_multi_value_rdata() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("PUT", "/v3/zones/example.com./rrsets/A/www.example.com.")
            .match_header("authorization", "Bearer cached-token")
            .match_body(Matcher::Json(json!({
                "ttl": 300,
                "rdata": ["1.1.1.1", "2.2.2.2"],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup(server.url().as_str());
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
        assert!(result.is_ok(), "{result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_deletes_only_this_type() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("DELETE", "/v3/zones/example.com./rrsets/A/www.example.com.")
            .with_status(204)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_treats_404_as_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("DELETE", "/v3/zones/example.com./rrsets/A/www.example.com.")
            .with_status(404)
            .with_body(r#"[{"errorCode":70002,"errorMessage":"Data not found."}]"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_type_mismatch_returns_error() {
        let server = mockito::Server::new_async().await;
        let provider = setup(server.url().as_str());
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
    async fn add_to_rrset_merges_with_existing() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v3/zones/example.com./rrsets/A/www.example.com.")
            .with_status(200)
            .with_body(
                r#"{"zoneName":"example.com.","rrSets":[{"ownerName":"www.example.com.","rrtype":"A (1)","ttl":3600,"rdata":["1.1.1.1"]}]}"#,
            )
            .create();
        let put = server
            .mock("PUT", "/v3/zones/example.com./rrsets/A/www.example.com.")
            .match_body(Matcher::Json(json!({
                "ttl": 3600,
                "rdata": ["1.1.1.1", "2.2.2.2"],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_when_not_found_creates_new() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v3/zones/example.com./rrsets/A/www.example.com.")
            .with_status(404)
            .with_body(r#"[{"errorCode":70002,"errorMessage":"Data not found."}]"#)
            .create();
        let put = server
            .mock("PUT", "/v3/zones/example.com./rrsets/A/www.example.com.")
            .match_body(Matcher::Json(json!({
                "ttl": 600,
                "rdata": ["1.1.1.1"],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn remove_from_rrset_filters_and_puts_remainder() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v3/zones/example.com./rrsets/A/www.example.com.")
            .with_status(200)
            .with_body(
                r#"{"zoneName":"example.com.","rrSets":[{"ownerName":"www.example.com.","rrtype":"A (1)","ttl":3600,"rdata":["1.1.1.1","2.2.2.2"]}]}"#,
            )
            .create();
        let put = server
            .mock("PUT", "/v3/zones/example.com./rrsets/A/www.example.com.")
            .match_body(Matcher::Json(json!({
                "ttl": 3600,
                "rdata": ["2.2.2.2"],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_when_empty_remains() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v3/zones/example.com./rrsets/A/www.example.com.")
            .with_status(200)
            .with_body(
                r#"{"zoneName":"example.com.","rrSets":[{"ownerName":"www.example.com.","rrtype":"A (1)","ttl":3600,"rdata":["1.1.1.1"]}]}"#,
            )
            .create();
        let delete = server
            .mock("DELETE", "/v3/zones/example.com./rrsets/A/www.example.com.")
            .with_status(204)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        get.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_when_not_found_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v3/zones/example.com./rrsets/A/www.example.com.")
            .with_status(404)
            .with_body(r#"[{"errorCode":70002,"errorMessage":"Data not found."}]"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        get.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup(server.url().as_str());
        let result = provider
            .remove_from_rrset("www.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn list_rrset_parses_rdata() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v3/zones/example.com./rrsets/A/www.example.com.")
            .with_status(200)
            .with_body(
                r#"{"zoneName":"example.com.","rrSets":[{"ownerName":"www.example.com.","rrtype":"A (1)","ttl":3600,"rdata":["1.1.1.1","2.2.2.2"]}]}"#,
            )
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list");
        assert_eq!(
            result,
            vec![
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                DnsRecord::A("2.2.2.2".parse().unwrap()),
            ]
        );
        get.assert();
    }

    #[tokio::test]
    async fn list_rrset_404_returns_empty() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v3/zones/example.com./rrsets/A/www.example.com.")
            .with_status(404)
            .with_body(r#"[{"errorCode":70002,"errorMessage":"Data not found."}]"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list");
        assert!(result.is_empty());
        get.assert();
    }

    #[tokio::test]
    #[ignore = "Requires UltraDNS account credentials and a managed zone"]
    async fn integration_test() {
        let username = "";
        let password = "";
        let zone = "";
        assert!(!username.is_empty() && !password.is_empty() && !zone.is_empty());
        let provider =
            UltraDnsProvider::new(username, password, None, Some(Duration::from_secs(30)))
                .expect("provider");
        let owner = format!("test.{zone}");
        provider
            .set_rrset(
                owner.as_str(),
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                zone,
            )
            .await
            .expect("set");
        provider
            .set_rrset(owner.as_str(), DnsRecordType::A, 3600, vec![], zone)
            .await
            .expect("delete");
    }
}
