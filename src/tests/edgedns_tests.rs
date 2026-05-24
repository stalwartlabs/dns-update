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
    use crate::providers::edgedns::{EdgeDnsConfig, EdgeDnsProvider};
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord};
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn provider_with_endpoint(endpoint: &str) -> EdgeDnsProvider {
        let config = EdgeDnsConfig {
            host: "edgedns.akamaiapis.net".to_string(),
            client_token: "client-token-value".to_string(),
            client_secret: "client-secret-value".to_string(),
            access_token: "access-token-value".to_string(),
            account_switch_key: None,
            request_timeout: Some(Duration::from_secs(5)),
        };
        EdgeDnsProvider::new(config)
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[test]
    fn updater_factory_creates_edgedns_variant() {
        let updater = DnsUpdater::new_edgedns(EdgeDnsConfig {
            host: "edgedns.akamaiapis.net".to_string(),
            client_token: "ct".to_string(),
            client_secret: "cs".to_string(),
            access_token: "at".to_string(),
            account_switch_key: None,
            request_timeout: None,
        })
        .unwrap();
        assert!(matches!(updater, DnsUpdater::EdgeDns(_)));
    }

    #[test]
    fn missing_credentials_rejected() {
        let res = EdgeDnsProvider::new(EdgeDnsConfig {
            host: "edgedns.akamaiapis.net".to_string(),
            client_token: String::new(),
            client_secret: "cs".to_string(),
            access_token: "at".to_string(),
            account_switch_key: None,
            request_timeout: None,
        });
        assert!(matches!(res, Err(Error::Client(_))));
    }

    #[tokio::test]
    async fn set_rrset_puts_full_rdata_array() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "PUT",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/A",
            )
            .match_body(Matcher::Json(json!({
                "name": "www.example.com",
                "type": "A",
                "ttl": 120,
                "rdata": ["1.2.3.4", "5.6.7.8"]
            })))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                120,
                vec![
                    DnsRecord::A("1.2.3.4".parse().unwrap()),
                    DnsRecord::A("5.6.7.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {:?}", result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn set_rrset_falls_back_to_post_when_missing() {
        let mut server = mockito::Server::new_async().await;
        let put_mock = server
            .mock(
                "PUT",
                "/config-dns/v2/zones/example.com/names/api.example.com/types/A",
            )
            .with_status(404)
            .with_body(r#"{"detail":"not found"}"#)
            .create_async()
            .await;
        let post_mock = server
            .mock(
                "POST",
                "/config-dns/v2/zones/example.com/names/api.example.com/types/A",
            )
            .match_body(Matcher::Json(json!({
                "name": "api.example.com",
                "type": "A",
                "ttl": 60,
                "rdata": ["9.9.9.9"]
            })))
            .with_status(201)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .set_rrset(
                "api.example.com",
                DnsRecordType::A,
                60,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {:?}", result);
        put_mock.assert_async().await;
        post_mock.assert_async().await;
    }

    #[tokio::test]
    async fn set_rrset_with_empty_vec_deletes() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "DELETE",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/A",
            )
            .with_status(204)
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {:?}", result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn set_rrset_with_empty_vec_swallows_404() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "DELETE",
                "/config-dns/v2/zones/example.com/names/missing.example.com/types/A",
            )
            .with_status(404)
            .with_body(r#"{"detail":"not found"}"#)
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .set_rrset(
                "missing.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {:?}", result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn set_rrset_rejects_type_mismatch() {
        let provider = provider_with_endpoint("http://127.0.0.1:1");
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::AAAA("2001:db8::1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))));
    }

    #[tokio::test]
    async fn add_to_rrset_empty_vec_is_noop() {
        let provider = provider_with_endpoint("http://127.0.0.1:1");
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_to_rrset_merges_with_existing() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock(
                "GET",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/A",
            )
            .with_status(200)
            .with_body(r#"{"name":"www.example.com","type":"A","ttl":300,"rdata":["1.1.1.1"]}"#)
            .create_async()
            .await;
        let put_mock = server
            .mock(
                "PUT",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/A",
            )
            .match_body(Matcher::Json(json!({
                "name": "www.example.com",
                "type": "A",
                "ttl": 120,
                "rdata": ["1.1.1.1", "2.2.2.2"]
            })))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                120,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset failed: {:?}", result);
        get_mock.assert_async().await;
        put_mock.assert_async().await;
    }

    #[tokio::test]
    async fn add_to_rrset_handles_missing_rrset_via_post() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock(
                "GET",
                "/config-dns/v2/zones/example.com/names/new.example.com/types/A",
            )
            .with_status(404)
            .with_body(r#"{"detail":"not found"}"#)
            .create_async()
            .await;
        let put_mock = server
            .mock(
                "PUT",
                "/config-dns/v2/zones/example.com/names/new.example.com/types/A",
            )
            .with_status(404)
            .with_body(r#"{"detail":"not found"}"#)
            .create_async()
            .await;
        let post_mock = server
            .mock(
                "POST",
                "/config-dns/v2/zones/example.com/names/new.example.com/types/A",
            )
            .match_body(Matcher::Json(json!({
                "name": "new.example.com",
                "type": "A",
                "ttl": 60,
                "rdata": ["3.3.3.3"]
            })))
            .with_status(201)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .add_to_rrset(
                "new.example.com",
                DnsRecordType::A,
                60,
                vec![DnsRecord::A("3.3.3.3".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset failed: {:?}", result);
        get_mock.assert_async().await;
        put_mock.assert_async().await;
        post_mock.assert_async().await;
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_vec_is_noop() {
        let provider = provider_with_endpoint("http://127.0.0.1:1");
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn remove_from_rrset_filters_and_puts() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock(
                "GET",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/A",
            )
            .with_status(200)
            .with_body(
                r#"{"name":"www.example.com","type":"A","ttl":300,"rdata":["1.1.1.1","2.2.2.2"]}"#,
            )
            .create_async()
            .await;
        let put_mock = server
            .mock(
                "PUT",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/A",
            )
            .match_body(Matcher::Json(json!({
                "name": "www.example.com",
                "type": "A",
                "ttl": 300,
                "rdata": ["2.2.2.2"]
            })))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {:?}", result);
        get_mock.assert_async().await;
        put_mock.assert_async().await;
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_when_filter_empties_set() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock(
                "GET",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/A",
            )
            .with_status(200)
            .with_body(r#"{"name":"www.example.com","type":"A","ttl":300,"rdata":["1.1.1.1"]}"#)
            .create_async()
            .await;
        let delete_mock = server
            .mock(
                "DELETE",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/A",
            )
            .with_status(204)
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {:?}", result);
        get_mock.assert_async().await;
        delete_mock.assert_async().await;
    }

    #[tokio::test]
    async fn remove_from_rrset_absent_is_noop_when_missing_rrset() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock(
                "GET",
                "/config-dns/v2/zones/example.com/names/missing.example.com/types/A",
            )
            .with_status(404)
            .with_body(r#"{"detail":"not found"}"#)
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .remove_from_rrset(
                "missing.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {:?}", result);
        get_mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_rrset_parses_a_records() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "GET",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/A",
            )
            .with_status(200)
            .with_body(
                r#"{"name":"www.example.com","type":"A","ttl":300,"rdata":["1.1.1.1","2.2.2.2"]}"#,
            )
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();
        assert_eq!(
            result,
            vec![
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                DnsRecord::A("2.2.2.2".parse().unwrap()),
            ]
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_rrset_returns_empty_on_404() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "GET",
                "/config-dns/v2/zones/example.com/names/missing.example.com/types/A",
            )
            .with_status(404)
            .with_body(r#"{"detail":"not found"}"#)
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .list_rrset("missing.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();
        assert!(result.is_empty());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_rrset_parses_mx_records() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "GET",
                "/config-dns/v2/zones/example.com/names/example.com/types/MX",
            )
            .with_status(200)
            .with_body(
                r#"{"name":"example.com","type":"MX","ttl":3600,"rdata":["10 mail.example.com.","20 backup.example.com."]}"#,
            )
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .unwrap();
        assert_eq!(
            result,
            vec![
                DnsRecord::MX(MXRecord {
                    priority: 10,
                    exchange: "mail.example.com".to_string()
                }),
                DnsRecord::MX(MXRecord {
                    priority: 20,
                    exchange: "backup.example.com".to_string()
                }),
            ]
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_rrset_parses_txt_records() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "GET",
                "/config-dns/v2/zones/example.com/names/_acme-challenge.example.com/types/TXT",
            )
            .with_status(200)
            .with_body(
                r#"{"name":"_acme-challenge.example.com","type":"TXT","ttl":60,"rdata":["\"token-value\""]}"#,
            )
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .list_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                "example.com",
            )
            .await
            .unwrap();
        assert_eq!(result, vec![DnsRecord::TXT("token-value".to_string())]);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn set_rrset_txt_chunks_long_value() {
        let mut server = mockito::Server::new_async().await;
        let long_value = "a".repeat(300);
        let expected_rdata = format!("\"{}\" \"{}\"", "a".repeat(255), "a".repeat(45),);
        let mock = server
            .mock(
                "PUT",
                "/config-dns/v2/zones/example.com/names/_acme-challenge.example.com/types/TXT",
            )
            .match_body(Matcher::Json(json!({
                "name": "_acme-challenge.example.com",
                "type": "TXT",
                "ttl": 60,
                "rdata": [expected_rdata]
            })))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .set_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT(long_value)],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {:?}", result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn set_rrset_does_not_touch_other_types() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "PUT",
                "/config-dns/v2/zones/example.com/names/host.example.com/types/A",
            )
            .with_status(200)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;
        let no_other_calls = server
            .mock(
                "DELETE",
                Matcher::Regex(
                    "/config-dns/v2/zones/example.com/names/host.example.com/types/AAAA"
                        .to_string(),
                ),
            )
            .expect(0)
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {:?}", result);
        mock.assert_async().await;
        no_other_calls.assert_async().await;
    }
}
