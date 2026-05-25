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
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, Error, providers::autodns::AutodnsProvider};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> AutodnsProvider {
        AutodnsProvider::new("user", "pass", Some(4), Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[test]
    fn dns_updater_creation() {
        let updater =
            DnsUpdater::new_autodns("user", "pass", Some(4), Some(Duration::from_secs(30)));
        assert!(updater.is_ok());
        assert!(matches!(updater, Ok(DnsUpdater::Autodns(..))));
    }

    #[test]
    fn empty_credentials_rejected() {
        assert!(matches!(
            AutodnsProvider::new("", "pass", None, None),
            Err(Error::Api(_))
        ));
        assert!(matches!(
            AutodnsProvider::new("user", "", None, None),
            Err(Error::Api(_))
        ));
    }

    #[tokio::test]
    async fn set_rrset_replaces_full_set() {
        let mut server = mockito::Server::new_async().await;

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(
                r#"{"data":[{"origin":"example.com","resourceRecords":[
                    {"name":"www.example.com.","ttl":3600,"type":"A","value":"203.0.113.10"},
                    {"name":"www.example.com.","ttl":3600,"type":"A","value":"203.0.113.11"},
                    {"name":"www.example.com.","ttl":3600,"type":"AAAA","value":"2001:db8::1"}
                ]}]}"#,
            )
            .create();

        let stream_mock = server
            .mock("POST", "/zone/example.com/_stream")
            .match_body(mockito::Matcher::Json(json!({
                "adds": [
                    {"name": "www.example.com.", "ttl": 3600, "type": "A", "value": "203.0.113.20"},
                    {"name": "www.example.com.", "ttl": 3600, "type": "A", "value": "203.0.113.21"}
                ],
                "rems": [
                    {"name": "www.example.com.", "ttl": 3600, "type": "A", "value": "203.0.113.10"},
                    {"name": "www.example.com.", "ttl": 3600, "type": "A", "value": "203.0.113.11"}
                ],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![
                    DnsRecord::A("203.0.113.20".parse().unwrap()),
                    DnsRecord::A("203.0.113.21".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        search_mock.assert();
        stream_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_keeps_overlapping_records() {
        let mut server = mockito::Server::new_async().await;

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(
                r#"{"data":[{"origin":"example.com","resourceRecords":[
                    {"name":"www.example.com.","ttl":3600,"type":"A","value":"203.0.113.10"},
                    {"name":"www.example.com.","ttl":3600,"type":"A","value":"203.0.113.11"}
                ]}]}"#,
            )
            .create();

        let stream_mock = server
            .mock("POST", "/zone/example.com/_stream")
            .match_body(mockito::Matcher::Json(json!({
                "adds": [
                    {"name": "www.example.com.", "ttl": 3600, "type": "A", "value": "203.0.113.12"}
                ],
                "rems": [
                    {"name": "www.example.com.", "ttl": 3600, "type": "A", "value": "203.0.113.10"}
                ],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![
                    DnsRecord::A("203.0.113.11".parse().unwrap()),
                    DnsRecord::A("203.0.113.12".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        search_mock.assert();
        stream_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_deletes_only_target_type() {
        let mut server = mockito::Server::new_async().await;

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(
                r#"{"data":[{"origin":"example.com","resourceRecords":[
                    {"name":"www.example.com.","ttl":3600,"type":"A","value":"203.0.113.10"},
                    {"name":"www.example.com.","ttl":3600,"type":"A","value":"203.0.113.11"},
                    {"name":"www.example.com.","ttl":3600,"type":"AAAA","value":"2001:db8::1"}
                ]}]}"#,
            )
            .create();

        let stream_mock = server
            .mock("POST", "/zone/example.com/_stream")
            .match_body(mockito::Matcher::Json(json!({
                "rems": [
                    {"name": "www.example.com.", "ttl": 3600, "type": "A", "value": "203.0.113.10"},
                    {"name": "www.example.com.", "ttl": 3600, "type": "A", "value": "203.0.113.11"}
                ],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        search_mock.assert();
        stream_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_idempotent_no_http_when_matches() {
        let mut server = mockito::Server::new_async().await;

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(
                r#"{"data":[{"origin":"example.com","resourceRecords":[
                    {"name":"www.example.com.","ttl":3600,"type":"A","value":"203.0.113.10"}
                ]}]}"#,
            )
            .create();

        let stream_mock = server
            .mock("POST", "/zone/example.com/_stream")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("203.0.113.10".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        search_mock.assert();
        stream_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(msg)) if msg.contains("type mismatch")));
    }

    #[tokio::test]
    async fn add_to_rrset_appends_missing() {
        let mut server = mockito::Server::new_async().await;

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(
                r#"{"data":[{"origin":"example.com","resourceRecords":[
                    {"name":"www.example.com.","ttl":3600,"type":"A","value":"203.0.113.10"}
                ]}]}"#,
            )
            .create();

        let stream_mock = server
            .mock("POST", "/zone/example.com/_stream")
            .match_body(mockito::Matcher::Json(json!({
                "adds": [
                    {"name": "www.example.com.", "ttl": 3600, "type": "A", "value": "203.0.113.11"}
                ],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![
                    DnsRecord::A("203.0.113.10".parse().unwrap()),
                    DnsRecord::A("203.0.113.11".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        search_mock.assert();
        stream_mock.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_empty_short_circuits() {
        let mut server = mockito::Server::new_async().await;

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .expect(0)
            .create();
        let stream_mock = server
            .mock("POST", "/zone/example.com/_stream")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        search_mock.assert();
        stream_mock.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_all_present_no_http() {
        let mut server = mockito::Server::new_async().await;

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(
                r#"{"data":[{"origin":"example.com","resourceRecords":[
                    {"name":"www.example.com.","ttl":3600,"type":"A","value":"203.0.113.10"}
                ]}]}"#,
            )
            .create();
        let stream_mock = server
            .mock("POST", "/zone/example.com/_stream")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("203.0.113.10".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        search_mock.assert();
        stream_mock.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::CNAME("oops".to_string())],
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(msg)) if msg.contains("type mismatch")));
    }

    #[tokio::test]
    async fn remove_from_rrset_only_removes_matches() {
        let mut server = mockito::Server::new_async().await;

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(
                r#"{"data":[{"origin":"example.com","resourceRecords":[
                    {"name":"www.example.com.","ttl":3600,"type":"A","value":"203.0.113.10"},
                    {"name":"www.example.com.","ttl":3600,"type":"A","value":"203.0.113.11"}
                ]}]}"#,
            )
            .create();

        let stream_mock = server
            .mock("POST", "/zone/example.com/_stream")
            .match_body(mockito::Matcher::Json(json!({
                "rems": [
                    {"name": "www.example.com.", "ttl": 3600, "type": "A", "value": "203.0.113.10"}
                ],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![
                    DnsRecord::A("203.0.113.10".parse().unwrap()),
                    DnsRecord::A("198.51.100.99".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        search_mock.assert();
        stream_mock.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_short_circuits() {
        let mut server = mockito::Server::new_async().await;

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .expect(0)
            .create();
        let stream_mock = server
            .mock("POST", "/zone/example.com/_stream")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .remove_from_rrset("www.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok());
        search_mock.assert();
        stream_mock.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_all_absent_no_http() {
        let mut server = mockito::Server::new_async().await;

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(r#"{"data":[]}"#)
            .create();
        let stream_mock = server
            .mock("POST", "/zone/example.com/_stream")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("203.0.113.10".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        search_mock.assert();
        stream_mock.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(msg)) if msg.contains("type mismatch")));
    }

    #[tokio::test]
    async fn set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(
                r#"{"data":[{"origin":"example.com","resourceRecords":[
                    {"name":"host.example.com.","ttl":3600,"type":"A","value":"203.0.113.10"},
                    {"name":"host.example.com.","ttl":3600,"type":"AAAA","value":"2001:db8::1"},
                    {"name":"host.example.com.","ttl":3600,"type":"TXT","value":"keep-me"}
                ]}]}"#,
            )
            .create();

        let stream_mock = server
            .mock("POST", "/zone/example.com/_stream")
            .match_body(mockito::Matcher::Json(json!({
                "adds": [
                    {"name": "host.example.com.", "ttl": 3600, "type": "A", "value": "203.0.113.20"}
                ],
                "rems": [
                    {"name": "host.example.com.", "ttl": 3600, "type": "A", "value": "203.0.113.10"}
                ],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("203.0.113.20".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        search_mock.assert();
        stream_mock.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_mx_distinguishes_by_pref() {
        let mut server = mockito::Server::new_async().await;

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(
                r#"{"data":[{"origin":"example.com","resourceRecords":[
                    {"name":"example.com.","ttl":3600,"type":"MX","value":"mail.example.com","pref":10}
                ]}]}"#,
            )
            .create();

        let stream_mock = server
            .mock("POST", "/zone/example.com/_stream")
            .match_body(mockito::Matcher::Json(json!({
                "adds": [
                    {"name": "example.com.", "ttl": 3600, "type": "MX", "value": "mail.example.com", "pref": 20}
                ],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .add_to_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![
                    DnsRecord::MX(crate::MXRecord {
                        exchange: "mail.example.com".to_string(),
                        priority: 10,
                    }),
                    DnsRecord::MX(crate::MXRecord {
                        exchange: "mail.example.com".to_string(),
                        priority: 20,
                    }),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        search_mock.assert();
        stream_mock.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_matching_records() {
        let mut server = mockito::Server::new_async().await;

        let search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(
                r#"{"data":[{"origin":"example.com","resourceRecords":[
                    {"name":"www.example.com.","ttl":3600,"type":"A","value":"203.0.113.10"},
                    {"name":"www.example.com.","ttl":3600,"type":"A","value":"203.0.113.11"},
                    {"name":"www.example.com.","ttl":3600,"type":"AAAA","value":"2001:db8::1"},
                    {"name":"other.example.com.","ttl":3600,"type":"A","value":"198.51.100.1"}
                ]}]}"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();

        assert_eq!(result.len(), 2);
        let values: Vec<String> = result
            .iter()
            .map(|r| match r {
                DnsRecord::A(ip) => ip.to_string(),
                _ => panic!("expected A record"),
            })
            .collect();
        assert!(values.iter().any(|v| v == "203.0.113.10"));
        assert!(values.iter().any(|v| v == "203.0.113.11"));
        search_mock.assert();
    }

    #[tokio::test]
    async fn list_rrset_empty_when_no_matches() {
        let mut server = mockito::Server::new_async().await;

        let _search_mock = server
            .mock("POST", "/zone/example.com/_search")
            .with_status(200)
            .with_body(r#"{"data":[]}"#)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .list_rrset("www.example.com", DnsRecordType::TXT, "example.com")
            .await
            .unwrap();

        assert!(result.is_empty());
    }

    #[tokio::test]
    #[ignore = "Requires AutoDNS account credentials"]
    async fn integration_test() {
        let user = std::env::var("AUTODNS_USER").unwrap_or_default();
        let pass = std::env::var("AUTODNS_PASS").unwrap_or_default();
        let origin = std::env::var("AUTODNS_ORIGIN").unwrap_or_default();
        let subdomain = std::env::var("AUTODNS_SUBDOMAIN").unwrap_or_default();

        assert!(
            !user.is_empty() && !pass.is_empty() && !origin.is_empty() && !subdomain.is_empty(),
            "Set AUTODNS_USER, AUTODNS_PASS, AUTODNS_ORIGIN and AUTODNS_SUBDOMAIN env vars"
        );

        let provider =
            AutodnsProvider::new(&user, &pass, None, Some(Duration::from_secs(30))).unwrap();

        assert!(
            provider
                .set_rrset(
                    &subdomain,
                    DnsRecordType::TXT,
                    300,
                    vec![DnsRecord::TXT("integration".to_string())],
                    &origin
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .set_rrset(&subdomain, DnsRecordType::TXT, 300, vec![], &origin)
                .await
                .is_ok()
        );
    }
}
