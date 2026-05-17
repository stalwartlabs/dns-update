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
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord,
        providers::infoblox::{InfobloxConfig, InfobloxProvider},
    };
    use serde_json::json;
    use std::time::Duration;

    fn config() -> InfobloxConfig {
        InfobloxConfig {
            host: "grid.example.com".into(),
            port: None,
            username: "admin".into(),
            password: "secret".into(),
            wapi_version: None,
            dns_view: None,
            request_timeout: Some(Duration::from_secs(2)),
        }
    }

    fn setup(server_url: &str) -> InfobloxProvider {
        InfobloxProvider::new(config())
            .expect("provider")
            .with_endpoint(server_url)
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_infoblox(config());
        assert!(matches!(updater, Ok(DnsUpdater::Infoblox(..))));
    }

    #[tokio::test]
    async fn create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/record:a")
            .match_header("authorization", "Basic YWRtaW46c2VjcmV0")
            .match_body(mockito::Matcher::Json(json!({
                "name": "test.example.com",
                "ipv4addr": "1.1.1.1",
                "ttl": 300,
                "use_ttl": true,
                "view": "External",
            })))
            .with_status(201)
            .with_body(r#""record:a/ZG5zLmJpbmRfYQ:test.example.com/default""#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn create_caa_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/record:caa")
            .match_body(mockito::Matcher::Json(json!({
                "name": "example.com",
                "ca_flag": 0,
                "ca_tag": "issue",
                "ca_value": "letsencrypt.org",
                "ttl": 3600,
                "use_ttl": true,
                "view": "External",
            })))
            .with_status(201)
            .with_body(r#""record:caa/ABC:example.com/default""#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .create(
                "example.com",
                DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".into()),
                    options: vec![],
                }),
                3600,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn update_record_resolves_reference_then_puts() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/record:a\\?".into()))
            .with_status(200)
            .with_body(
                r#"[{"_ref":"record:a/REF1:test.example.com/default","name":"test.example.com","ipv4addr":"1.1.1.1"}]"#,
            )
            .create();
        let put_mock = server
            .mock("PUT", "/record:a/REF1:test.example.com/default")
            .match_body(mockito::Matcher::Json(json!({
                "ipv4addr": "2.2.2.2",
                "ttl": 600,
                "use_ttl": true,
            })))
            .with_status(200)
            .with_body(r#""record:a/REF1:test.example.com/default""#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("2.2.2.2".parse().unwrap()),
                600,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        lookup.assert();
        put_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", "/record:txt")
            .match_query(mockito::Matcher::UrlEncoded(
                "name".into(),
                "test.example.com".into(),
            ))
            .with_status(200)
            .with_body(
                r#"[{"_ref":"record:txt/REF2:test.example.com/default","name":"test.example.com","text":"v=spf1"}]"#,
            )
            .create();
        let delete_mock = server
            .mock("DELETE", "/record:txt/REF2:test.example.com/default")
            .with_status(200)
            .with_body(r#""record:txt/REF2:test.example.com/default""#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;
        assert!(result.is_ok(), "{result:?}");
        lookup.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_not_found() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", "/record:a")
            .match_query(mockito::Matcher::UrlEncoded(
                "name".into(),
                "missing.example.com".into(),
            ))
            .with_status(200)
            .with_body(r#"[]"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .delete("missing.example.com", "example.com", DnsRecordType::A)
            .await;
        assert!(matches!(result, Err(Error::NotFound)));
        lookup.assert();
    }

    #[tokio::test]
    async fn delete_tlsa_returns_unsupported() {
        let provider = setup("http://127.0.0.1:1/wapi/v2.11");
        let result = provider
            .delete("_443._tcp.example.com", "example.com", DnsRecordType::TLSA)
            .await;
        match result {
            Err(Error::Api(msg)) => assert!(msg.contains("TLSA"), "{msg}"),
            other => panic!("expected TLSA Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_mx_record_uses_preference() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/record:mx")
            .match_body(mockito::Matcher::Json(json!({
                "name": "example.com",
                "mail_exchanger": "mail.example.com",
                "preference": 10,
                "ttl": 3600,
                "use_ttl": true,
                "view": "External",
            })))
            .with_status(201)
            .with_body(r#""record:mx/REF""#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .create(
                "example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".into(),
                    priority: 10,
                }),
                3600,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn create_request_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/record:a")
            .with_status(401)
            .with_body(r#"{"Error":"AdmConProtoError: Authentication failed."}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Unauthorized)));
        mock.assert();
    }

    #[tokio::test]
    #[ignore = "Requires Infoblox grid manager credentials"]
    async fn integration_test() {
        let host = ""; // <-- e.g. "grid.example.com"
        let user = ""; // <-- WAPI user
        let pass = ""; // <-- WAPI password
        let zone = ""; // <-- managed zone (e.g. "example.com")
        assert!(!host.is_empty() && !user.is_empty() && !pass.is_empty() && !zone.is_empty());
        let provider = InfobloxProvider::new(InfobloxConfig {
            host: host.into(),
            port: None,
            username: user.into(),
            password: pass.into(),
            wapi_version: None,
            dns_view: None,
            request_timeout: Some(Duration::from_secs(30)),
        })
        .expect("provider");
        let name = format!("test.{zone}");
        provider
            .create(
                name.as_str(),
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                zone,
            )
            .await
            .expect("create");
        provider
            .delete(name.as_str(), zone, DnsRecordType::A)
            .await
            .expect("delete");
    }
}
