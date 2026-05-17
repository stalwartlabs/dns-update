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
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, SRVRecord,
        providers::inwx::InwxProvider,
    };
    use serde_json::{Value, json};
    use std::time::Duration;

    fn setup(server_url: &str) -> InwxProvider {
        InwxProvider::new(
            "user",
            "pass",
            None,
            false,
            Some(Duration::from_secs(2)),
        )
        .expect("provider")
        .with_endpoint(server_url)
        .with_cached_session("inwx-session=abcd")
    }

    fn json_match(expected: serde_json::Value) -> mockito::Matcher {
        mockito::Matcher::Json(expected)
    }

    fn match_method(name: &str) -> mockito::Matcher {
        let pattern = format!(r#""method"\s*:\s*"{name}""#);
        mockito::Matcher::Regex(pattern)
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_inwx(
            "user",
            "pass",
            None,
            false,
            Some(Duration::from_secs(1)),
        );
        assert!(matches!(updater, Ok(DnsUpdater::Inwx(..))));
    }

    #[tokio::test]
    async fn create_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.createRecord",
                "params": {
                    "domain": "example.com",
                    "name": "test.example.com",
                    "type": "A",
                    "content": "1.1.1.1",
                    "ttl": 300
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"msg":"Command completed successfully","resData":{"id":12345}}"#)
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
    async fn create_record_api_error() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.createRecord"))
            .with_status(200)
            .with_body(r#"{"code":2005,"msg":"Object exists"}"#)
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

        assert!(matches!(result, Err(Error::Api(_))));
        mock.assert();
    }

    #[tokio::test]
    async fn create_mx_record_includes_prio() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.createRecord",
                "params": {
                    "domain": "example.com",
                    "name": "example.com",
                    "type": "MX",
                    "content": "mail.example.com",
                    "ttl": 600,
                    "prio": 10
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"id":42}}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .create(
                "example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".into(),
                    priority: 10,
                }),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn update_record_resolves_id_then_updates() {
        let mut server = mockito::Server::new_async().await;
        let info_mock = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.info",
                "params": {
                    "domain": "example.com",
                    "name": "test.example.com",
                    "type": "TXT"
                }
            })))
            .with_status(200)
            .with_body(
                r#"{
                    "code": 1000,
                    "resData": {
                        "record": [{
                            "id": 555,
                            "name": "test.example.com",
                            "type": "TXT",
                            "content": "old"
                        }]
                    }
                }"#,
            )
            .create();

        let update_mock = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.updateRecord",
                "params": {
                    "id": 555,
                    "content": "new value",
                    "ttl": 3600
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"msg":"ok"}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::TXT("new value".into()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{result:?}");
        info_mock.assert();
        update_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let info_mock = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.info",
                "params": {
                    "domain": "example.com",
                    "name": "test.example.com",
                    "type": "AAAA"
                }
            })))
            .with_status(200)
            .with_body(
                r#"{"code":1000,"resData":{"record":[{"id":99,"name":"test.example.com","type":"AAAA","content":"::1"}]}}"#,
            )
            .create();
        let delete_mock = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.deleteRecord",
                "params": {"id": 99}
            })))
            .with_status(200)
            .with_body(r#"{"code":1000}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::AAAA)
            .await;
        assert!(result.is_ok(), "{result:?}");
        info_mock.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    async fn create_srv_record_includes_prio_and_content() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.createRecord",
                "params": {
                    "domain": "example.com",
                    "name": "_sip._tcp.example.com",
                    "type": "SRV",
                    "content": "20 5060 sip.example.com",
                    "ttl": 3600,
                    "prio": 10
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"id":1}}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .create(
                "_sip._tcp.example.com",
                DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 20,
                    port: 5060,
                    target: "sip.example.com".into(),
                }),
                3600,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn create_caa_record_formats_content() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.createRecord",
                "params": {
                    "domain": "example.com",
                    "name": "example.com",
                    "type": "CAA",
                    "content": "0 issue \"letsencrypt.org\"",
                    "ttl": 3600
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"id":2}}"#)
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
    async fn create_tlsa_returns_unsupported() {
        let provider = InwxProvider::new(
            "user",
            "pass",
            None,
            false,
            Some(Duration::from_secs(1)),
        )
        .expect("provider")
        .with_cached_session("inwx-session=zzz");
        let result = provider
            .create(
                "_443._tcp.example.com",
                DnsRecord::TLSA(crate::TLSARecord {
                    cert_usage: crate::TlsaCertUsage::DaneEe,
                    selector: crate::TlsaSelector::Spki,
                    matching: crate::TlsaMatching::Sha256,
                    cert_data: vec![0u8; 4],
                }),
                300,
                "example.com",
            )
            .await;
        match result {
            Err(Error::Api(msg)) => assert!(msg.contains("TLSA")),
            other => panic!("expected TLSA Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn login_unsupported_with_tfa() {
        let mut server = mockito::Server::new_async().await;
        let _login_mock = server
            .mock("POST", "/")
            .match_body(match_method("account.login"))
            .with_status(200)
            .with_header("set-cookie", "inwx-session=foo; Path=/")
            .with_body(r#"{"code":1000,"resData":{"tfa":"GOOGLE-AUTH"}}"#)
            .create();

        let provider = InwxProvider::new(
            "user",
            "pass",
            Some("secret".into()),
            false,
            Some(Duration::from_secs(2)),
        )
        .expect("provider")
        .with_endpoint(server.url().as_str());

        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        match result {
            Err(Error::Api(msg)) => assert!(msg.contains("2FA"), "{msg}"),
            other => panic!("expected 2FA Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore = "Requires INWX sandbox account credentials"]
    async fn integration_test() {
        let username = ""; // <-- INWX sandbox username
        let password = ""; // <-- INWX sandbox password
        let domain = ""; // <-- e.g. "example.com"
        assert!(!username.is_empty() && !password.is_empty() && !domain.is_empty());
        let provider = InwxProvider::new(
            username,
            password,
            None,
            true,
            Some(Duration::from_secs(30)),
        )
        .expect("provider");
        provider
            .create(
                &format!("test.{domain}"),
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                domain,
            )
            .await
            .expect("create");
        provider
            .delete(&format!("test.{domain}"), domain, DnsRecordType::A)
            .await
            .expect("delete");
        let _ = Value::Null;
    }
}
