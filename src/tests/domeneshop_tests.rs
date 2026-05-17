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
    use crate::providers::domeneshop::DomeneshopProvider;
    use crate::{
        CAARecord, DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord, TLSARecord,
        TlsaCertUsage, TlsaMatching, TlsaSelector,
    };
    use serde_json::json;
    use std::time::Duration;

    const DOMAINS_JSON: &str = r#"[
        {"id": 42, "domain": "example.com"}
    ]"#;

    fn setup_provider(endpoint: &str) -> DomeneshopProvider {
        DomeneshopProvider::new("token", "secret", Some(Duration::from_secs(2)))
            .with_endpoint(endpoint)
    }

    fn basic_auth_value() -> String {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        format!("Basic {}", BASE64.encode(b"token:secret"))
    }

    #[tokio::test]
    async fn test_create_a_record() {
        let mut server = mockito::Server::new_async().await;
        let auth = basic_auth_value();
        let domains_mock = server
            .mock("GET", "/domains")
            .match_header("authorization", auth.as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(DOMAINS_JSON)
            .create();

        let expected_body = json!({
            "host": "www",
            "type": "A",
            "data": "1.2.3.4",
            "ttl": 300
        });
        let create_mock = server
            .mock("POST", "/domains/42/dns")
            .match_header("authorization", auth.as_str())
            .match_body(mockito::Matcher::Json(expected_body))
            .with_status(201)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domains_mock.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn test_create_mx_record() {
        let mut server = mockito::Server::new_async().await;
        let auth = basic_auth_value();
        let domains_mock = server
            .mock("GET", "/domains")
            .with_status(200)
            .with_body(DOMAINS_JSON)
            .create();
        let expected_body = json!({
            "host": "@",
            "type": "MX",
            "data": "mail.example.com",
            "ttl": 3600,
            "priority": 10
        });
        let create_mock = server
            .mock("POST", "/domains/42/dns")
            .match_header("authorization", auth.as_str())
            .match_body(mockito::Matcher::Json(expected_body))
            .with_status(201)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domains_mock.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn test_create_srv_record() {
        let mut server = mockito::Server::new_async().await;
        let domains_mock = server
            .mock("GET", "/domains")
            .with_status(200)
            .with_body(DOMAINS_JSON)
            .create();
        let expected_body = json!({
            "host": "_sip._tcp",
            "type": "SRV",
            "data": "sip.example.com",
            "ttl": 3600,
            "priority": 10,
            "weight": 20,
            "port": 5060
        });
        let create_mock = server
            .mock("POST", "/domains/42/dns")
            .match_body(mockito::Matcher::Json(expected_body))
            .with_status(201)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "_sip._tcp.example.com",
                DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 20,
                    port: 5060,
                    target: "sip.example.com".to_string(),
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domains_mock.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn test_create_caa_record() {
        let mut server = mockito::Server::new_async().await;
        let domains_mock = server
            .mock("GET", "/domains")
            .with_status(200)
            .with_body(DOMAINS_JSON)
            .create();
        let expected_body = json!({
            "host": "@",
            "type": "CAA",
            "data": "letsencrypt.org",
            "ttl": 3600,
            "flags": 0,
            "tag": "issue"
        });
        let create_mock = server
            .mock("POST", "/domains/42/dns")
            .match_body(mockito::Matcher::Json(expected_body))
            .with_status(201)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "example.com",
                DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".to_string()),
                    options: vec![],
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domains_mock.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn test_update_record() {
        let mut server = mockito::Server::new_async().await;
        let domains_mock = server
            .mock("GET", "/domains")
            .with_status(200)
            .with_body(DOMAINS_JSON)
            .expect(1)
            .create();
        let records_mock = server
            .mock("GET", "/domains/42/dns")
            .with_status(200)
            .with_body(r#"[{"id": 7, "host": "www", "type": "A"}]"#)
            .create();
        let expected_body = json!({
            "host": "www",
            "type": "A",
            "data": "5.6.7.8",
            "ttl": 600
        });
        let update_mock = server
            .mock("PUT", "/domains/42/dns/7")
            .match_body(mockito::Matcher::Json(expected_body))
            .with_status(204)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "www.example.com",
                DnsRecord::A("5.6.7.8".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domains_mock.assert();
        records_mock.assert();
        update_mock.assert();
    }

    #[tokio::test]
    async fn test_delete_record() {
        let mut server = mockito::Server::new_async().await;
        let domains_mock = server
            .mock("GET", "/domains")
            .with_status(200)
            .with_body(DOMAINS_JSON)
            .create();
        let records_mock = server
            .mock("GET", "/domains/42/dns")
            .with_status(200)
            .with_body(r#"[{"id": 9, "host": "www", "type": "TXT"}]"#)
            .create();
        let delete_mock = server
            .mock("DELETE", "/domains/42/dns/9")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("www.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domains_mock.assert();
        records_mock.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_lookup() {
        let mut server = mockito::Server::new_async().await;
        let domains_mock = server
            .mock("GET", "/domains")
            .with_status(401)
            .with_body(r#"{"message":"invalid credentials"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Unauthorized)), "{:?}", result);
        domains_mock.assert();
    }

    #[tokio::test]
    async fn test_tlsa_unsupported() {
        let mut server = mockito::Server::new_async().await;
        let _ = server
            .mock("GET", "/domains")
            .with_status(200)
            .with_body(DOMAINS_JSON)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "tls.example.com",
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xab, 0xcd],
                }),
                3600,
                "example.com",
            )
            .await;

        match result {
            Err(Error::Api(msg)) => assert!(msg.contains("TLSA")),
            other => panic!("expected Error::Api, got {:?}", other),
        }
    }

    #[tokio::test]
    #[ignore = "Requires Domeneshop API credentials"]
    async fn integration_test() {
        let token = "";
        let secret = "";
        let origin = "";
        let name = "";

        assert!(!token.is_empty(), "Set DOMENESHOP_API_TOKEN");
        assert!(!secret.is_empty(), "Set DOMENESHOP_API_SECRET");
        assert!(!origin.is_empty(), "Set origin");
        assert!(!name.is_empty(), "Set name");

        let provider = DomeneshopProvider::new(token, secret, Some(Duration::from_secs(30)));
        assert!(
            provider
                .create(name, DnsRecord::A("1.1.1.1".parse().unwrap()), 3600, origin)
                .await
                .is_ok()
        );
        assert!(
            provider
                .update(name, DnsRecord::A("2.2.2.2".parse().unwrap()), 3600, origin)
                .await
                .is_ok()
        );
        assert!(
            provider
                .delete(name, origin, DnsRecordType::A)
                .await
                .is_ok()
        );
    }
}
