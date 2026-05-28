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
    use crate::providers::oraclecloud::{OracleCloudConfig, OracleCloudProvider};
    use crate::{
        DnsRecord, DnsRecordType, Error, MXRecord, TLSARecord, TlsaCertUsage, TlsaMatching,
        TlsaSelector,
    };
    use mockito::{Matcher, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDAzjAQ8c4YC7y1\nk01bHdwfoAy6orACYHZHBsDc4rTfgzOHJ06OcOaKDD3d5Rzid3d2cgLI2lvats/0\nWAaUC4yUnytodCQbgNJcXUF/Xid46Eul8Ei1pf34QHeg7Q26kpmFoeuxMrMsYPtt\nq4A9fo8Ne4A+ne7maAYa5mOktmgqqDf/9YiZv/bEQxWya88pNvkXFL+0Ay3LCMZJ\nS0JMKu51QSHgaePohuhV3Bia3nf0RMMr9F6vF/f8ayYRu46QNR0GLFDAujRT5QCg\nw7DjOjJAOuu3JSa998PEjnREB1kMXIW2pnRlBryVCqsx1B1/7HVZvsEqjNKS0DDi\nKBE/+aSdAgMBAAECggEAWl2pWJ/ErS9/HIl0NbMKk0YEAUuz/AEzHnoTVdPp22KW\neY+aOZe/7c7sBj7WqWw98SVhmbsCV0HcuNSzDJtXIedyRGw+6icYMVNCGgzKqlgR\n8K3snjq1DLBGgYXpq9r/Got4ON6e7LttzIqXufrB2JtcUbzbFmGGDwCRjkcyDl9l\nM8ufwD/Xgcd2L8jainU43d2pVxvxUIpRlRdoupCCSlkRYPsXiWlqav7YO4F/Txos\nz3gJyzkXzc3WwfNZdQtEMYwBwozO+Dp2p4TUBr0Ta3MbfrKfDoTs4XT/Ce9IwJJS\n/h6E9cxZD8t5oMT50quFjwhHBKodMiUqIlh2YQEAbwKBgQDIULzo/tgDgTwveyEn\nL9n8yVbEh/SfrE9QtXcjkDB5+tYmIsIaz16NRWlAqnJVGZvcanrCq7ZTxgUcs/hW\nAg+sfWkeg7lmfeJAkiZ6kmi1h2qJjXMOBri+Cm6MTOsE6qdIc3eT4PnYkNpV7o6S\n70hWNncVadXLV4Thm9BLAbMbQwKBgQD2ZwKe/2zRQcbuBe1loF0HWIsJPxcKQ3LH\nhVf7f0YLQlIuzOhK8TQXgM0G4hxLlk1XeLjgf3z4Ju7hfh2JQLor1QYPRGUj66SX\nKTE5eDwE0yEX1c9m5PW6M+f8vkOU4LQ/OtPw5OrKyYxpLf9dp42nmDYY/8IvUk96\niKZNY1sSnwKBgQC27tS2SxVmjf0yt1WdfdurOQueSzKhJzD/2djFh4Zdvy8WgKOW\n7E3C4eKvBXmIMezeq/cUFNBbTPmaLtjZYuSBd74p+c20xb17jnzJby9kqBgpKh4q\nbwUDuG8gfZYbVVgTmC9ZwxkoJ5Dc7RETKqZ65R53VcHDA1f82Nitxw2UFQKBgBDl\nc2qPvViEGC4OPf8wBfERA0e5Cc1sXpyL6kKWsajn/Va0OmGZNKc/788/Bg2w2tDa\nuGK8m0cw9ESGL2RQCfQjgWzelcjmybyL2JJGSmdSSvylbrlxjeAc2xWbvmqhFfsX\n/5yPNgJ926ECxHYZnT8W0u7X6urvy/9tC2pXG9GlAoGBAKOAfij4fMbHY+Z1m825\nVhY110FDnePYFJWmExP8GAVqOzhCs0mzyCnYh6nvS/OY8moH2LOuwPUlDfF3IzyT\nhTUuXnykWT3w40eYQXXIaXEGhue+guL8ch16vEEJy5ltwEdIPNMTErbqAAk2W6Ps\nNB46HzETzEIWnzoamX6iQVWj\n-----END PRIVATE KEY-----\n";

    fn config() -> OracleCloudConfig {
        OracleCloudConfig {
            tenancy_ocid: "ocid1.tenancy.oc1..tenancy".to_string(),
            user_ocid: "ocid1.user.oc1..user".to_string(),
            fingerprint: "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99".to_string(),
            private_key_pem: TEST_PRIVATE_KEY.to_string(),
            private_key_password: None,
            region: "us-phoenix-1".to_string(),
            compartment_ocid: "ocid1.compartment.oc1..compartment".to_string(),
            request_timeout: Some(Duration::from_secs(5)),
        }
    }

    fn setup_provider(endpoint: &str) -> OracleCloudProvider {
        OracleCloudProvider::new(config())
            .expect("provider must build")
            .with_endpoint(endpoint)
    }

    fn mock_zone(server: &mut ServerGuard, zone_name: &str, zone_id: &str) -> mockito::Mock {
        server
            .mock("GET", "/20180115/zones")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), zone_name.into()),
                Matcher::UrlEncoded(
                    "compartmentId".into(),
                    "ocid1.compartment.oc1..compartment".into(),
                ),
            ]))
            .match_header(
                "authorization",
                Matcher::Regex(r#"Signature .*algorithm="rsa-sha256""#.into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!([{"id": zone_id, "name": zone_name}]).to_string())
            .create()
    }

    #[test]
    fn provider_rejects_password_protected_keys() {
        let mut cfg = config();
        cfg.private_key_password = Some("secret".to_string());
        match OracleCloudProvider::new(cfg) {
            Err(Error::Unsupported(msg)) => assert!(msg.contains("passphrase")),
            Err(other) => panic!("expected Unsupported error, got {:?}", other),
            Ok(_) => panic!("expected error"),
        }
    }

    #[tokio::test]
    async fn set_rrset_empty_deletes_rrset() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone(&mut server, "example.com", "zone-id");

        let del = server
            .mock(
                "DELETE",
                Matcher::Regex(r"/20180115/zones/zone-id/records/www\.example\.com/A".into()),
            )
            .with_status(204)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {:?}", result);
        del.assert_async().await;
    }

    #[tokio::test]
    async fn set_rrset_empty_treats_404_as_success() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone(&mut server, "example.com", "zone-id");

        let del = server
            .mock(
                "DELETE",
                Matcher::Regex(r"/20180115/zones/zone-id/records/missing\.example\.com/A".into()),
            )
            .with_status(404)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "missing.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {:?}", result);
        del.assert_async().await;
    }

    #[tokio::test]
    async fn set_rrset_with_records_puts_all() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone(&mut server, "example.com", "zone-id");

        let put = server
            .mock(
                "PUT",
                Matcher::Regex(r"/20180115/zones/zone-id/records/api\.example\.com/A".into()),
            )
            .match_body(Matcher::PartialJsonString(
                json!({
                    "items": [
                        {"domain": "api.example.com", "rtype": "A", "rdata": "10.0.0.1", "ttl": 300},
                        {"domain": "api.example.com", "rtype": "A", "rdata": "10.0.0.2", "ttl": 300}
                    ]
                })
                .to_string(),
            ))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "api.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("10.0.0.1".parse().unwrap()),
                    DnsRecord::A("10.0.0.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {:?}", result);
        put.assert_async().await;
    }

    #[tokio::test]
    async fn add_to_rrset_uses_patch_add() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone(&mut server, "example.com", "zone-id");

        let get = server
            .mock(
                "GET",
                Matcher::Regex(r"/20180115/zones/zone-id/records/api\.example\.com/A".into()),
            )
            .with_status(200)
            .with_body(json!({"items": []}).to_string())
            .create_async()
            .await;

        let patch = server
            .mock(
                "PATCH",
                Matcher::Regex(r"/20180115/zones/zone-id/records/api\.example\.com/A".into()),
            )
            .match_body(Matcher::PartialJsonString(
                json!({
                    "items": [
                        {"operation": "ADD", "rdata": "10.0.0.3", "ttl": 600},
                        {"operation": "ADD", "rdata": "10.0.0.4", "ttl": 600}
                    ]
                })
                .to_string(),
            ))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "api.example.com",
                DnsRecordType::A,
                600,
                vec![
                    DnsRecord::A("10.0.0.3".parse().unwrap()),
                    DnsRecord::A("10.0.0.4".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {:?}", result);
        get.assert_async().await;
        patch.assert_async().await;
    }

    #[tokio::test]
    async fn add_to_rrset_empty_is_noop() {
        let provider = setup_provider("http://does-not-exist.invalid");
        let result = provider
            .add_to_rrset(
                "api.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {:?}", result);
    }

    #[tokio::test]
    async fn remove_from_rrset_uses_patch_remove() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone(&mut server, "example.com", "zone-id");

        let patch = server
            .mock(
                "PATCH",
                Matcher::Regex(r"/20180115/zones/zone-id/records/api\.example\.com/A".into()),
            )
            .match_body(Matcher::PartialJsonString(
                json!({
                    "items": [
                        {"operation": "REMOVE", "rdata": "10.0.0.3"}
                    ]
                })
                .to_string(),
            ))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "api.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("10.0.0.3".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {:?}", result);
        patch.assert_async().await;
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_is_noop() {
        let provider = setup_provider("http://does-not-exist.invalid");
        let result = provider
            .remove_from_rrset(
                "api.example.com",
                DnsRecordType::A,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {:?}", result);
    }

    #[tokio::test]
    async fn remove_from_rrset_404_is_success() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone(&mut server, "example.com", "zone-id");

        let _patch = server
            .mock(
                "PATCH",
                Matcher::Regex(r"/20180115/zones/zone-id/records/api\.example\.com/A".into()),
            )
            .with_status(404)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "api.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("10.0.0.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {:?}", result);
    }

    #[tokio::test]
    async fn rrset_methods_reject_type_mismatch() {
        let provider = setup_provider("http://does-not-exist.invalid");
        let result = provider
            .set_rrset(
                "api.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("oops".into())],
                "example.com",
            )
            .await;
        match result {
            Err(Error::Api(msg)) => assert!(msg.contains("type mismatch")),
            other => panic!("expected Api error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn tlsa_record_now_supported_via_set_rrset() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone(&mut server, "example.com", "zone-id");

        let put = server
            .mock(
                "PUT",
                Matcher::Regex(r"/20180115/zones/zone-id/records/mail\.example\.com/TLSA".into()),
            )
            .match_body(Matcher::PartialJsonString(
                json!({
                    "items": [{
                        "domain": "mail.example.com",
                        "rtype": "TLSA",
                        "rdata": "1 1 1 abcd",
                        "ttl": 300
                    }]
                })
                .to_string(),
            ))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let tlsa = DnsRecord::TLSA(TLSARecord {
            cert_usage: TlsaCertUsage::PkixEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            cert_data: vec![0xab, 0xcd],
        });
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![tlsa],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "expected ok, got {:?}", result);
        put.assert_async().await;
    }

    #[tokio::test]
    async fn list_rrset_parses_records() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone(&mut server, "example.com", "zone-id");

        let _list = server
            .mock(
                "GET",
                Matcher::Regex(r"/20180115/zones/zone-id/records/api\.example\.com/A".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "items": [
                        {"domain": "api.example.com", "rtype": "A", "rdata": "10.0.0.1", "ttl": 300},
                        {"domain": "api.example.com", "rtype": "A", "rdata": "10.0.0.2", "ttl": 300}
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("api.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset must succeed");
        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("10.0.0.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("10.0.0.2".parse().unwrap())));
    }

    #[tokio::test]
    async fn list_rrset_handles_pagination() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone(&mut server, "example.com", "zone-id");

        let _page1 = server
            .mock(
                "GET",
                Matcher::Regex(r"/20180115/zones/zone-id/records/api\.example\.com/A".into()),
            )
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("limit".into(), "1000".into()),
                Matcher::UrlEncoded(
                    "compartmentId".into(),
                    "ocid1.compartment.oc1..compartment".into(),
                ),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_header("opc-next-page", "cursor-2")
            .with_body(
                json!({
                    "items": [
                        {"domain": "api.example.com", "rtype": "A", "rdata": "10.0.0.1", "ttl": 300}
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let _page2 = server
            .mock(
                "GET",
                Matcher::Regex(r"/20180115/zones/zone-id/records/api\.example\.com/A".into()),
            )
            .match_query(Matcher::UrlEncoded("page".into(), "cursor-2".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "items": [
                        {"domain": "api.example.com", "rtype": "A", "rdata": "10.0.0.2", "ttl": 300}
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("api.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset must succeed");
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn list_rrset_returns_empty_on_404() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone(&mut server, "example.com", "zone-id");

        let _list = server
            .mock(
                "GET",
                Matcher::Regex(r"/20180115/zones/zone-id/records/missing\.example\.com/A".into()),
            )
            .with_status(404)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("missing.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset must succeed");
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn list_rrset_filters_cross_type() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone(&mut server, "example.com", "zone-id");

        let _list = server
            .mock(
                "GET",
                Matcher::Regex(r"/20180115/zones/zone-id/records/api\.example\.com/A".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "items": [
                        {"domain": "api.example.com", "rtype": "A", "rdata": "10.0.0.1", "ttl": 300},
                        {"domain": "api.example.com", "rtype": "TXT", "rdata": "\"foo\"", "ttl": 300}
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("api.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset must succeed");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], DnsRecord::A("10.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn list_rrset_parses_mx() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone(&mut server, "example.com", "zone-id");

        let _list = server
            .mock(
                "GET",
                Matcher::Regex(r"/20180115/zones/zone-id/records/example\.com/MX".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "items": [
                        {"domain": "example.com", "rtype": "MX", "rdata": "10 mx1.example.com.", "ttl": 300}
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .expect("list_rrset must succeed");
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            DnsRecord::MX(MXRecord {
                priority: 10,
                exchange: "mx1.example.com".to_string(),
            })
        );
    }

    #[tokio::test]
    async fn list_rrset_parses_tlsa() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone(&mut server, "example.com", "zone-id");

        let _list = server
            .mock(
                "GET",
                Matcher::Regex(r"/20180115/zones/zone-id/records/mail\.example\.com/TLSA".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "items": [
                        {"domain": "mail.example.com", "rtype": "TLSA", "rdata": "3 1 1 abcdef", "ttl": 300}
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("mail.example.com", DnsRecordType::TLSA, "example.com")
            .await
            .expect("list_rrset must succeed");
        assert_eq!(result.len(), 1);
        match &result[0] {
            DnsRecord::TLSA(t) => {
                assert!(matches!(t.cert_usage, TlsaCertUsage::DaneEe));
                assert!(matches!(t.selector, TlsaSelector::Spki));
                assert!(matches!(t.matching, TlsaMatching::Sha256));
                assert_eq!(t.cert_data, vec![0xab, 0xcd, 0xef]);
            }
            other => panic!("expected TLSA, got {:?}", other),
        }
    }

    #[tokio::test]
    #[ignore = "Requires real Oracle Cloud Infrastructure credentials"]
    async fn integration_smoke() {
        let cfg = OracleCloudConfig {
            tenancy_ocid: std::env::var("OCI_TENANCY_OCID").unwrap_or_default(),
            user_ocid: std::env::var("OCI_USER_OCID").unwrap_or_default(),
            fingerprint: std::env::var("OCI_FINGERPRINT").unwrap_or_default(),
            private_key_pem: std::env::var("OCI_PRIVATE_KEY_PEM").unwrap_or_default(),
            private_key_password: None,
            region: std::env::var("OCI_REGION").unwrap_or_default(),
            compartment_ocid: std::env::var("OCI_COMPARTMENT_OCID").unwrap_or_default(),
            request_timeout: Some(Duration::from_secs(30)),
        };
        let provider = OracleCloudProvider::new(cfg).expect("provider must build");
        let zone = std::env::var("OCI_TEST_ZONE").expect("OCI_TEST_ZONE");
        let host = format!("smoketest.{}", zone);
        provider
            .set_rrset(
                &host,
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("203.0.113.1".parse().unwrap())],
                &zone,
            )
            .await
            .expect("set_rrset");
        provider
            .set_rrset(&host, DnsRecordType::A, 300, Vec::new(), &zone)
            .await
            .expect("delete via empty set_rrset");
    }
}
