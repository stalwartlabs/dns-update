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
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, Error, TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector};
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

    #[test]
    fn provider_rejects_password_protected_keys() {
        let mut cfg = config();
        cfg.private_key_password = Some("secret".to_string());
        match OracleCloudProvider::new(cfg) {
            Err(Error::Api(msg)) => assert!(msg.contains("passphrase")),
            Err(other) => panic!("expected Api error, got {:?}", other),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn dns_updater_creation_succeeds() {
        let updater = DnsUpdater::new_oraclecloud(config()).expect("must construct");
        assert!(matches!(updater, DnsUpdater::OracleCloud(_)));
    }

    #[tokio::test]
    async fn create_record_signs_and_sends() {
        let mut server = mockito::Server::new_async().await;
        let zones_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "example.com".into()),
            ]))
            .match_header("authorization", mockito::Matcher::Regex("Signature .*keyId=.*algorithm=\"rsa-sha256\"".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!([{"id": "ocid1.zone.oc1..zone1", "name": "example.com"}]).to_string())
            .create_async()
            .await;

        let get_records_mock = server
            .mock("GET", mockito::Matcher::Regex(r"/20180115/zones/.*/records/test\.example\.com/A".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({"items": []}).to_string())
            .create_async()
            .await;

        let put_mock = server
            .mock("PUT", mockito::Matcher::Regex(r"/20180115/zones/.*/records/test\.example\.com/A".into()))
            .match_header("authorization", mockito::Matcher::Regex("Signature .*algorithm=\"rsa-sha256\"".into()))
            .match_header("x-content-sha256", mockito::Matcher::Any)
            .match_header("content-type", "application/json")
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        zones_mock.assert_async().await;
        get_records_mock.assert_async().await;
        put_mock.assert_async().await;
    }

    #[tokio::test]
    async fn update_record_puts_to_records_endpoint() {
        let mut server = mockito::Server::new_async().await;
        let _zones = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "name".into(),
                "example.com".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!([{"id": "zone-id", "name": "example.com"}]).to_string())
            .create_async()
            .await;

        let put_mock = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(
                    r"/20180115/zones/zone-id/records/host\.example\.com/TXT".into(),
                ),
            )
            .match_body(mockito::Matcher::PartialJsonString(
                json!({
                    "items": [{
                        "domain": "host.example.com",
                        "rtype": "TXT",
                        "rdata": "\"hello\"",
                        "ttl": 60
                    }]
                })
                .to_string(),
            ))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "host.example.com",
                DnsRecord::TXT("hello".into()),
                60,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "expected ok, got {:?}", result);
        put_mock.assert_async().await;
    }

    #[tokio::test]
    async fn delete_record_sends_delete_to_records_endpoint() {
        let mut server = mockito::Server::new_async().await;
        let _zones = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "name".into(),
                "example.com".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!([{"id": "zone-id", "name": "example.com"}]).to_string())
            .create_async()
            .await;

        let del = server
            .mock(
                "DELETE",
                mockito::Matcher::Regex(
                    r"/20180115/zones/zone-id/records/host\.example\.com/A".into(),
                ),
            )
            .with_status(204)
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("host.example.com", "example.com", DnsRecordType::A)
            .await;
        assert!(result.is_ok(), "expected ok, got {:?}", result);
        del.assert_async().await;
    }

    #[tokio::test]
    async fn tlsa_records_rejected() {
        let provider = OracleCloudProvider::new(config()).expect("provider builds");
        let tlsa = DnsRecord::TLSA(TLSARecord {
            cert_usage: TlsaCertUsage::PkixEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            cert_data: vec![0xab, 0xcd],
        });
        let err = provider
            .create("host.example.com", tlsa, 60, "example.com")
            .await
            .unwrap_err();
        match err {
            Error::Api(msg) => assert!(msg.contains("TLSA")),
            other => panic!("expected Api error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn zone_not_found_returns_error() {
        let mut server = mockito::Server::new_async().await;
        let _zones = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "name".into(),
                "missing.example".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create_async()
            .await;

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "host.missing.example",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                60,
                "missing.example",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))));
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
            .create(&host, DnsRecord::A("203.0.113.1".parse().unwrap()), 300, &zone)
            .await
            .expect("create");
        provider
            .delete(&host, &zone, DnsRecordType::A)
            .await
            .expect("delete");
    }
}
