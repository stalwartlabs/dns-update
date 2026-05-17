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
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, Error, providers::ionos::IonosProvider};
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> IonosProvider {
        IonosProvider::new("test_key", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let zones = server
            .mock("GET", "/v1/zones")
            .match_header("x-api-key", "test_key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":"zone-1","name":"example.com","type":"NATIVE"}]"#)
            .create();

        let create = server
            .mock("POST", "/v1/zones/zone-1/records")
            .match_header("x-api-key", "test_key")
            .match_body(Matcher::Json(json!([{
                "name": "test.example.com",
                "content": "1.2.3.4",
                "ttl": 3600,
                "type": "A",
            }])))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        zones.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_update_resolves_record_id() {
        let mut server = mockito::Server::new_async().await;
        let zones = server
            .mock("GET", "/v1/zones")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":"zone-1","name":"example.com","type":"NATIVE"}]"#)
            .create();

        let lookup = server
            .mock("GET", "/v1/zones/zone-1")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "test.example.com".into()),
                Matcher::UrlEncoded("recordType".into(), "A".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"zone-1","name":"example.com","records":[{"id":"rec-1","name":"test.example.com","content":"1.2.3.4","ttl":300,"type":"A"}]}"#,
            )
            .create();

        let put = server
            .mock("PUT", "/v1/zones/zone-1/records/rec-1")
            .match_body(Matcher::Json(json!({
                "name": "test.example.com",
                "content": "5.6.7.8",
                "ttl": 600,
                "type": "A",
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("5.6.7.8".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update returned: {result:?}");
        zones.assert();
        lookup.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_delete_resolves_record_id() {
        let mut server = mockito::Server::new_async().await;
        let zones = server
            .mock("GET", "/v1/zones")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":"zone-1","name":"example.com","type":"NATIVE"}]"#)
            .create();

        let lookup = server
            .mock("GET", "/v1/zones/zone-1")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "test.example.com".into()),
                Matcher::UrlEncoded("recordType".into(), "TXT".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"zone-1","name":"example.com","records":[{"id":"rec-2","name":"test.example.com","content":"\"abc\"","ttl":300,"type":"TXT"}]}"#,
            )
            .create();

        let delete = server
            .mock("DELETE", "/v1/zones/zone-1/records/rec-2")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete returned: {result:?}");
        zones.assert();
        lookup.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_update_returns_error_when_record_missing() {
        let mut server = mockito::Server::new_async().await;
        let _zones = server
            .mock("GET", "/v1/zones")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":"zone-1","name":"example.com","type":"NATIVE"}]"#)
            .create();
        let _lookup = server
            .mock("GET", "/v1/zones/zone-1")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"zone-1","name":"example.com","records":[]}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "missing.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_tlsa_unsupported() {
        let mut server = mockito::Server::new_async().await;
        let _zones = server
            .mock("GET", "/v1/zones")
            .with_status(200)
            .with_body(r#"[{"id":"zone-1","name":"example.com","type":"NATIVE"}]"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "_443._tcp.example.com",
                DnsRecord::TLSA(crate::TLSARecord {
                    cert_usage: crate::TlsaCertUsage::DaneEe,
                    selector: crate::TlsaSelector::Spki,
                    matching: crate::TlsaMatching::Sha256,
                    cert_data: vec![0, 1, 2],
                }),
                300,
                "example.com",
            )
            .await;

        assert!(
            matches!(&result, Err(Error::Api(msg)) if msg.contains("TLSA")),
            "got {result:?}"
        );
    }

    #[tokio::test]
    #[ignore = "Requires IONOS_API_KEY, IONOS_ORIGIN, IONOS_FQDN env vars"]
    async fn integration_test() {
        let api_key = std::env::var("IONOS_API_KEY").unwrap_or_default();
        let origin = std::env::var("IONOS_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("IONOS_FQDN").unwrap_or_default();
        assert!(!api_key.is_empty(), "Set IONOS_API_KEY");
        assert!(!origin.is_empty(), "Set IONOS_ORIGIN");
        assert!(!fqdn.is_empty(), "Set IONOS_FQDN");

        let updater =
            DnsUpdater::new_ionos(api_key, Some(Duration::from_secs(30))).unwrap();
        let create_result = updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 300, &origin)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");

        let update_result = updater
            .update(&fqdn, DnsRecord::A([8, 8, 8, 8].into()), 300, &origin)
            .await;
        assert!(update_result.is_ok(), "update failed: {update_result:?}");

        let delete_result = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
