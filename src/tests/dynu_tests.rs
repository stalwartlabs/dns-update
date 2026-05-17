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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::dynu::DynuProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const DOMAIN_ID: i64 = 9007481;
    const RECORD_ID: i64 = 6041417;

    fn setup_provider(endpoint: String) -> DynuProvider {
        DynuProvider::new("test_key", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn mock_get_root(server: &mut ServerGuard, hostname: &str, domain_name: &str) -> Mock {
        server
            .mock("GET", format!("/dns/getroot/{hostname}").as_str())
            .match_header("api-key", "test_key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"statusCode":200,"id":{DOMAIN_ID},"domainName":"{domain_name}","hostname":"{hostname}","node":"sub"}}"#
            ))
            .create()
    }

    fn mock_get_records(
        server: &mut ServerGuard,
        hostname: &str,
        record_type: &str,
        records: serde_json::Value,
    ) -> Mock {
        server
            .mock("GET", format!("/dns/record/{hostname}").as_str())
            .match_query(Matcher::UrlEncoded(
                "recordType".into(),
                record_type.into(),
            ))
            .match_header("api-key", "test_key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(records.to_string())
            .create()
    }

    #[tokio::test]
    async fn test_create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "host.example.com", "example.com");
        let create = server
            .mock("POST", format!("/dns/{DOMAIN_ID}/record").as_str())
            .match_header("api-key", "test_key")
            .match_header("content-type", "application/json")
            .match_body(Matcher::Json(json!({
                "recordType": "TXT",
                "domainName": "example.com",
                "nodeName": "host",
                "hostname": "host.example.com",
                "state": true,
                "ttl": 300,
                "textData": "challenge",
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"statusCode":200}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "host.example.com",
                DnsRecord::TXT("challenge".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        root.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "host.example.com", "example.com");
        let create = server
            .mock("POST", format!("/dns/{DOMAIN_ID}/record").as_str())
            .match_body(Matcher::Json(json!({
                "recordType": "A",
                "domainName": "example.com",
                "nodeName": "host",
                "hostname": "host.example.com",
                "state": true,
                "ttl": 300,
                "ipv4Address": "1.2.3.4",
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"statusCode":200}"#)
            .create();
        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "host.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        root.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_delete_resolves_record_id_and_deletes() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "host.example.com", "example.com");
        let records = mock_get_records(
            &mut server,
            "host.example.com",
            "TXT",
            json!({
                "statusCode": 200,
                "dnsRecords": [
                    {
                        "id": RECORD_ID,
                        "recordType": "TXT",
                        "hostname": "host.example.com",
                        "textData": "value"
                    }
                ]
            }),
        );
        let delete = server
            .mock(
                "DELETE",
                format!("/dns/{DOMAIN_ID}/record/{RECORD_ID}").as_str(),
            )
            .match_header("api-key", "test_key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"statusCode":200}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("host.example.com", "example.com", DnsRecordType::TXT)
            .await;
        assert!(result.is_ok(), "delete returned: {result:?}");
        root.assert();
        records.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_delete_returns_error_when_record_missing() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "missing.example.com", "example.com");
        let records = mock_get_records(
            &mut server,
            "missing.example.com",
            "TXT",
            json!({"statusCode": 200, "dnsRecords": []}),
        );
        let provider = setup_provider(server.url());
        let result = provider
            .delete("missing.example.com", "example.com", DnsRecordType::TXT)
            .await;
        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
        root.assert();
        records.assert();
    }

    #[tokio::test]
    async fn test_tlsa_record_rejected() {
        let provider = DynuProvider::new("test_key", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .create(
                "host.example.com",
                DnsRecord::TLSA(crate::TLSARecord {
                    cert_usage: crate::TlsaCertUsage::DaneEe,
                    selector: crate::TlsaSelector::Spki,
                    matching: crate::TlsaMatching::Sha256,
                    cert_data: vec![0; 32],
                }),
                300,
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
    }

    #[tokio::test]
    #[ignore = "Requires DYNU_API_KEY, DYNU_ORIGIN, DYNU_FQDN env vars"]
    async fn integration_test() {
        let key = std::env::var("DYNU_API_KEY").unwrap_or_default();
        let origin = std::env::var("DYNU_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("DYNU_FQDN").unwrap_or_default();
        assert!(!key.is_empty(), "Set DYNU_API_KEY");
        assert!(!origin.is_empty(), "Set DYNU_ORIGIN");
        assert!(!fqdn.is_empty(), "Set DYNU_FQDN");

        let updater = DnsUpdater::new_dynu(key, Some(Duration::from_secs(30))).unwrap();
        let create_result = updater
            .create(&fqdn, DnsRecord::TXT("test".into()), 300, &origin)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");
        let delete_result = updater.delete(&fqdn, &origin, DnsRecordType::TXT).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
