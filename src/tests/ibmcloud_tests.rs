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
    use crate::providers::ibmcloud::IbmCloudProvider;
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, Error};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> IbmCloudProvider {
        IbmCloudProvider::new("user", "key", Some(Duration::from_secs(2)))
            .expect("provider")
            .with_endpoint(endpoint)
    }

    fn basic_auth_header() -> String {
        use base64::{Engine, engine::general_purpose::STANDARD};
        format!("Basic {}", STANDARD.encode("user:key"))
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_ibmcloud("user", "key", None);
        assert!(updater.is_ok());
        assert!(matches!(updater, Ok(DnsUpdater::IbmCloud(..))));
    }

    #[tokio::test]
    async fn create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let domain_mock = server
            .mock("GET", "/SoftLayer_Dns_Domain/getByDomainName/example.com.json")
            .match_header("authorization", basic_auth_header().as_str())
            .with_status(200)
            .with_body(r#"[{"id":4711,"name":"example.com"}]"#)
            .create();
        let create_mock = server
            .mock("POST", "/SoftLayer_Dns_Domain_ResourceRecord.json")
            .match_header("authorization", basic_auth_header().as_str())
            .match_body(mockito::Matcher::Json(json!({
                "parameters": [{
                    "host": "host.example.com",
                    "ttl": 300,
                    "type": "a",
                    "domainId": 4711,
                    "data": "1.2.3.4"
                }]
            })))
            .with_status(200)
            .with_body(r#"{"id":99}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "host.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domain_mock.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn create_txt_record_falls_back_to_parent_domain() {
        let mut server = mockito::Server::new_async().await;
        let sub_lookup = server
            .mock(
                "GET",
                "/SoftLayer_Dns_Domain/getByDomainName/sub.example.com.json",
            )
            .with_status(200)
            .with_body("[]")
            .create();
        let parent_lookup = server
            .mock("GET", "/SoftLayer_Dns_Domain/getByDomainName/example.com.json")
            .with_status(200)
            .with_body(r#"[{"id":5000,"name":"example.com"}]"#)
            .create();
        let create_mock = server
            .mock("POST", "/SoftLayer_Dns_Domain_ResourceRecord.json")
            .match_body(mockito::Matcher::Json(json!({
                "parameters": [{
                    "host": "host.sub.example.com",
                    "ttl": 60,
                    "type": "txt",
                    "domainId": 5000,
                    "data": "hello"
                }]
            })))
            .with_status(200)
            .with_body(r#"{"id":11}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "host.sub.example.com",
                DnsRecord::TXT("hello".to_string()),
                60,
                "sub.example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        sub_lookup.assert();
        parent_lookup.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn update_record_success() {
        let mut server = mockito::Server::new_async().await;
        let domain_mock = server
            .mock("GET", "/SoftLayer_Dns_Domain/getByDomainName/example.com.json")
            .with_status(200)
            .with_body(r#"[{"id":4711,"name":"example.com"}]"#)
            .create();
        let list_mock = server
            .mock("GET", "/SoftLayer_Dns_Domain/4711/getResourceRecords.json")
            .with_status(200)
            .with_body(
                r#"[{"id":42,"host":"host.example.com","type":"a","data":"1.1.1.1","ttl":300}]"#,
            )
            .create();
        let update_mock = server
            .mock("PUT", "/SoftLayer_Dns_Domain_ResourceRecord/42.json")
            .match_body(mockito::Matcher::Json(json!({
                "parameters": [{
                    "id": 42,
                    "host": "host.example.com",
                    "ttl": 600,
                    "type": "a",
                    "domainId": 4711,
                    "data": "9.9.9.9"
                }]
            })))
            .with_status(200)
            .with_body(r#"true"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "host.example.com",
                DnsRecord::A("9.9.9.9".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domain_mock.assert();
        list_mock.assert();
        update_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let domain_mock = server
            .mock("GET", "/SoftLayer_Dns_Domain/getByDomainName/example.com.json")
            .with_status(200)
            .with_body(r#"[{"id":4711,"name":"example.com"}]"#)
            .create();
        let list_mock = server
            .mock("GET", "/SoftLayer_Dns_Domain/4711/getResourceRecords.json")
            .with_status(200)
            .with_body(
                r#"[{"id":71,"host":"host.example.com","type":"a","data":"1.1.1.1","ttl":300}]"#,
            )
            .create();
        let delete_mock = server
            .mock("DELETE", "/SoftLayer_Dns_Domain_ResourceRecord/71.json")
            .with_status(200)
            .with_body(r#"true"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("host.example.com", "example.com", DnsRecordType::A)
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domain_mock.assert();
        list_mock.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    async fn delete_missing_is_idempotent() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/SoftLayer_Dns_Domain/getByDomainName/example.com.json")
            .with_status(200)
            .with_body(r#"[{"id":4711,"name":"example.com"}]"#)
            .create();
        server
            .mock("GET", "/SoftLayer_Dns_Domain/4711/getResourceRecords.json")
            .with_status(200)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("missing.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "{:?}", result);
    }

    #[tokio::test]
    async fn unsupported_caa_record() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("host.example.com", "example.com", DnsRecordType::CAA)
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("not supported")),
            "got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn domain_not_found() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/SoftLayer_Dns_Domain/getByDomainName/unknown.test.json")
            .with_status(200)
            .with_body("[]")
            .expect_at_least(1)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "x.unknown.test",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "unknown.test",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(ref msg)) if msg.contains("No data found")));
    }

    #[tokio::test]
    #[ignore = "integration test requires real SoftLayer credentials"]
    async fn integration_smoke() {
        let provider = IbmCloudProvider::new(
            std::env::var("SOFTLAYER_USERNAME").unwrap_or_default(),
            std::env::var("SOFTLAYER_API_KEY").unwrap_or_default(),
            Some(Duration::from_secs(10)),
        )
        .expect("provider");
        let _ = provider
            .create(
                "smoke.example.com",
                DnsRecord::TXT("hello".to_string()),
                60,
                "example.com",
            )
            .await;
    }
}
