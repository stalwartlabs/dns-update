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
        DnsRecord, DnsRecordType, DnsUpdater, Error,
        providers::tencentcloud::TencentCloudProvider,
    };
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> TencentCloudProvider {
        TencentCloudProvider::new(
            "test_secret_id",
            "test_secret_key",
            None::<&str>,
            None::<&str>,
            Some(Duration::from_secs(5)),
        )
        .unwrap()
        .with_endpoint(endpoint)
    }

    const DOMAIN_LIST_BODY: &str = r#"{
        "Response": {
            "DomainList": [
                {"DomainId": 12345, "Name": "example.com", "Punycode": "example.com"}
            ],
            "DomainCountInfo": {"AllTotal": 1}
        }
    }"#;

    const EMPTY_OK_BODY: &str = r#"{"Response":{"RequestId":"x"}}"#;

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_tencentcloud(
            "test_secret_id",
            "test_secret_key",
            None::<&str>,
            None::<&str>,
            Some(Duration::from_secs(30)),
        );
        assert!(matches!(updater, Ok(DnsUpdater::TencentCloud(..))));
    }

    #[tokio::test]
    async fn create_record_success() {
        let mut server = mockito::Server::new_async().await;

        let list_mock = server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DescribeDomainList")
            .with_status(200)
            .with_body(DOMAIN_LIST_BODY)
            .create();

        let create_mock = server
            .mock("POST", "/")
            .match_header("X-TC-Action", "CreateRecord")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"Domain":"example.com","SubDomain":"test","RecordType":"A","Value":"1.1.1.1","TTL":3600}"#
                    .to_string(),
            ))
            .with_status(200)
            .with_body(EMPTY_OK_BODY)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create failed: {result:?}");
        list_mock.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn update_record_success() {
        let mut server = mockito::Server::new_async().await;

        server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DescribeDomainList")
            .with_status(200)
            .with_body(DOMAIN_LIST_BODY)
            .create();

        server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DescribeRecordList")
            .with_status(200)
            .with_body(
                r#"{"Response":{"RecordList":[{"RecordId":7777,"Name":"www","Type":"AAAA"}]}}"#,
            )
            .create();

        let modify_mock = server
            .mock("POST", "/")
            .match_header("X-TC-Action", "ModifyRecord")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"Domain":"example.com","RecordId":7777,"SubDomain":"www","RecordType":"AAAA","Value":"2001:db8::2","TTL":3600}"#
                    .to_string(),
            ))
            .with_status(200)
            .with_body(EMPTY_OK_BODY)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "www.example.com",
                DnsRecord::AAAA("2001:db8::2".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update failed: {result:?}");
        modify_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DescribeDomainList")
            .with_status(200)
            .with_body(DOMAIN_LIST_BODY)
            .create();

        server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DescribeRecordList")
            .with_status(200)
            .with_body(
                r#"{"Response":{"RecordList":[{"RecordId":7777,"Name":"www","Type":"TXT"}]}}"#,
            )
            .create();

        let delete_mock = server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DeleteRecord")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"Domain":"example.com","RecordId":7777}"#.to_string(),
            ))
            .with_status(200)
            .with_body(EMPTY_OK_BODY)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("www.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete failed: {result:?}");
        delete_mock.assert();
    }

    #[tokio::test]
    async fn create_record_api_error() {
        let mut server = mockito::Server::new_async().await;

        server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DescribeDomainList")
            .with_status(200)
            .with_body(DOMAIN_LIST_BODY)
            .create();

        server
            .mock("POST", "/")
            .match_header("X-TC-Action", "CreateRecord")
            .with_status(200)
            .with_body(
                r#"{"Response":{"Error":{"Code":"InvalidParameter","Message":"bad input"}}}"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(_))));
    }

    #[tokio::test]
    async fn tlsa_record_unsupported() {
        let mut server = mockito::Server::new_async().await;

        server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DescribeDomainList")
            .with_status(200)
            .with_body(DOMAIN_LIST_BODY)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "_443._tcp.example.com",
                DnsRecord::TLSA(crate::TLSARecord {
                    cert_usage: crate::TlsaCertUsage::DaneEe,
                    selector: crate::TlsaSelector::Spki,
                    matching: crate::TlsaMatching::Sha256,
                    cert_data: vec![1, 2, 3, 4],
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(msg)) if msg.contains("TLSA")));
    }

    #[tokio::test]
    #[ignore = "Requires TENCENTCLOUD_SECRET_ID, TENCENTCLOUD_SECRET_KEY, and an origin/fqdn"]
    async fn integration_test() {
        let secret_id = std::env::var("TENCENTCLOUD_SECRET_ID").unwrap_or_default();
        let secret_key = std::env::var("TENCENTCLOUD_SECRET_KEY").unwrap_or_default();
        let origin = std::env::var("TENCENTCLOUD_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("TENCENTCLOUD_FQDN").unwrap_or_default();
        assert!(!secret_id.is_empty());
        assert!(!secret_key.is_empty());
        assert!(!origin.is_empty());
        assert!(!fqdn.is_empty());

        let updater = DnsUpdater::new_tencentcloud(
            secret_id,
            secret_key,
            None::<&str>,
            None::<&str>,
            Some(Duration::from_secs(30)),
        )
        .unwrap();

        let create_result = updater
            .create(&fqdn, DnsRecord::A("1.1.1.1".parse().unwrap()), 600, &origin)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");

        let update_result = updater
            .update(&fqdn, DnsRecord::A("8.8.8.8".parse().unwrap()), 600, &origin)
            .await;
        assert!(update_result.is_ok(), "update failed: {update_result:?}");

        let delete_result = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
