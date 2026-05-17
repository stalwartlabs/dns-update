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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::alidns::AlidnsProvider,
    };
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> AlidnsProvider {
        AlidnsProvider::new(
            "test_access_key",
            "test_secret_key",
            None::<&str>,
            None::<&str>,
            None::<&str>,
            Some(Duration::from_secs(5)),
        )
        .unwrap()
        .with_endpoint(endpoint)
    }

    const DESCRIBE_DOMAINS_BODY: &str = r#"{
        "TotalCount": 1,
        "PageNumber": 1,
        "PageSize": 100,
        "Domains": {
            "Domain": [
                {"DomainName": "example.com", "PunyCode": "example.com"}
            ]
        }
    }"#;

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_alidns(
            "test_access_key",
            "test_secret_key",
            None::<&str>,
            None::<&str>,
            None::<&str>,
            Some(Duration::from_secs(30)),
        );
        assert!(matches!(updater, Ok(DnsUpdater::Alidns(..))));
    }

    #[tokio::test]
    async fn create_record_success() {
        let mut server = mockito::Server::new_async().await;

        let list_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "Action".into(),
                "DescribeDomains".into(),
            ))
            .with_status(200)
            .with_body(DESCRIBE_DOMAINS_BODY)
            .create();

        let create_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("Action".into(), "AddDomainRecord".into()),
                mockito::Matcher::UrlEncoded("DomainName".into(), "example.com".into()),
                mockito::Matcher::UrlEncoded("RR".into(), "test".into()),
                mockito::Matcher::UrlEncoded("Type".into(), "A".into()),
                mockito::Matcher::UrlEncoded("Value".into(), "1.1.1.1".into()),
                mockito::Matcher::UrlEncoded("TTL".into(), "3600".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"RecordId":"123","RequestId":"r"}"#)
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
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "Action".into(),
                "DescribeDomains".into(),
            ))
            .with_status(200)
            .with_body(DESCRIBE_DOMAINS_BODY)
            .create();

        server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "Action".into(),
                "DescribeDomainRecords".into(),
            ))
            .with_status(200)
            .with_body(
                r#"{"DomainRecords":{"Record":[{"RecordId":"42","RR":"www","Type":"AAAA"}]}}"#,
            )
            .create();

        let update_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("Action".into(), "UpdateDomainRecord".into()),
                mockito::Matcher::UrlEncoded("RecordId".into(), "42".into()),
                mockito::Matcher::UrlEncoded("RR".into(), "www".into()),
                mockito::Matcher::UrlEncoded("Type".into(), "AAAA".into()),
                mockito::Matcher::UrlEncoded("Value".into(), "2001:db8::2".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"RecordId":"42","RequestId":"r"}"#)
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
        update_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "Action".into(),
                "DescribeDomains".into(),
            ))
            .with_status(200)
            .with_body(DESCRIBE_DOMAINS_BODY)
            .create();

        server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "Action".into(),
                "DescribeDomainRecords".into(),
            ))
            .with_status(200)
            .with_body(
                r#"{"DomainRecords":{"Record":[{"RecordId":"99","RR":"old","Type":"TXT"}]}}"#,
            )
            .create();

        let delete_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("Action".into(), "DeleteDomainRecord".into()),
                mockito::Matcher::UrlEncoded("RecordId".into(), "99".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"RecordId":"99","RequestId":"r"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("old.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete failed: {result:?}");
        delete_mock.assert();
    }

    #[tokio::test]
    async fn create_record_api_error() {
        let mut server = mockito::Server::new_async().await;

        server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "Action".into(),
                "DescribeDomains".into(),
            ))
            .with_status(200)
            .with_body(
                r#"{"Code":"InvalidAccessKeyId.NotFound","Message":"key not found","RequestId":"r"}"#,
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
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "Action".into(),
                "DescribeDomains".into(),
            ))
            .with_status(200)
            .with_body(DESCRIBE_DOMAINS_BODY)
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
    #[ignore = "Requires ALICLOUD_ACCESS_KEY, ALICLOUD_SECRET_KEY, and an origin/fqdn"]
    async fn integration_test() {
        let access_key = std::env::var("ALICLOUD_ACCESS_KEY").unwrap_or_default();
        let secret_key = std::env::var("ALICLOUD_SECRET_KEY").unwrap_or_default();
        let origin = std::env::var("ALICLOUD_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("ALICLOUD_FQDN").unwrap_or_default();
        assert!(!access_key.is_empty());
        assert!(!secret_key.is_empty());
        assert!(!origin.is_empty());
        assert!(!fqdn.is_empty());

        let updater = DnsUpdater::new_alidns(
            access_key,
            secret_key,
            None::<&str>,
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
