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
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, Error, providers::alidns::AlidnsProvider};
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

    fn mock_describe_domains(server: &mut mockito::ServerGuard) -> mockito::Mock {
        server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "Action".into(),
                "DescribeDomains".into(),
            ))
            .with_status(200)
            .with_body(DESCRIBE_DOMAINS_BODY)
            .expect_at_least(1)
            .create()
    }

    fn mock_list_records(
        server: &mut mockito::ServerGuard,
        rr: &str,
        record_type: &str,
        body: &str,
    ) -> mockito::Mock {
        server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("Action".into(), "DescribeDomainRecords".into()),
                mockito::Matcher::UrlEncoded("DomainName".into(), "example.com".into()),
                mockito::Matcher::UrlEncoded("RRKeyWord".into(), rr.into()),
                mockito::Matcher::UrlEncoded("TypeKeyWord".into(), record_type.into()),
                mockito::Matcher::UrlEncoded("SearchMode".into(), "EXACT".into()),
                mockito::Matcher::UrlEncoded("PageSize".into(), "500".into()),
            ]))
            .with_status(200)
            .with_body(body)
            .create()
    }

    #[tokio::test]
    async fn set_rrset_noop_when_current_matches_desired() {
        let mut server = mockito::Server::new_async().await;
        let _domains = mock_describe_domains(&mut server);
        let list = mock_list_records(
            &mut server,
            "www",
            "A",
            r#"{"DomainRecords":{"Record":[
                {"RecordId":"r1","RR":"www","Type":"A","Value":"1.1.1.1","TTL":300}
            ]}}"#,
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn set_rrset_adds_and_deletes_diff() {
        let mut server = mockito::Server::new_async().await;
        let _domains = mock_describe_domains(&mut server);
        let _list = mock_list_records(
            &mut server,
            "www",
            "A",
            r#"{"DomainRecords":{"Record":[
                {"RecordId":"keep","RR":"www","Type":"A","Value":"1.1.1.1","TTL":300},
                {"RecordId":"stale","RR":"www","Type":"A","Value":"9.9.9.9","TTL":300}
            ]}}"#,
        );

        let delete_stale = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("Action".into(), "DeleteDomainRecord".into()),
                mockito::Matcher::UrlEncoded("RecordId".into(), "stale".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"RecordId":"stale","RequestId":"r"}"#)
            .create();

        let add_new = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("Action".into(), "AddDomainRecord".into()),
                mockito::Matcher::UrlEncoded("DomainName".into(), "example.com".into()),
                mockito::Matcher::UrlEncoded("RR".into(), "www".into()),
                mockito::Matcher::UrlEncoded("Type".into(), "A".into()),
                mockito::Matcher::UrlEncoded("Value".into(), "8.8.8.8".into()),
                mockito::Matcher::UrlEncoded("TTL".into(), "300".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"RecordId":"new","RequestId":"r"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("8.8.8.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        delete_stale.assert();
        add_new.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_uses_delete_sub_domain_records() {
        let mut server = mockito::Server::new_async().await;
        let _domains = mock_describe_domains(&mut server);

        let bulk_delete = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("Action".into(), "DeleteSubDomainRecords".into()),
                mockito::Matcher::UrlEncoded("DomainName".into(), "example.com".into()),
                mockito::Matcher::UrlEncoded("RR".into(), "www".into()),
                mockito::Matcher::UrlEncoded("Type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"TotalCount":2,"RR":"www","RequestId":"r"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        bulk_delete.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_skips_already_present() {
        let mut server = mockito::Server::new_async().await;
        let _domains = mock_describe_domains(&mut server);
        let _list = mock_list_records(
            &mut server,
            "_acme",
            "TXT",
            r#"{"DomainRecords":{"Record":[
                {"RecordId":"have","RR":"_acme","Type":"TXT","Value":"existing","TTL":60}
            ]}}"#,
        );

        let add_new = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("Action".into(), "AddDomainRecord".into()),
                mockito::Matcher::UrlEncoded("RR".into(), "_acme".into()),
                mockito::Matcher::UrlEncoded("Type".into(), "TXT".into()),
                mockito::Matcher::UrlEncoded("Value".into(), "new-token".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"RecordId":"new","RequestId":"r"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                60,
                vec![
                    DnsRecord::TXT("existing".to_string()),
                    DnsRecord::TXT("new-token".to_string()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset failed: {result:?}");
        add_new.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_empty_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let unused = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                60,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset failed: {result:?}");
        unused.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_only_matching() {
        let mut server = mockito::Server::new_async().await;
        let _domains = mock_describe_domains(&mut server);
        let _list = mock_list_records(
            &mut server,
            "_acme",
            "TXT",
            r#"{"DomainRecords":{"Record":[
                {"RecordId":"keep","RR":"_acme","Type":"TXT","Value":"keep-me","TTL":60},
                {"RecordId":"drop","RR":"_acme","Type":"TXT","Value":"drop-me","TTL":60}
            ]}}"#,
        );

        let delete_drop = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("Action".into(), "DeleteDomainRecord".into()),
                mockito::Matcher::UrlEncoded("RecordId".into(), "drop".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"RecordId":"drop","RequestId":"r"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![
                    DnsRecord::TXT("drop-me".to_string()),
                    DnsRecord::TXT("absent".to_string()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
        delete_drop.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let unused = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("www.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
        unused.assert();
    }

    #[tokio::test]
    async fn set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let _domains = mock_describe_domains(&mut server);
        let _list = mock_list_records(
            &mut server,
            "www",
            "A",
            r#"{"DomainRecords":{"Record":[]}}"#,
        );

        let add = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("Action".into(), "AddDomainRecord".into()),
                mockito::Matcher::UrlEncoded("RR".into(), "www".into()),
                mockito::Matcher::UrlEncoded("Type".into(), "A".into()),
                mockito::Matcher::UrlEncoded("Value".into(), "1.1.1.1".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"RecordId":"new","RequestId":"r"}"#)
            .create();

        let txt_touched = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded("Type".into(), "TXT".into()))
            .with_status(500)
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        add.assert();
        txt_touched.assert();
    }

    #[tokio::test]
    async fn set_rrset_rejects_type_mismatch() {
        let mut server = mockito::Server::new_async().await;
        let unused = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("RRSet record type mismatch"))
        );
        unused.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_parsed_records() {
        let mut server = mockito::Server::new_async().await;
        let _domains = mock_describe_domains(&mut server);
        let _list = mock_list_records(
            &mut server,
            "mail",
            "MX",
            r#"{"DomainRecords":{"Record":[
                {"RecordId":"m1","RR":"mail","Type":"MX","Value":"mx1.example.com","TTL":300,"Priority":10},
                {"RecordId":"m2","RR":"mail","Type":"MX","Value":"mx2.example.com","TTL":300,"Priority":20}
            ]}}"#,
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("mail.example.com", DnsRecordType::MX, "example.com")
            .await
            .expect("list_rrset failed");

        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::MX(crate::MXRecord {
            exchange: "mx1.example.com".to_string(),
            priority: 10,
        })));
        assert!(result.contains(&DnsRecord::MX(crate::MXRecord {
            exchange: "mx2.example.com".to_string(),
            priority: 20,
        })));
    }
}
