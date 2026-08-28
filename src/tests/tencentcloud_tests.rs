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
        DnsRecord, DnsRecordType, Error, MXRecord, providers::tencentcloud::TencentCloudProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
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

    fn mock_domain_list(server: &mut ServerGuard) -> Mock {
        server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DescribeDomainList")
            .with_status(200)
            .with_body(DOMAIN_LIST_BODY)
            .expect_at_least(1)
            .create()
    }

    fn mock_describe_records(server: &mut ServerGuard, body: &str) -> Mock {
        server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DescribeRecordList")
            .with_status(200)
            .with_body(body)
            .create()
    }

    fn mock_create(server: &mut ServerGuard, partial_body: serde_json::Value) -> Mock {
        server
            .mock("POST", "/")
            .match_header("X-TC-Action", "CreateRecord")
            .match_body(Matcher::PartialJson(partial_body))
            .with_status(200)
            .with_body(EMPTY_OK_BODY)
            .create()
    }

    fn mock_delete(server: &mut ServerGuard, record_id: u64) -> Mock {
        server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DeleteRecord")
            .match_body(Matcher::PartialJson(serde_json::json!({
                "Domain": "example.com",
                "RecordId": record_id,
            })))
            .with_status(200)
            .with_body(EMPTY_OK_BODY)
            .create()
    }

    #[tokio::test]
    async fn set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_list(&mut server);
        let list = mock_describe_records(&mut server, r#"{"Response":{"RecordList":[]}}"#);
        let create_1 = mock_create(
            &mut server,
            serde_json::json!({
                "Domain": "example.com",
                "SubDomain": "host",
                "RecordType": "A",
                "RecordLineId": "0",
                "Value": "1.1.1.1",
                "TTL": 300,
            }),
        );
        let create_2 = mock_create(
            &mut server,
            serde_json::json!({
                "Domain": "example.com",
                "SubDomain": "host",
                "RecordType": "A",
                "RecordLineId": "0",
                "Value": "2.2.2.2",
                "TTL": 300,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        domain.assert();
        list.assert();
        create_1.assert();
        create_2.assert();
    }

    #[tokio::test]
    async fn set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_list(&mut server);
        let list = mock_describe_records(
            &mut server,
            r#"{"Response":{"RecordList":[
                {"RecordId":111,"Name":"host","Type":"A","Value":"1.1.1.1"}
            ]}}"#,
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        domain.assert();
        list.assert();
    }

    #[tokio::test]
    async fn set_rrset_deletes_extras_and_creates_missing() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_list(&mut server);
        let list = mock_describe_records(
            &mut server,
            r#"{"Response":{"RecordList":[
                {"RecordId":111,"Name":"host","Type":"A","Value":"1.1.1.1"},
                {"RecordId":222,"Name":"host","Type":"A","Value":"9.9.9.9"}
            ]}}"#,
        );
        let delete_stale = mock_delete(&mut server, 222);
        let create_new = mock_create(
            &mut server,
            serde_json::json!({
                "Domain": "example.com",
                "SubDomain": "host",
                "RecordType": "A",
                "RecordLineId": "0",
                "Value": "8.8.8.8",
                "TTL": 300,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
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
        domain.assert();
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_vec_deletes_all_of_type() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_list(&mut server);
        let list = mock_describe_records(
            &mut server,
            r#"{"Response":{"RecordList":[
                {"RecordId":111,"Name":"host","Type":"A","Value":"1.1.1.1"},
                {"RecordId":222,"Name":"host","Type":"A","Value":"2.2.2.2"}
            ]}}"#,
        );
        let delete_1 = mock_delete(&mut server, 111);
        let delete_2 = mock_delete(&mut server, 222);

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        domain.assert();
        list.assert();
        delete_1.assert();
        delete_2.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_empty_vec_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset failed: {result:?}");
    }

    #[tokio::test]
    async fn add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_list(&mut server);
        let list = mock_describe_records(
            &mut server,
            r#"{"Response":{"RecordList":[
                {"RecordId":111,"Name":"host","Type":"A","Value":"1.1.1.1"}
            ]}}"#,
        );
        let create_new = mock_create(
            &mut server,
            serde_json::json!({
                "Domain": "example.com",
                "SubDomain": "host",
                "RecordType": "A",
                "RecordLineId": "0",
                "Value": "2.2.2.2",
                "TTL": 300,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset failed: {result:?}");
        domain.assert();
        list.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_vec_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("host.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_only_matching() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_list(&mut server);
        let list = mock_describe_records(
            &mut server,
            r#"{"Response":{"RecordList":[
                {"RecordId":111,"Name":"host","Type":"A","Value":"1.1.1.1"},
                {"RecordId":222,"Name":"host","Type":"A","Value":"2.2.2.2"}
            ]}}"#,
        );
        let delete_match = mock_delete(&mut server, 222);

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                    DnsRecord::A("9.9.9.9".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
        domain.assert();
        list.assert();
        delete_match.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_decoded_records() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_list(&mut server);
        let list = mock_describe_records(
            &mut server,
            r#"{"Response":{"RecordList":[
                {"RecordId":111,"Name":"mail","Type":"MX","Value":"mx1.example.com.","MX":10},
                {"RecordId":222,"Name":"mail","Type":"MX","Value":"mx2.example.com.","MX":20}
            ]}}"#,
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("mail.example.com", DnsRecordType::MX, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset failed: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::MX(MXRecord {
            exchange: "mx1.example.com".to_string(),
            priority: 10,
        })));
        assert!(records.contains(&DnsRecord::MX(MXRecord {
            exchange: "mx2.example.com".to_string(),
            priority: 20,
        })));
        domain.assert();
        list.assert();
    }

    #[tokio::test]
    async fn list_rrset_empty_on_no_data_error() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_list(&mut server);
        let list = server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DescribeRecordList")
            .with_status(200)
            .with_body(
                r#"{"Response":{"Error":{"Code":"ResourceNotFound.NoDataOfRecord","Message":"no data"}}}"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("missing.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset failed: {result:?}");
        assert!(result.unwrap().is_empty());
        domain.assert();
        list.assert();
    }

    #[tokio::test]
    async fn set_rrset_rejects_type_mismatch() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::AAAA("2001:db8::1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(msg)) if msg.contains("mismatch")));
    }

    #[tokio::test]
    async fn set_rrset_rejects_tlsa() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_443._tcp.example.com",
                DnsRecordType::TLSA,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Unsupported(msg)) if msg.contains("TLSA")));
    }

    #[tokio::test]
    async fn set_rrset_only_touches_target_type() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_list(&mut server);
        let list = server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DescribeRecordList")
            .match_body(Matcher::PartialJson(serde_json::json!({
                "RecordType": "A",
            })))
            .with_status(200)
            .with_body(
                r#"{"Response":{"RecordList":[
                    {"RecordId":111,"Name":"host","Type":"A","Value":"1.1.1.1"}
                ]}}"#,
            )
            .create();
        let delete_a = mock_delete(&mut server, 111);

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        domain.assert();
        list.assert();
        delete_a.assert();
    }

    #[tokio::test]
    async fn set_rrset_idempotent_on_repeat() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_list(&mut server);
        let list = server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DescribeRecordList")
            .with_status(200)
            .with_body(
                r#"{"Response":{"RecordList":[
                    {"RecordId":111,"Name":"host","Type":"TXT","Value":"hello"}
                ]}}"#,
            )
            .expect(2)
            .create();

        let provider = setup_provider(server.url().as_str());
        for _ in 0..2 {
            let result = provider
                .set_rrset(
                    "host.example.com",
                    DnsRecordType::TXT,
                    300,
                    vec![DnsRecord::TXT("hello".to_string())],
                    "example.com",
                )
                .await;
            assert!(result.is_ok(), "set_rrset failed: {result:?}");
        }
        domain.assert();
        list.assert();
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

        let provider = TencentCloudProvider::new(
            secret_id,
            secret_key,
            None::<&str>,
            None::<&str>,
            Some(Duration::from_secs(30)),
        )
        .unwrap();

        let set_result = provider
            .set_rrset(
                &fqdn,
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                &origin,
            )
            .await;
        assert!(set_result.is_ok(), "set failed: {set_result:?}");

        let add_result = provider
            .add_to_rrset(
                &fqdn,
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("8.8.8.8".parse().unwrap())],
                &origin,
            )
            .await;
        assert!(add_result.is_ok(), "add failed: {add_result:?}");

        let listed = provider.list_rrset(&fqdn, DnsRecordType::A, &origin).await;
        assert!(listed.is_ok(), "list failed: {listed:?}");

        let remove_result = provider
            .remove_from_rrset(
                &fqdn,
                DnsRecordType::A,
                vec![DnsRecord::A("8.8.8.8".parse().unwrap())],
                &origin,
            )
            .await;
        assert!(remove_result.is_ok(), "remove failed: {remove_result:?}");

        let delete_result = provider
            .set_rrset(&fqdn, DnsRecordType::A, 600, vec![], &origin)
            .await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }

    #[tokio::test]
    async fn test_uses_charset_content_type() {
        let mut server = mockito::Server::new_async().await;

        let domain_list = mock_domain_list(&mut server);

        let list_records = server
            .mock("POST", "/")
            .match_header("X-TC-Action", "DescribeRecordList")
            .match_header("content-type", "application/json; charset=utf-8")
            .with_status(200)
            .with_body(r#"{"Response":{"RecordList":[],"TotalCount":0,"RequestId":"x"}}"#)
            .create();

        let p = setup_provider(&server.url());
        let result = p
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await;
        assert!(result.is_ok(), "list failed: {result:?}");
        domain_list.assert();
        list_records.assert();
    }
}
