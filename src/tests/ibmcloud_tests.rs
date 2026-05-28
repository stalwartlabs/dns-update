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
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, SRVRecord};
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const DOMAIN_ID: i64 = 4711;

    fn setup_provider(endpoint: &str) -> IbmCloudProvider {
        IbmCloudProvider::new("user", "key", Some(Duration::from_secs(2)))
            .expect("provider")
            .with_endpoint(endpoint)
    }

    fn basic_auth_header() -> String {
        use base64::{Engine, engine::general_purpose::STANDARD};
        format!("Basic {}", STANDARD.encode("user:key"))
    }

    fn mock_domain_lookup(server: &mut ServerGuard, name: &str, id: i64) -> Mock {
        let path = format!("/SoftLayer_Dns_Domain/getByDomainName/{name}.json");
        server
            .mock("GET", path.as_str())
            .match_header("authorization", basic_auth_header().as_str())
            .with_status(200)
            .with_body(format!(r#"[{{"id":{id},"name":"{name}"}}]"#))
            .create()
    }

    fn mock_list_records(server: &mut ServerGuard, body: serde_json::Value) -> Mock {
        let path = format!("/SoftLayer_Dns_Domain/{DOMAIN_ID}/getResourceRecords.json");
        server
            .mock("GET", path.as_str())
            .match_header("authorization", basic_auth_header().as_str())
            .with_status(200)
            .with_body(body.to_string())
            .create()
    }

    fn mock_post_record(server: &mut ServerGuard, expected: serde_json::Value) -> Mock {
        server
            .mock("POST", "/SoftLayer_Dns_Domain_ResourceRecord.json")
            .match_header("authorization", basic_auth_header().as_str())
            .match_body(Matcher::Json(expected))
            .with_status(200)
            .with_body(r#"{"id":1}"#)
            .create()
    }

    fn mock_delete_record(server: &mut ServerGuard, id: i64) -> Mock {
        server
            .mock(
                "DELETE",
                format!("/SoftLayer_Dns_Domain_ResourceRecord/{id}.json").as_str(),
            )
            .match_header("authorization", basic_auth_header().as_str())
            .with_status(200)
            .with_body("true")
            .create()
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_ibmcloud("user", "key", None);
        assert!(updater.is_ok());
        assert!(matches!(updater, Ok(DnsUpdater::IbmCloud(..))));
    }

    #[tokio::test]
    async fn set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let domain_mock = mock_domain_lookup(&mut server, "example.com", DOMAIN_ID);
        let list_mock = mock_list_records(&mut server, json!([]));
        let create_mock = mock_post_record(
            &mut server,
            json!({
                "parameters": [{
                    "host": "www",
                    "ttl": 300,
                    "type": "a",
                    "domainId": DOMAIN_ID,
                    "data": "1.2.3.4"
                }]
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domain_mock.assert();
        list_mock.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let domain_mock = mock_domain_lookup(&mut server, "example.com", DOMAIN_ID);
        let list_mock = mock_list_records(
            &mut server,
            json!([
                {"id": 1, "host": "www", "type": "a", "data": "1.2.3.4", "ttl": 300}
            ]),
        );
        let no_post = server
            .mock("POST", "/SoftLayer_Dns_Domain_ResourceRecord.json")
            .expect(0)
            .create();
        let no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex("^/SoftLayer_Dns_Domain_ResourceRecord/".to_string()),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domain_mock.assert();
        list_mock.assert();
        no_post.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn set_rrset_deletes_extras_and_creates_missing() {
        let mut server = mockito::Server::new_async().await;
        let domain_mock = mock_domain_lookup(&mut server, "example.com", DOMAIN_ID);
        let list_mock = mock_list_records(
            &mut server,
            json!([
                {"id": 11, "host": "host", "type": "a", "data": "1.1.1.1", "ttl": 300},
                {"id": 22, "host": "host", "type": "a", "data": "9.9.9.9", "ttl": 300}
            ]),
        );
        let delete_stale = mock_delete_record(&mut server, 22);
        let create_new = mock_post_record(
            &mut server,
            json!({
                "parameters": [{
                    "host": "host",
                    "ttl": 300,
                    "type": "a",
                    "domainId": DOMAIN_ID,
                    "data": "8.8.8.8"
                }]
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

        assert!(result.is_ok(), "{:?}", result);
        domain_mock.assert();
        list_mock.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_deletes_all_at_owner_and_type() {
        let mut server = mockito::Server::new_async().await;
        let domain_mock = mock_domain_lookup(&mut server, "example.com", DOMAIN_ID);
        let list_mock = mock_list_records(
            &mut server,
            json!([
                {"id": 33, "host": "gone", "type": "a", "data": "1.2.3.4", "ttl": 300},
                {"id": 44, "host": "gone", "type": "a", "data": "5.6.7.8", "ttl": 300},
                {"id": 55, "host": "gone", "type": "txt", "data": "keep-me", "ttl": 300},
                {"id": 66, "host": "other", "type": "a", "data": "9.9.9.9", "ttl": 300}
            ]),
        );
        let del33 = mock_delete_record(&mut server, 33);
        let del44 = mock_delete_record(&mut server, 44);
        let no_other = server
            .mock("DELETE", "/SoftLayer_Dns_Domain_ResourceRecord/55.json")
            .expect(0)
            .create();
        let no_other_host = server
            .mock("DELETE", "/SoftLayer_Dns_Domain_ResourceRecord/66.json")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "gone.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domain_mock.assert();
        list_mock.assert();
        del33.assert();
        del44.assert();
        no_other.assert();
        no_other_host.assert();
    }

    #[tokio::test]
    async fn set_rrset_filters_by_type_for_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let domain_mock = mock_domain_lookup(&mut server, "example.com", DOMAIN_ID);
        let list_mock = mock_list_records(
            &mut server,
            json!([
                {"id": 100, "host": "shared", "type": "txt", "data": "manual", "ttl": 300},
                {"id": 101, "host": "shared", "type": "aaaa", "data": "::1", "ttl": 300}
            ]),
        );
        let create_a = mock_post_record(
            &mut server,
            json!({
                "parameters": [{
                    "host": "shared",
                    "ttl": 300,
                    "type": "a",
                    "domainId": DOMAIN_ID,
                    "data": "1.1.1.1"
                }]
            }),
        );
        let no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex("^/SoftLayer_Dns_Domain_ResourceRecord/".to_string()),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "shared.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domain_mock.assert();
        list_mock.assert();
        create_a.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_skips_existing_and_creates_new() {
        let mut server = mockito::Server::new_async().await;
        let domain_mock = mock_domain_lookup(&mut server, "example.com", DOMAIN_ID);
        let list_mock = mock_list_records(
            &mut server,
            json!([
                {"id": 101, "host": "_acme", "type": "txt", "data": "existing", "ttl": 60}
            ]),
        );
        let create_new = mock_post_record(
            &mut server,
            json!({
                "parameters": [{
                    "host": "_acme",
                    "ttl": 60,
                    "type": "txt",
                    "domainId": DOMAIN_ID,
                    "data": "new-token"
                }]
            }),
        );

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

        assert!(result.is_ok(), "{:?}", result);
        domain_mock.assert();
        list_mock.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_empty_input_is_short_circuit() {
        let mut server = mockito::Server::new_async().await;
        let no_call = server.mock("GET", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        no_call.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let domain_mock = mock_domain_lookup(&mut server, "example.com", DOMAIN_ID);
        let list_mock = mock_list_records(
            &mut server,
            json!([
                {"id": 200, "host": "_acme", "type": "txt", "data": "keep-me", "ttl": 60},
                {"id": 201, "host": "_acme", "type": "txt", "data": "drop-me", "ttl": 60}
            ]),
        );
        let delete = mock_delete_record(&mut server, 201);
        let no_other = server
            .mock("DELETE", "/SoftLayer_Dns_Domain_ResourceRecord/200.json")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop-me".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domain_mock.assert();
        list_mock.assert();
        delete.assert();
        no_other.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_noop_when_value_absent() {
        let mut server = mockito::Server::new_async().await;
        let domain_mock = mock_domain_lookup(&mut server, "example.com", DOMAIN_ID);
        let list_mock = mock_list_records(
            &mut server,
            json!([
                {"id": 300, "host": "test", "type": "a", "data": "1.1.1.1", "ttl": 300}
            ]),
        );
        let no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex("^/SoftLayer_Dns_Domain_ResourceRecord/".to_string()),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domain_mock.assert();
        list_mock.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_input_is_short_circuit() {
        let mut server = mockito::Server::new_async().await;
        let no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok(), "{:?}", result);
        no_call.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn set_rrset_type_mismatch_returns_api_error() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not-an-A".to_string())],
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(_))), "got {:?}", result);
    }

    #[tokio::test]
    async fn set_rrset_rejects_caa() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::CAA,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref msg)) if msg.contains("CAA")),
            "got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn set_rrset_rejects_tlsa() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::TLSA,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref msg)) if msg.contains("TLSA")),
            "got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn set_rrset_mx_uses_mx_priority_and_trailing_dot() {
        let mut server = mockito::Server::new_async().await;
        let domain_mock = mock_domain_lookup(&mut server, "example.com", DOMAIN_ID);
        let list_mock = mock_list_records(&mut server, json!([]));
        let create_mock = mock_post_record(
            &mut server,
            json!({
                "parameters": [{
                    "host": "@",
                    "ttl": 3600,
                    "type": "mx",
                    "domainId": DOMAIN_ID,
                    "data": "mail.example.com.",
                    "mxPriority": 10,
                    "complexType": "SoftLayer_Dns_Domain_ResourceRecord_MxType"
                }]
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domain_mock.assert();
        list_mock.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_srv_breaks_out_service_protocol() {
        let mut server = mockito::Server::new_async().await;
        let domain_mock = mock_domain_lookup(&mut server, "example.com", DOMAIN_ID);
        let list_mock = mock_list_records(&mut server, json!([]));
        let create_mock = mock_post_record(
            &mut server,
            json!({
                "parameters": [{
                    "host": "_sip._tcp",
                    "ttl": 3600,
                    "type": "srv",
                    "domainId": DOMAIN_ID,
                    "data": "sipserver.example.com.",
                    "service": "_sip",
                    "protocol": "_tcp",
                    "priority": 10,
                    "weight": 20,
                    "port": 5060,
                    "complexType": "SoftLayer_Dns_Domain_ResourceRecord_SrvType"
                }]
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                3600,
                vec![DnsRecord::SRV(SRVRecord {
                    target: "sipserver.example.com".to_string(),
                    priority: 10,
                    weight: 20,
                    port: 5060,
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        domain_mock.assert();
        list_mock.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_only_matching_records() {
        let mut server = mockito::Server::new_async().await;
        let domain_mock = mock_domain_lookup(&mut server, "example.com", DOMAIN_ID);
        let list_mock = mock_list_records(
            &mut server,
            json!([
                {"id": 1, "host": "www", "type": "a", "data": "1.2.3.4", "ttl": 300},
                {"id": 2, "host": "www", "type": "a", "data": "5.6.7.8", "ttl": 300},
                {"id": 3, "host": "www", "type": "txt", "data": "ignore-me", "ttl": 300},
                {"id": 4, "host": "other", "type": "a", "data": "9.9.9.9", "ttl": 300}
            ]),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list");

        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("1.2.3.4".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("5.6.7.8".parse().unwrap())));
        domain_mock.assert();
        list_mock.assert();
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
            .set_rrset(
                "smoke.example.com",
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("hello".to_string())],
                "example.com",
            )
            .await;
    }
}
