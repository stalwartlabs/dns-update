#[cfg(test)]
mod tests {
    use crate::{
        CAARecord, DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord, TLSARecord, TlsaCertUsage,
        TlsaMatching, TlsaSelector, providers::dnsimple::DNSimpleProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> DNSimpleProvider {
        DNSimpleProvider::new("test_bearer_token", "1010", Some(Duration::from_secs(1)))
            .with_endpoint(endpoint)
    }

    fn list_mock(
        server: &mut ServerGuard,
        subdomain: &str,
        record_type: &str,
        body: serde_json::Value,
    ) -> Mock {
        server
            .mock("GET", "/1010/zones/example.com/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), subdomain.into()),
                Matcher::UrlEncoded("type".into(), record_type.into()),
                Matcher::UrlEncoded("per_page".into(), "100".into()),
            ]))
            .match_header("Authorization", "Bearer test_bearer_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    fn ok_list(items: serde_json::Value) -> serde_json::Value {
        json!({ "data": items })
    }

    fn record_json(
        id: i64,
        name: &str,
        record_type: &str,
        content: &str,
        priority: Option<u16>,
    ) -> serde_json::Value {
        json!({
            "id": id,
            "zone_id": "example.com",
            "parent_id": null,
            "name": name,
            "content": content,
            "ttl": 3600,
            "priority": priority,
            "type": record_type,
            "regions": ["global"],
            "system_record": false,
        })
    }

    #[tokio::test]
    async fn set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(&mut server, "mail", "TLSA", ok_list(json!([])));

        let create_1 = server
            .mock("POST", "/1010/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "name": "mail",
                "type": "TLSA",
                "content": "3 1 1 00",
                "ttl": 300,
            })))
            .with_status(201)
            .with_body(r#"{"data":{}}"#)
            .create();
        let create_2 = server
            .mock("POST", "/1010/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "name": "mail",
                "type": "TLSA",
                "content": "2 1 1 ff",
                "ttl": 300,
            })))
            .with_status(201)
            .with_body(r#"{"data":{}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneEe,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0x00],
                    }),
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneTa,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xff],
                    }),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create_1.assert();
        create_2.assert();
    }

    #[tokio::test]
    async fn set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "test",
            "A",
            ok_list(json!([record_json(1, "test", "A", "1.1.1.1", None)])),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn set_rrset_deletes_extras_and_keeps_matching() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "host",
            "A",
            ok_list(json!([
                record_json(11, "host", "A", "1.1.1.1", None),
                record_json(22, "host", "A", "9.9.9.9", None),
            ])),
        );

        let delete_stale = server
            .mock("DELETE", "/1010/zones/example.com/records/22")
            .with_status(204)
            .create();

        let create_new = server
            .mock("POST", "/1010/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "name": "host",
                "type": "A",
                "content": "8.8.8.8",
                "ttl": 300,
            })))
            .with_status(201)
            .with_body(r#"{"data":{}}"#)
            .create();

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
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_records_deletes_all() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "gone",
            "A",
            ok_list(json!([
                record_json(101, "gone", "A", "1.2.3.4", None),
                record_json(102, "gone", "A", "5.6.7.8", None),
            ])),
        );
        let del_a = server
            .mock("DELETE", "/1010/zones/example.com/records/101")
            .with_status(204)
            .create();
        let del_b = server
            .mock("DELETE", "/1010/zones/example.com/records/102")
            .with_status(204)
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
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        del_a.assert();
        del_b.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_records_at_apex_only_lists_target_type() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(&mut server, "", "A", ok_list(json!([])));
        let _no_other_list = server
            .mock("GET", "/1010/zones/example.com/records")
            .match_query(Matcher::UrlEncoded("type".into(), "TXT".into()))
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset("example.com", DnsRecordType::A, 300, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "_acme",
            "TXT",
            ok_list(json!([record_json(7, "_acme", "TXT", "existing", None)])),
        );
        let create_new = server
            .mock("POST", "/1010/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "name": "_acme",
                "type": "TXT",
                "content": "new-token",
                "ttl": 60,
            })))
            .with_status(201)
            .with_body(r#"{"data":{}}"#)
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
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        list.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_empty_input_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let _no_post = server.mock("POST", Matcher::Any).expect(0).create();

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
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "_acme",
            "TXT",
            ok_list(json!([
                record_json(11, "_acme", "TXT", "keep-me", None),
                record_json(12, "_acme", "TXT", "drop-me", None),
            ])),
        );
        let delete = server
            .mock("DELETE", "/1010/zones/example.com/records/12")
            .with_status(204)
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
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_noop_when_values_absent() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "test",
            "A",
            ok_list(json!([record_json(1, "test", "A", "1.1.1.1", None)])),
        );
        let _no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_input_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let _no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn set_rrset_rejects_records_of_wrong_type() {
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
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn set_rrset_filters_other_types_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(&mut server, "shared", "A", ok_list(json!([])));
        let _txt_get_must_not_fire = server
            .mock("GET", "/1010/zones/example.com/records")
            .match_query(Matcher::UrlEncoded("type".into(), "TXT".into()))
            .expect(0)
            .create();
        let create = server
            .mock("POST", "/1010/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "name": "shared",
                "type": "A",
                "content": "1.1.1.1",
                "ttl": 300,
            })))
            .with_status(201)
            .with_body(r#"{"data":{}}"#)
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
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn set_rrset_mx_sends_priority_top_level() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(&mut server, "", "MX", ok_list(json!([])));
        let create = server
            .mock("POST", "/1010/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "name": "",
                "type": "MX",
                "content": "mail.example.com",
                "ttl": 3600,
                "priority": 10,
            })))
            .with_status(201)
            .with_body(r#"{"data":{}}"#)
            .create();

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
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn set_rrset_mx_with_different_priorities_distinct_rrset_entries() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "",
            "MX",
            ok_list(json!([record_json(
                1,
                "",
                "MX",
                "mx1.example.com",
                Some(10)
            ),])),
        );
        let create_backup = server
            .mock("POST", "/1010/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "name": "",
                "type": "MX",
                "content": "mx2.example.com",
                "ttl": 3600,
                "priority": 20,
            })))
            .with_status(201)
            .with_body(r#"{"data":{}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![
                    DnsRecord::MX(MXRecord {
                        exchange: "mx1.example.com".to_string(),
                        priority: 10,
                    }),
                    DnsRecord::MX(MXRecord {
                        exchange: "mx2.example.com".to_string(),
                        priority: 20,
                    }),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create_backup.assert();
    }

    #[tokio::test]
    async fn set_rrset_srv_sends_weight_port_target_and_priority_top_level() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(&mut server, "_imaps._tcp", "SRV", ok_list(json!([])));
        let create = server
            .mock("POST", "/1010/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "name": "_imaps._tcp",
                "type": "SRV",
                "content": "5 993 mail.example.com",
                "ttl": 3600,
                "priority": 10,
            })))
            .with_status(201)
            .with_body(r#"{"data":{}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_imaps._tcp.example.com",
                DnsRecordType::SRV,
                3600,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 993,
                    target: "mail.example.com".to_string(),
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn set_rrset_caa_sends_bind_style_content() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(&mut server, "", "CAA", ok_list(json!([])));
        let create = server
            .mock("POST", "/1010/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "name": "",
                "type": "CAA",
                "content": "0 issue \"letsencrypt.org\"",
                "ttl": 3600,
            })))
            .with_status(201)
            .with_body(r#"{"data":{}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::CAA,
                3600,
                vec![DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".to_string()),
                    options: vec![],
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn set_rrset_txt_is_sent_raw_no_quoting() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "selector._domainkey",
            "TXT",
            ok_list(json!([])),
        );
        let long_value = format!("v=DKIM1;k=rsa;p={}", "A".repeat(380));
        let body = json!({
            "name": "selector._domainkey",
            "type": "TXT",
            "content": long_value,
            "ttl": 300,
        });
        let create = server
            .mock("POST", "/1010/zones/example.com/records")
            .match_body(Matcher::Json(body))
            .with_status(201)
            .with_body(r#"{"data":{}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "selector._domainkey.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(long_value.clone())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_parsed_records() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "host",
            "A",
            ok_list(json!([
                record_json(1, "host", "A", "1.1.1.1", None),
                record_json(2, "host", "A", "2.2.2.2", None),
            ])),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset");
        list.assert();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
    }

    #[tokio::test]
    async fn list_rrset_parses_mx_with_priority() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "",
            "MX",
            ok_list(json!([record_json(
                1,
                "",
                "MX",
                "mail.example.com",
                Some(10)
            )])),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .expect("list_rrset");
        list.assert();
        assert_eq!(
            result,
            vec![DnsRecord::MX(MXRecord {
                exchange: "mail.example.com".to_string(),
                priority: 10,
            })]
        );
    }

    #[tokio::test]
    async fn list_rrset_parses_srv_content_into_record() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "_imaps._tcp",
            "SRV",
            ok_list(json!([record_json(
                1,
                "_imaps._tcp",
                "SRV",
                "5 993 mail.example.com",
                Some(10)
            )])),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("_imaps._tcp.example.com", DnsRecordType::SRV, "example.com")
            .await
            .expect("list_rrset");
        list.assert();
        assert_eq!(
            result,
            vec![DnsRecord::SRV(SRVRecord {
                priority: 10,
                weight: 5,
                port: 993,
                target: "mail.example.com".to_string(),
            })]
        );
    }

    #[tokio::test]
    async fn list_rrset_parses_tlsa_bind_content() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "_443._tcp.www",
            "TLSA",
            ok_list(json!([record_json(
                1,
                "_443._tcp.www",
                "TLSA",
                "3 1 1 aabbcc",
                None
            )])),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset(
                "_443._tcp.www.example.com",
                DnsRecordType::TLSA,
                "example.com",
            )
            .await
            .expect("list_rrset");
        list.assert();
        assert_eq!(
            result,
            vec![DnsRecord::TLSA(TLSARecord {
                cert_usage: TlsaCertUsage::DaneEe,
                selector: TlsaSelector::Spki,
                matching: TlsaMatching::Sha256,
                cert_data: vec![0xaa, 0xbb, 0xcc],
            })]
        );
    }

    #[tokio::test]
    async fn list_rrset_parses_caa_bind_content() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "",
            "CAA",
            ok_list(json!([record_json(
                1,
                "",
                "CAA",
                "0 issue \"letsencrypt.org\"",
                None
            )])),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("example.com", DnsRecordType::CAA, "example.com")
            .await
            .expect("list_rrset");
        list.assert();
        assert_eq!(
            result,
            vec![DnsRecord::CAA(CAARecord::Issue {
                issuer_critical: false,
                name: Some("letsencrypt.org".to_string()),
                options: vec![],
            })]
        );
    }

    #[tokio::test]
    async fn list_rrset_drops_records_that_dont_match_subdomain() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "host",
            "A",
            ok_list(json!([
                record_json(1, "host", "A", "1.1.1.1", None),
                record_json(2, "other", "A", "9.9.9.9", None),
            ])),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset");
        list.assert();
        assert_eq!(result, vec![DnsRecord::A("1.1.1.1".parse().unwrap())]);
    }

    #[tokio::test]
    async fn set_rrset_replaces_two_tlsa_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "_25._tcp.mail",
            "TLSA",
            ok_list(json!([
                record_json(1, "_25._tcp.mail", "TLSA", "3 1 1 aa", None),
                record_json(2, "_25._tcp.mail", "TLSA", "2 1 1 bb", None),
            ])),
        );
        let del1 = server
            .mock("DELETE", "/1010/zones/example.com/records/1")
            .with_status(204)
            .create();
        let del2 = server
            .mock("DELETE", "/1010/zones/example.com/records/2")
            .with_status(204)
            .create();
        let create_ee = server
            .mock("POST", "/1010/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "name": "_25._tcp.mail",
                "type": "TLSA",
                "content": "3 1 1 cc",
                "ttl": 300,
            })))
            .with_status(201)
            .with_body(r#"{"data":{}}"#)
            .create();
        let create_ta = server
            .mock("POST", "/1010/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "name": "_25._tcp.mail",
                "type": "TLSA",
                "content": "2 1 1 dd",
                "ttl": 300,
            })))
            .with_status(201)
            .with_body(r#"{"data":{}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneEe,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xcc],
                    }),
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneTa,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xdd],
                    }),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        del1.assert();
        del2.assert();
        create_ee.assert();
        create_ta.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_creates_rrset_from_empty_owner() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(&mut server, "fresh", "A", ok_list(json!([])));
        let create = server
            .mock("POST", "/1010/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "name": "fresh",
                "type": "A",
                "content": "9.9.9.9",
                "ttl": 300,
            })))
            .with_status(201)
            .with_body(r#"{"data":{}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "fresh.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_full_noop_when_everything_present() {
        let mut server = mockito::Server::new_async().await;
        let list = list_mock(
            &mut server,
            "test",
            "A",
            ok_list(json!([
                record_json(1, "test", "A", "1.1.1.1", None),
                record_json(2, "test", "A", "8.8.8.8", None),
            ])),
        );
        let _no_post = server
            .mock("POST", "/1010/zones/example.com/records")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("8.8.8.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("GET", "/1010/zones/example.com/records")
            .match_query(Matcher::Any)
            .with_status(401)
            .with_body(r#"{"message":"Authentication failed"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
        unauthorized.assert();
    }
}
