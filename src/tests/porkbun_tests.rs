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
        DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, SRVRecord,
        providers::porkbun::{PorkBunProvider, RecordData},
    };
    use mockito::{Matcher, ServerGuard};
    use serde_json::json;
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    fn setup_provider(endpoint: &str) -> PorkBunProvider {
        PorkBunProvider::new(
            "test_api_key",
            "test_secret_api_key",
            Some(Duration::from_secs(1)),
        )
        .with_endpoint(endpoint)
    }

    fn auth_only() -> serde_json::Value {
        json!({
            "apikey": "test_api_key",
            "secretapikey": "test_secret_api_key",
        })
    }

    fn ok_status() -> &'static str {
        r#"{"status": "SUCCESS"}"#
    }

    fn mock_retrieve(
        server: &mut ServerGuard,
        record_type: &str,
        subdomain: &str,
        records: serde_json::Value,
    ) -> mockito::Mock {
        let path = if subdomain.is_empty() {
            format!("/dns/retrieveByNameType/example.com/{record_type}")
        } else {
            format!("/dns/retrieveByNameType/example.com/{record_type}/{subdomain}")
        };
        server
            .mock("POST", path.as_str())
            .match_body(Matcher::Json(auth_only()))
            .with_body(
                json!({
                    "status": "SUCCESS",
                    "records": records,
                })
                .to_string(),
            )
            .create()
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_porkbun(
            "test_api_key-mock-api-key",
            "test_secret_api_key",
            Some(Duration::from_secs(30)),
        );
        assert!(updater.is_ok());
        assert!(matches!(updater, Ok(DnsUpdater::Porkbun(..))));
    }

    #[test]
    fn record_data_from_dns_record_strips_trailing_dots() {
        let cname: RecordData = DnsRecord::CNAME("alias.example.com.".to_string()).into();
        if let RecordData::CNAME { content } = cname {
            assert_eq!(content, "alias.example.com");
        } else {
            panic!("expected CNAME");
        }

        let ns: RecordData = DnsRecord::NS("ns1.example.com.".to_string()).into();
        if let RecordData::NS { content } = ns {
            assert_eq!(content, "ns1.example.com");
        } else {
            panic!("expected NS");
        }

        let mx: RecordData = DnsRecord::MX(MXRecord {
            exchange: "mail.example.com.".to_string(),
            priority: 10,
        })
        .into();
        if let RecordData::MX { content, prio } = mx {
            assert_eq!(content, "mail.example.com");
            assert_eq!(prio, 10);
        } else {
            panic!("expected MX");
        }

        let srv: RecordData = DnsRecord::SRV(SRVRecord {
            target: "sip.example.com.".to_string(),
            priority: 1,
            weight: 20,
            port: 443,
        })
        .into();
        if let RecordData::SRV { content, prio } = srv {
            assert_eq!(content, "20 443 sip.example.com");
            assert_eq!(prio, 1);
        } else {
            panic!("expected SRV");
        }
    }

    #[test]
    fn record_data_from_dns_record_basic_types() {
        let a: RecordData = DnsRecord::A("1.1.1.1".parse().unwrap()).into();
        if let RecordData::A { content } = a {
            assert_eq!(content, "1.1.1.1".parse::<Ipv4Addr>().unwrap());
        } else {
            panic!("expected A");
        }

        let aaaa: RecordData = DnsRecord::AAAA("2001:db8::1".parse().unwrap()).into();
        if let RecordData::AAAA { content } = aaaa {
            assert_eq!(content, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        } else {
            panic!("expected AAAA");
        }

        let txt: RecordData = DnsRecord::TXT("v=spf1 -all".to_string()).into();
        if let RecordData::TXT { content } = txt {
            assert_eq!(content, "v=spf1 -all");
        } else {
            panic!("expected TXT");
        }
    }

    #[tokio::test]
    async fn set_rrset_empty_calls_delete_by_name_type() {
        let mut server = mockito::Server::new_async().await;

        let delete = server
            .mock("POST", "/dns/deleteByNameType/example.com/A/gone")
            .match_body(Matcher::Json(auth_only()))
            .with_body(ok_status())
            .expect(1)
            .create();
        let _no_retrieve = server
            .mock("POST", Matcher::Regex("/dns/retrieveByNameType/.*".into()))
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

        assert!(result.is_ok(), "got {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_at_apex_uses_url_without_subdomain() {
        let mut server = mockito::Server::new_async().await;

        let delete = server
            .mock("POST", "/dns/deleteByNameType/example.com/A")
            .match_body(Matcher::Json(auth_only()))
            .with_body(ok_status())
            .expect(1)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset("example.com", DnsRecordType::A, 300, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "got {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn set_rrset_single_uses_edit_by_name_type() {
        let mut server = mockito::Server::new_async().await;

        let edit = server
            .mock("POST", "/dns/editByNameType/example.com/A/www")
            .match_body(Matcher::Json(json!({
                "apikey": "test_api_key",
                "secretapikey": "test_secret_api_key",
                "content": "1.2.3.4",
                "ttl": 300,
            })))
            .with_body(ok_status())
            .expect(1)
            .create();
        let _no_retrieve = server
            .mock("POST", Matcher::Regex("/dns/retrieveByNameType/.*".into()))
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
        assert!(result.is_ok(), "got {result:?}");
        edit.assert();
    }

    #[tokio::test]
    async fn set_rrset_single_mx_sends_prio_via_edit_by_name_type() {
        let mut server = mockito::Server::new_async().await;

        let edit = server
            .mock("POST", "/dns/editByNameType/example.com/MX")
            .match_body(Matcher::Json(json!({
                "apikey": "test_api_key",
                "secretapikey": "test_secret_api_key",
                "content": "mail.example.com",
                "ttl": 3600,
                "prio": 10,
            })))
            .with_body(ok_status())
            .expect(1)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com.".to_string(),
                    priority: 10,
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "got {result:?}");
        edit.assert();
    }

    #[tokio::test]
    async fn set_rrset_multi_diff_adds_and_deletes() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_retrieve(
            &mut server,
            "A",
            "host",
            json!([
                {"id": "rec-keep", "name": "host.example.com", "type": "A", "content": "1.1.1.1", "ttl": "300", "prio": "0"},
                {"id": "rec-stale", "name": "host.example.com", "type": "A", "content": "9.9.9.9", "ttl": "300", "prio": "0"},
            ]),
        );

        let delete_stale = server
            .mock("POST", "/dns/delete/example.com/rec-stale")
            .match_body(Matcher::Json(auth_only()))
            .with_body(ok_status())
            .expect(1)
            .create();
        let _no_keep_delete = server
            .mock("POST", "/dns/delete/example.com/rec-keep")
            .expect(0)
            .create();
        let create_new = server
            .mock("POST", "/dns/create/example.com")
            .match_body(Matcher::Json(json!({
                "apikey": "test_api_key",
                "secretapikey": "test_secret_api_key",
                "name": "host",
                "type": "A",
                "content": "8.8.8.8",
                "ttl": 300,
            })))
            .with_body(r#"{"status": "SUCCESS","id": "new-1"}"#)
            .expect(1)
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

        assert!(result.is_ok(), "got {result:?}");
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn set_rrset_multi_idempotent_when_all_match() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_retrieve(
            &mut server,
            "A",
            "host",
            json!([
                {"id": "rec-1", "name": "host.example.com", "type": "A", "content": "1.1.1.1", "ttl": "300", "prio": "0"},
                {"id": "rec-2", "name": "host.example.com", "type": "A", "content": "8.8.8.8", "ttl": "300", "prio": "0"},
            ]),
        );

        let _no_mutation = server
            .mock("POST", Matcher::Regex("/dns/(create|delete)/.*".into()))
            .expect(0)
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
        assert!(result.is_ok(), "got {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn set_rrset_type_validation_rejects_mismatched_record() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("POST", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not-an-a".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn add_to_rrset_empty_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("POST", Matcher::Any).expect(0).create();

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
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_to_rrset_skips_already_present() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_retrieve(
            &mut server,
            "TXT",
            "_acme",
            json!([
                {"id": "rec-old", "name": "_acme.example.com", "type": "TXT", "content": "existing", "ttl": "60", "prio": "0"},
            ]),
        );

        let create = server
            .mock("POST", "/dns/create/example.com")
            .match_body(Matcher::Json(json!({
                "apikey": "test_api_key",
                "secretapikey": "test_secret_api_key",
                "name": "_acme",
                "type": "TXT",
                "content": "new-token",
                "ttl": 60,
            })))
            .with_body(r#"{"status": "SUCCESS","id": "new-1"}"#)
            .expect(1)
            .create();
        let _no_create_existing = server
            .mock("POST", "/dns/create/example.com")
            .match_body(Matcher::PartialJson(json!({"content": "existing"})))
            .expect(0)
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
        assert!(result.is_ok(), "got {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("POST", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_only_matching() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_retrieve(
            &mut server,
            "TXT",
            "_acme",
            json!([
                {"id": "rec-keep", "name": "_acme.example.com", "type": "TXT", "content": "keep-me", "ttl": "60", "prio": "0"},
                {"id": "rec-drop", "name": "_acme.example.com", "type": "TXT", "content": "drop-me", "ttl": "60", "prio": "0"},
            ]),
        );

        let delete = server
            .mock("POST", "/dns/delete/example.com/rec-drop")
            .match_body(Matcher::Json(auth_only()))
            .with_body(ok_status())
            .expect(1)
            .create();
        let _no_keep_delete = server
            .mock("POST", "/dns/delete/example.com/rec-keep")
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
        assert!(result.is_ok(), "got {result:?}");
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_noop_when_value_absent() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_retrieve(
            &mut server,
            "A",
            "test",
            json!([
                {"id": "rec-1", "name": "test.example.com", "type": "A", "content": "1.1.1.1", "ttl": "300", "prio": "0"},
            ]),
        );
        let _no_delete = server
            .mock("POST", Matcher::Regex("/dns/delete/example.com/.*".into()))
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
        assert!(result.is_ok(), "got {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn list_rrset_converts_to_dns_records() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_retrieve(
            &mut server,
            "A",
            "host",
            json!([
                {"id": "rec-1", "name": "host.example.com", "type": "A", "content": "1.1.1.1", "ttl": "300", "prio": "0"},
                {"id": "rec-2", "name": "host.example.com", "type": "A", "content": "2.2.2.2", "ttl": "300", "prio": "0"},
            ]),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await;
        assert!(result.is_ok(), "got {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(records.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
        list.assert();
    }

    #[tokio::test]
    async fn list_rrset_filters_by_type_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_retrieve(
            &mut server,
            "A",
            "shared",
            json!([
                {"id": "rec-a", "name": "shared.example.com", "type": "A", "content": "1.1.1.1", "ttl": "300", "prio": "0"},
                {"id": "rec-txt-noise", "name": "shared.example.com", "type": "TXT", "content": "noise", "ttl": "300", "prio": "0"},
            ]),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("shared.example.com", DnsRecordType::A, "example.com")
            .await;
        assert!(result.is_ok(), "got {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], DnsRecord::A("1.1.1.1".parse().unwrap()));
        list.assert();
    }

    #[tokio::test]
    async fn set_rrset_cross_type_isolation_only_touches_declared_type() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_retrieve(
            &mut server,
            "A",
            "shared",
            json!([
                {"id": "rec-a-1", "name": "shared.example.com", "type": "A", "content": "1.1.1.1", "ttl": "300", "prio": "0"},
                {"id": "rec-a-2", "name": "shared.example.com", "type": "A", "content": "2.2.2.2", "ttl": "300", "prio": "0"},
            ]),
        );

        let delete_old1 = server
            .mock("POST", "/dns/delete/example.com/rec-a-1")
            .with_body(ok_status())
            .expect(1)
            .create();
        let delete_old2 = server
            .mock("POST", "/dns/delete/example.com/rec-a-2")
            .with_body(ok_status())
            .expect(1)
            .create();
        let create_new1 = server
            .mock("POST", "/dns/create/example.com")
            .match_body(Matcher::PartialJson(
                json!({"content": "3.3.3.3", "type": "A"}),
            ))
            .with_body(r#"{"status": "SUCCESS","id": "n1"}"#)
            .expect(1)
            .create();
        let create_new2 = server
            .mock("POST", "/dns/create/example.com")
            .match_body(Matcher::PartialJson(
                json!({"content": "4.4.4.4", "type": "A"}),
            ))
            .with_body(r#"{"status": "SUCCESS","id": "n2"}"#)
            .expect(1)
            .create();
        let _no_txt_retrieve = server
            .mock(
                "POST",
                Matcher::Regex("/dns/retrieveByNameType/example.com/TXT.*".into()),
            )
            .expect(0)
            .create();
        let _no_delete_by_name_type = server
            .mock("POST", Matcher::Regex("/dns/deleteByNameType/.*".into()))
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "shared.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("3.3.3.3".parse().unwrap()),
                    DnsRecord::A("4.4.4.4".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "got {result:?}");
        list.assert();
        delete_old1.assert();
        delete_old2.assert();
        create_new1.assert();
        create_new2.assert();
    }

    #[tokio::test]
    async fn set_rrset_multi_mx_with_different_priorities_via_diff() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_retrieve(&mut server, "MX", "", json!([]));

        let create_primary = server
            .mock("POST", "/dns/create/example.com")
            .match_body(Matcher::Json(json!({
                "apikey": "test_api_key",
                "secretapikey": "test_secret_api_key",
                "name": "",
                "type": "MX",
                "content": "mx1.example.com",
                "prio": 10,
                "ttl": 3600,
            })))
            .with_body(r#"{"status": "SUCCESS","id": "n1"}"#)
            .expect(1)
            .create();
        let create_backup = server
            .mock("POST", "/dns/create/example.com")
            .match_body(Matcher::Json(json!({
                "apikey": "test_api_key",
                "secretapikey": "test_secret_api_key",
                "name": "",
                "type": "MX",
                "content": "mx2.example.com",
                "prio": 20,
                "ttl": 3600,
            })))
            .with_body(r#"{"status": "SUCCESS","id": "n2"}"#)
            .expect(1)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![
                    DnsRecord::MX(MXRecord {
                        exchange: "mx1.example.com.".to_string(),
                        priority: 10,
                    }),
                    DnsRecord::MX(MXRecord {
                        exchange: "mx2.example.com.".to_string(),
                        priority: 20,
                    }),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "got {result:?}");
        list.assert();
        create_primary.assert();
        create_backup.assert();
    }

    #[tokio::test]
    async fn set_rrset_cname_strips_trailing_dot_in_payload() {
        let mut server = mockito::Server::new_async().await;

        let edit = server
            .mock("POST", "/dns/editByNameType/example.com/CNAME/www")
            .match_body(Matcher::Json(json!({
                "apikey": "test_api_key",
                "secretapikey": "test_secret_api_key",
                "content": "target.example.com",
                "ttl": 300,
            })))
            .with_body(ok_status())
            .expect(1)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::CNAME,
                300,
                vec![DnsRecord::CNAME("target.example.com.".to_string())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "got {result:?}");
        edit.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_treats_listed_trailing_dot_as_match() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_retrieve(
            &mut server,
            "NS",
            "sub",
            json!([
                {"id": "ns-1", "name": "sub.example.com", "type": "NS", "content": "ns1.example.com.", "ttl": "300", "prio": "0"},
            ]),
        );
        let _no_create = server
            .mock("POST", "/dns/create/example.com")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "sub.example.com",
                DnsRecordType::NS,
                300,
                vec![DnsRecord::NS("ns1.example.com".to_string())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "got {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn api_error_response_maps_to_error_api() {
        let mut server = mockito::Server::new_async().await;

        let edit = server
            .mock("POST", "/dns/editByNameType/example.com/A/www")
            .with_body(r#"{"status": "ERROR", "message": "Invalid API key"}"#)
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
        assert!(
            matches!(result, Err(Error::Api(ref m)) if m.contains("Invalid API key")),
            "got {result:?}"
        );
        edit.assert();
    }

    #[tokio::test]
    #[ignore = "Requires Porkbun API credentials and domain configuration"]
    async fn integration_test() {
        let api_key = std::env::var("PB_API_KEY").unwrap_or_default();
        let secret_api_key = std::env::var("PB_SECRET_API_KEY").unwrap_or_default();
        let origin = std::env::var("PB_ORIGIN").unwrap_or_default();
        let domain = std::env::var("PB_DOMAIN").unwrap_or_default();

        assert!(!api_key.is_empty(), "PB_API_KEY required");
        assert!(!secret_api_key.is_empty(), "PB_SECRET_API_KEY required");
        assert!(!origin.is_empty(), "PB_ORIGIN required");
        assert!(!domain.is_empty(), "PB_DOMAIN required");

        let updater =
            DnsUpdater::new_porkbun(api_key, secret_api_key, Some(Duration::from_secs(30)))
                .unwrap();

        updater
            .set_rrset(
                &domain,
                DnsRecordType::A,
                600,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                &origin,
            )
            .await
            .expect("set_rrset two A");

        updater
            .add_to_rrset(
                &domain,
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("3.3.3.3".parse().unwrap())],
                &origin,
            )
            .await
            .expect("add_to_rrset");

        updater
            .remove_from_rrset(
                &domain,
                DnsRecordType::A,
                vec![DnsRecord::A("2.2.2.2".parse().unwrap())],
                &origin,
            )
            .await
            .expect("remove_from_rrset");

        updater
            .set_rrset(&domain, DnsRecordType::A, 600, vec![], &origin)
            .await
            .expect("set_rrset empty");
    }
}
