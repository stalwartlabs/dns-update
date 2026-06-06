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
        DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, TLSARecord, TlsaCertUsage,
        TlsaMatching, TlsaSelector, providers::inwx::InwxProvider,
    };
    use serde_json::{Value, json};
    use std::time::Duration;

    fn setup(server_url: &str) -> InwxProvider {
        InwxProvider::new("user", "pass", false, Some(Duration::from_secs(2)))
            .expect("provider")
            .with_endpoint(server_url)
            .with_cached_session("inwx-session=abcd")
    }

    fn json_match(expected: serde_json::Value) -> mockito::Matcher {
        mockito::Matcher::Json(expected)
    }

    fn match_method(name: &str) -> mockito::Matcher {
        let pattern = format!(r#""method"\s*:\s*"{name}""#);
        mockito::Matcher::Regex(pattern)
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_inwx("user", "pass", false, Some(Duration::from_secs(1)));
        assert!(matches!(updater, Ok(DnsUpdater::Inwx(..))));
    }

    #[tokio::test]
    async fn set_rrset_creates_when_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.info",
                "params": {
                    "domain": "example.com",
                    "name": "fresh.example.com",
                    "type": "A"
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"record":[]}}"#)
            .create();

        let create1 = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.createRecord",
                "params": {
                    "domain": "example.com",
                    "name": "fresh.example.com",
                    "type": "A",
                    "content": "1.1.1.1",
                    "ttl": 300
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"id":11}}"#)
            .create();

        let create2 = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.createRecord",
                "params": {
                    "domain": "example.com",
                    "name": "fresh.example.com",
                    "type": "A",
                    "content": "8.8.8.8",
                    "ttl": 300
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"id":12}}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .set_rrset(
                "fresh.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("8.8.8.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{result:?}");
        list.assert();
        create1.assert();
        create2.assert();
    }

    #[tokio::test]
    async fn set_rrset_is_noop_when_matches_existing() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.info"))
            .with_status(200)
            .with_body(
                r#"{"code":1000,"resData":{"record":[
                    {"id":21,"name":"host.example.com","type":"A","content":"1.1.1.1"}
                ]}}"#,
            )
            .create();
        let no_create = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.createRecord"))
            .expect(0)
            .create();
        let no_delete = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.deleteRecord"))
            .expect(0)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        list.assert();
        no_create.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn set_rrset_deletes_extras_and_creates_new() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.info"))
            .with_status(200)
            .with_body(
                r#"{"code":1000,"resData":{"record":[
                    {"id":31,"name":"host.example.com","type":"A","content":"1.1.1.1"},
                    {"id":32,"name":"host.example.com","type":"A","content":"9.9.9.9"}
                ]}}"#,
            )
            .create();

        let delete_stale = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.deleteRecord",
                "params": {"id": "32"}
            })))
            .with_status(200)
            .with_body(r#"{"code":1000}"#)
            .create();

        let create_new = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.createRecord",
                "params": {
                    "domain": "example.com",
                    "name": "host.example.com",
                    "type": "A",
                    "content": "8.8.8.8",
                    "ttl": 300
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"id":33}}"#)
            .create();

        let provider = setup(server.url().as_str());
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

        assert!(result.is_ok(), "{result:?}");
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_records_deletes_all() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.info"))
            .with_status(200)
            .with_body(
                r#"{"code":1000,"resData":{"record":[
                    {"id":41,"name":"gone.example.com","type":"A","content":"1.2.3.4"},
                    {"id":42,"name":"gone.example.com","type":"A","content":"5.6.7.8"}
                ]}}"#,
            )
            .create();

        let delete1 = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.deleteRecord",
                "params": {"id": "41"}
            })))
            .with_status(200)
            .with_body(r#"{"code":1000}"#)
            .create();
        let delete2 = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.deleteRecord",
                "params": {"id": "42"}
            })))
            .with_status(200)
            .with_body(r#"{"code":1000}"#)
            .create();
        let no_create = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.createRecord"))
            .expect(0)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .set_rrset(
                "gone.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{result:?}");
        list.assert();
        delete1.assert();
        delete2.assert();
        no_create.assert();
    }

    #[tokio::test]
    async fn set_rrset_apex_matches_at_sign_echo() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.info",
                "params": {
                    "domain": "example.com",
                    "name": "example.com",
                    "type": "MX"
                }
            })))
            .with_status(200)
            .with_body(
                r#"{"code":1000,"resData":{"record":[
                    {"id":51,"name":"@","type":"MX","content":"mail.example.com.","prio":10}
                ]}}"#,
            )
            .create();
        let no_create = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.createRecord"))
            .expect(0)
            .create();
        let no_delete = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.deleteRecord"))
            .expect(0)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                300,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".into(),
                    priority: 10,
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{result:?}");
        list.assert();
        no_create.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn set_rrset_two_tlsa_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.info"))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"record":[]}}"#)
            .create();

        let create_ee = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.createRecord",
                "params": {
                    "domain": "example.com",
                    "name": "_443._tcp.mail.example.com",
                    "type": "TLSA",
                    "content": "3 1 1 cc",
                    "ttl": 300
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"id":61}}"#)
            .create();
        let create_ta = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.createRecord",
                "params": {
                    "domain": "example.com",
                    "name": "_443._tcp.mail.example.com",
                    "type": "TLSA",
                    "content": "2 1 1 dd",
                    "ttl": 300
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"id":62}}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .set_rrset(
                "_443._tcp.mail.example.com",
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

        assert!(result.is_ok(), "{result:?}");
        list.assert();
        create_ee.assert();
        create_ta.assert();
    }

    #[tokio::test]
    async fn set_rrset_mx_with_two_priorities() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.info"))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"record":[]}}"#)
            .create();

        let primary = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.createRecord",
                "params": {
                    "domain": "example.com",
                    "name": "example.com",
                    "type": "MX",
                    "content": "mx1.example.com.",
                    "ttl": 3600,
                    "prio": 10
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"id":71}}"#)
            .create();
        let backup = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.createRecord",
                "params": {
                    "domain": "example.com",
                    "name": "example.com",
                    "type": "MX",
                    "content": "mx2.example.com.",
                    "ttl": 3600,
                    "prio": 20
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"id":72}}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![
                    DnsRecord::MX(MXRecord {
                        exchange: "mx1.example.com".into(),
                        priority: 10,
                    }),
                    DnsRecord::MX(MXRecord {
                        exchange: "mx2.example.com".into(),
                        priority: 20,
                    }),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{result:?}");
        list.assert();
        primary.assert();
        backup.assert();
    }

    #[tokio::test]
    async fn set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let list_a = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.info",
                "params": {
                    "domain": "example.com",
                    "name": "shared.example.com",
                    "type": "A"
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"record":[]}}"#)
            .create();
        let list_txt_must_not_fire = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.info",
                "params": {
                    "domain": "example.com",
                    "name": "shared.example.com",
                    "type": "TXT"
                }
            })))
            .expect(0)
            .create();

        let create = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.createRecord",
                "params": {
                    "domain": "example.com",
                    "name": "shared.example.com",
                    "type": "A",
                    "content": "1.1.1.1",
                    "ttl": 300
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"id":81}}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .set_rrset(
                "shared.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{result:?}");
        list_a.assert();
        list_txt_must_not_fire.assert();
        create.assert();
    }

    #[tokio::test]
    async fn set_rrset_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup(server.url().as_str());
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
    async fn add_to_rrset_skips_existing() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.info"))
            .with_status(200)
            .with_body(
                r#"{"code":1000,"resData":{"record":[
                    {"id":91,"name":"_acme.example.com","type":"TXT","content":"existing"}
                ]}}"#,
            )
            .create();

        let create_new = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.createRecord",
                "params": {
                    "domain": "example.com",
                    "name": "_acme.example.com",
                    "type": "TXT",
                    "content": "new-token",
                    "ttl": 60
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"id":92}}"#)
            .create();

        let provider = setup(server.url().as_str());
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

        assert!(result.is_ok(), "{result:?}");
        list.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_empty_input_short_circuits() {
        let mut server = mockito::Server::new_async().await;
        let no_call = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Any)
            .expect(0)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        no_call.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_only_matching() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.info"))
            .with_status(200)
            .with_body(
                r#"{"code":1000,"resData":{"record":[
                    {"id":101,"name":"_acme.example.com","type":"TXT","content":"keep-me"},
                    {"id":102,"name":"_acme.example.com","type":"TXT","content":"drop-me"}
                ]}}"#,
            )
            .create();

        let delete = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.deleteRecord",
                "params": {"id": "102"}
            })))
            .with_status(200)
            .with_body(r#"{"code":1000}"#)
            .create();
        let no_other_delete = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.deleteRecord",
                "params": {"id": "101"}
            })))
            .expect(0)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop-me".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{result:?}");
        list.assert();
        delete.assert();
        no_other_delete.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_absent_value_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.info"))
            .with_status(200)
            .with_body(
                r#"{"code":1000,"resData":{"record":[
                    {"id":111,"name":"test.example.com","type":"A","content":"1.1.1.1"}
                ]}}"#,
            )
            .create();
        let no_delete = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.deleteRecord"))
            .expect(0)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{result:?}");
        list.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_input_short_circuits() {
        let mut server = mockito::Server::new_async().await;
        let no_call = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Any)
            .expect(0)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "{result:?}");
        no_call.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_parsed_records() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.info",
                "params": {
                    "domain": "example.com",
                    "name": "example.com",
                    "type": "MX"
                }
            })))
            .with_status(200)
            .with_body(
                r#"{"code":1000,"resData":{"record":[
                    {"id":121,"name":"@","type":"MX","content":"mx1.example.com.","prio":10},
                    {"id":122,"name":"@","type":"MX","content":"mx2.example.com.","prio":20}
                ]}}"#,
            )
            .create();

        let provider = setup(server.url().as_str());
        let records = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .expect("list_rrset");

        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0],
            DnsRecord::MX(MXRecord {
                exchange: "mx1.example.com.".into(),
                priority: 10,
            })
        );
        assert_eq!(
            records[1],
            DnsRecord::MX(MXRecord {
                exchange: "mx2.example.com.".into(),
                priority: 20,
            })
        );
        list.assert();
    }

    #[tokio::test]
    async fn set_rrset_handles_string_record_ids() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("POST", "/")
            .match_body(match_method("nameserver.info"))
            .with_status(200)
            .with_body(
                r#"{"code":1000,"resData":{"record":[
                    {"id":"2377221647","name":"host.example.com","type":"A","content":"9.9.9.9"}
                ]}}"#,
            )
            .create();

        let delete = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.deleteRecord",
                "params": {"id": "2377221647"}
            })))
            .with_status(200)
            .with_body(r#"{"code":1000}"#)
            .create();

        let create = server
            .mock("POST", "/")
            .match_body(json_match(json!({
                "method": "nameserver.createRecord",
                "params": {
                    "domain": "example.com",
                    "name": "host.example.com",
                    "type": "A",
                    "content": "1.1.1.1",
                    "ttl": 300
                }
            })))
            .with_status(200)
            .with_body(r#"{"code":1000,"resData":{"id":"2377221648"}}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{result:?}");
        list.assert();
        delete.assert();
        create.assert();
    }

    #[tokio::test]
    #[ignore = "Requires INWX sandbox account credentials"]
    async fn integration_test() {
        let username = std::env::var("INWX_USERNAME").unwrap_or_default();
        let password = std::env::var("INWX_PASSWORD").unwrap_or_default();
        let domain = std::env::var("INWX_DOMAIN").unwrap_or_default();
        assert!(
            !username.is_empty() && !password.is_empty() && !domain.is_empty(),
            "Set INWX_USERNAME, INWX_PASSWORD and INWX_DOMAIN env vars"
        );
        let provider = InwxProvider::new(&username, &password, true, Some(Duration::from_secs(30)))
            .expect("provider");
        provider
            .set_rrset(
                &format!("test.{domain}"),
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                &domain,
            )
            .await
            .expect("set_rrset");
        provider
            .set_rrset(
                &format!("test.{domain}"),
                DnsRecordType::A,
                3600,
                vec![],
                &domain,
            )
            .await
            .expect("cleanup");
        let _ = Value::Null;
    }
}
