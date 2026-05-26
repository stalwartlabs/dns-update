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
        DnsRecord, DnsRecordType, Error, MXRecord, TLSARecord, TlsaCertUsage, TlsaMatching,
        TlsaSelector, providers::infomaniak::InfomaniakProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> InfomaniakProvider {
        InfomaniakProvider::new("test-token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    fn mock_list(server: &mut ServerGuard, domain: &str, body: serde_json::Value) -> Mock {
        server
            .mock("GET", format!("/2/zones/{domain}/records").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    fn ok_envelope() -> &'static str {
        r#"{"result":"success","data":null}"#
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[]}),
        );

        let create_1 = server
            .mock("POST", "/2/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "source": "host",
                "target": "1.1.1.1",
                "type": "A",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(ok_envelope())
            .create();
        let create_2 = server
            .mock("POST", "/2/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "source": "host",
                "target": "2.2.2.2",
                "type": "A",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(ok_envelope())
            .create();

        let provider = setup_provider(server.url());
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
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create_1.assert();
        create_2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let _list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[
                {"id":42,"source":"host","type":"A","target":"1.1.1.1"}
            ]}),
        );
        let _no_post = server
            .mock("POST", "/2/zones/example.com/records")
            .expect(0)
            .create();
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex("^/2/zones/example.com/records/".into()),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_keeps_matching() {
        let mut server = mockito::Server::new_async().await;
        let _list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[
                {"id":42,"source":"host","type":"A","target":"1.1.1.1"},
                {"id":43,"source":"host","type":"A","target":"9.9.9.9"}
            ]}),
        );

        let delete_stale = server
            .mock("DELETE", "/2/zones/example.com/records/43")
            .with_status(200)
            .with_body(ok_envelope())
            .create();
        let create_new = server
            .mock("POST", "/2/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "source": "host",
                "target": "8.8.8.8",
                "type": "A",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(ok_envelope())
            .create();

        let provider = setup_provider(server.url());
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
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_records_deletes_only_matching_type() {
        let mut server = mockito::Server::new_async().await;
        let _list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[
                {"id":42,"source":"host","type":"A","target":"1.1.1.1"},
                {"id":43,"source":"host","type":"A","target":"2.2.2.2"},
                {"id":44,"source":"host","type":"TXT","target":"\"keep-me\""}
            ]}),
        );

        let del1 = server
            .mock("DELETE", "/2/zones/example.com/records/42")
            .with_status(200)
            .with_body(ok_envelope())
            .create();
        let del2 = server
            .mock("DELETE", "/2/zones/example.com/records/43")
            .with_status(200)
            .with_body(ok_envelope())
            .create();
        let _no_txt_delete = server
            .mock("DELETE", "/2/zones/example.com/records/44")
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        del1.assert();
        del2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let _list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[
                {"id":42,"source":"shared","type":"TXT","target":"\"do-not-touch\""},
                {"id":43,"source":"other","type":"A","target":"4.4.4.4"}
            ]}),
        );
        let _no_txt_delete = server
            .mock("DELETE", "/2/zones/example.com/records/42")
            .expect(0)
            .create();
        let _no_other_a_delete = server
            .mock("DELETE", "/2/zones/example.com/records/43")
            .expect(0)
            .create();

        let create = server
            .mock("POST", "/2/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "source": "shared",
                "target": "1.1.1.1",
                "type": "A",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(ok_envelope())
            .create();

        let provider = setup_provider(server.url());
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
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_apex_uses_empty_source() {
        let mut server = mockito::Server::new_async().await;
        let _list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[]}),
        );

        let create = server
            .mock("POST", "/2/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "source": "",
                "target": "mail.example.com.",
                "type": "MX",
                "ttl": 3600,
                "priority": 10,
            })))
            .with_status(200)
            .with_body(ok_envelope())
            .create();

        let provider = setup_provider(server.url());
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
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_priority_differentiates_records() {
        let mut server = mockito::Server::new_async().await;
        let _list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[
                {"id":42,"source":"","type":"MX","target":"mx1.example.com.","priority":10}
            ]}),
        );

        let create_backup = server
            .mock("POST", "/2/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "source": "",
                "target": "mx2.example.com.",
                "type": "MX",
                "ttl": 3600,
                "priority": 20,
            })))
            .with_status(200)
            .with_body(ok_envelope())
            .create();
        let _no_primary_delete = server
            .mock("DELETE", "/2/zones/example.com/records/42")
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
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
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        create_backup.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_input_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
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
    async fn test_add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let _list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[
                {"id":42,"source":"_acme","type":"TXT","target":"\"existing\""}
            ]}),
        );

        let create_new = server
            .mock("POST", "/2/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "source": "_acme",
                "target": "\"new-token\"",
                "type": "TXT",
                "ttl": 60,
            })))
            .with_status(200)
            .with_body(ok_envelope())
            .create();

        let provider = setup_provider(server.url());
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
        create_new.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_input_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let _no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let _list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[
                {"id":42,"source":"_acme","type":"TXT","target":"\"keep-me\""},
                {"id":43,"source":"_acme","type":"TXT","target":"\"drop-me\""}
            ]}),
        );

        let delete = server
            .mock("DELETE", "/2/zones/example.com/records/43")
            .with_status(200)
            .with_body(ok_envelope())
            .create();
        let _no_keep_delete = server
            .mock("DELETE", "/2/zones/example.com/records/42")
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop-me".to_string())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_noop_when_values_absent() {
        let mut server = mockito::Server::new_async().await;
        let _list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[
                {"id":42,"source":"host","type":"A","target":"1.1.1.1"}
            ]}),
        );
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex("^/2/zones/example.com/records/".into()),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_returns_api_error() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
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
    async fn test_set_rrset_tlsa_is_created() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[]}),
        );

        let create = server
            .mock("POST", "/2/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "source": "host",
                "target": "3 1 1 00",
                "type": "TLSA",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(ok_envelope())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::TLSA,
                300,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0x00],
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_tlsa_skips_existing_value() {
        let mut server = mockito::Server::new_async().await;

        let _list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[
                {"id":42,"source":"_25._tcp.mail","type":"TLSA","target":"3 1 1 00"}
            ]}),
        );

        let _no_post = server
            .mock("POST", "/2/zones/example.com/records")
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0x00],
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_tlsa_creates_missing_value() {
        let mut server = mockito::Server::new_async().await;

        let _list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[
                {"id":42,"source":"_25._tcp.mail","type":"TLSA","target":"3 1 1 00"}
            ]}),
        );

        let create = server
            .mock("POST", "/2/zones/example.com/records")
            .match_body(Matcher::Json(json!({
                "source": "_25._tcp.mail",
                "target": "3 1 1 abcd",
                "type": "TLSA",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(ok_envelope())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "_25._tcp.mail.example.com",
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
                        cert_usage: TlsaCertUsage::DaneEe,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xab, 0xcd],
                    }),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        create.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_tlsa_value() {
        let mut server = mockito::Server::new_async().await;

        let _list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[
                {"id":42,"source":"_25._tcp.mail","type":"TLSA","target":"3 1 1 00"},
                {"id":43,"source":"_25._tcp.mail","type":"TLSA","target":"3 1 1 abcd"}
            ]}),
        );

        let delete = server
            .mock("DELETE", "/2/zones/example.com/records/43")
            .with_status(200)
            .with_body(ok_envelope())
            .create();

        let _no_keep_delete = server
            .mock("DELETE", "/2/zones/example.com/records/42")
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xab, 0xcd],
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_txt_with_same_owner() {
        let mut server = mockito::Server::new_async().await;

        let _list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[
                {"id":42,"source":"_acme","type":"TXT","target":"\"keep-me\""},
                {"id":43,"source":"_acme","type":"TXT","target":"\"drop-me\""},
                {"id":44,"source":"_acme","type":"TXT","target":"\"also-keep-me\""}
            ]}),
        );

        let delete = server
            .mock("DELETE", "/2/zones/example.com/records/43")
            .with_status(200)
            .with_body(ok_envelope())
            .create();

        let _no_keep_delete = server
            .mock("DELETE", "/2/zones/example.com/records/42")
            .expect(0)
            .create();

        let _no_also_keep_delete = server
            .mock("DELETE", "/2/zones/example.com/records/44")
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop-me".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_filters_by_type_and_source() {
        let mut server = mockito::Server::new_async().await;
        let _list = mock_list(
            &mut server,
            "example.com",
            json!({"result":"success","data":[
                {"id":42,"source":"host","type":"A","target":"1.1.1.1"},
                {"id":43,"source":"host","type":"A","target":"2.2.2.2"},
                {"id":44,"source":"host","type":"TXT","target":"\"hello\""},
                {"id":45,"source":"other","type":"A","target":"9.9.9.9"}
            ]}),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await;
        let records = result.expect("list_rrset");
        assert_eq!(records.len(), 2);
        let mut targets: Vec<String> = records
            .into_iter()
            .map(|r| match r {
                DnsRecord::A(addr) => addr.to_string(),
                other => panic!("unexpected record: {other:?}"),
            })
            .collect();
        targets.sort();
        assert_eq!(targets, vec!["1.1.1.1", "2.2.2.2"]);
    }

    #[tokio::test]
    async fn test_set_rrset_long_txt_diffs_against_chunked_existing() {
        let mut server = mockito::Server::new_async().await;
        let long_value: String = "v=DKIM1;k=rsa;p=".to_string() + &"A".repeat(300);

        let mut wire = String::new();
        let mut current_bytes: usize = 0;
        wire.push('"');
        for ch in long_value.chars() {
            let ch_len = ch.len_utf8();
            if current_bytes > 0 && current_bytes + ch_len > 255 {
                wire.push('"');
                wire.push(' ');
                wire.push('"');
                current_bytes = 0;
            }
            wire.push(ch);
            current_bytes += ch_len;
        }
        wire.push('"');
        let wire_for_response = wire.replace('"', "\\\"");

        let _list = mock_list(
            &mut server,
            "example.com",
            serde_json::from_str::<serde_json::Value>(&format!(
                r#"{{"result":"success","data":[
                    {{"id":42,"source":"selector._domainkey","type":"TXT","target":"{wire_for_response}"}}
                ]}}"#
            ))
            .unwrap(),
        );
        let _no_post = server
            .mock("POST", "/2/zones/example.com/records")
            .expect(0)
            .create();
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex("^/2/zones/example.com/records/".into()),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "selector._domainkey.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(long_value)],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
    }

    fn integration_env() -> (String, String, String) {
        let token = std::env::var("INFOMANIAK_ACCESS_TOKEN").unwrap_or_default();
        let origin = std::env::var("INFOMANIAK_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("INFOMANIAK_FQDN").unwrap_or_default();

        assert!(!token.is_empty(), "Set INFOMANIAK_ACCESS_TOKEN");
        assert!(!origin.is_empty(), "Set INFOMANIAK_ORIGIN");
        assert!(!fqdn.is_empty(), "Set INFOMANIAK_FQDN");

        (token, origin, fqdn)
    }

    fn integration_provider() -> (InfomaniakProvider, String, String) {
        let (token, origin, fqdn) = integration_env();
        (
            InfomaniakProvider::new(token, Some(Duration::from_secs(30))),
            origin,
            fqdn,
        )
    }

    async fn cleanup_rrset(
        provider: &InfomaniakProvider,
        fqdn: &str,
        record_type: DnsRecordType,
        origin: &str,
    ) {
        let _ = provider
            .set_rrset(fqdn, record_type, 300, vec![], origin)
            .await;
    }

    #[tokio::test]
    #[ignore = "Requires INFOMANIAK_ACCESS_TOKEN, INFOMANIAK_ORIGIN, INFOMANIAK_FQDN env vars"]
    async fn integration_test_a_aaaa_cname_ns_mx_txt_srv() {
        let (provider, origin, base_fqdn) = integration_provider();

        let a_name = format!("it-a.{base_fqdn}");
        let aaaa_name = format!("it-aaaa.{base_fqdn}");
        let cname_name = format!("it-cname.{base_fqdn}");
        let ns_name = format!("it-ns.{base_fqdn}");
        let mx_name = format!("it-mx.{base_fqdn}");
        let txt_name = format!("it-txt.{base_fqdn}");
        let srv_name = format!("_sip._tcp.it-srv.{base_fqdn}");

        cleanup_rrset(&provider, &a_name, DnsRecordType::A, &origin).await;
        cleanup_rrset(&provider, &aaaa_name, DnsRecordType::AAAA, &origin).await;
        cleanup_rrset(&provider, &cname_name, DnsRecordType::CNAME, &origin).await;
        cleanup_rrset(&provider, &ns_name, DnsRecordType::NS, &origin).await;
        cleanup_rrset(&provider, &mx_name, DnsRecordType::MX, &origin).await;
        cleanup_rrset(&provider, &txt_name, DnsRecordType::TXT, &origin).await;
        cleanup_rrset(&provider, &srv_name, DnsRecordType::SRV, &origin).await;

        provider
            .set_rrset(
                a_name.as_str(),
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                origin.as_str(),
            )
            .await
            .expect("set A");

        provider
            .set_rrset(
                a_name.as_str(),
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("8.8.8.8".parse().unwrap())],
                origin.as_str(),
            )
            .await
            .expect("update A");

        let a_records = provider
            .list_rrset(a_name.as_str(), DnsRecordType::A, origin.as_str())
            .await
            .expect("list A");
        assert_eq!(a_records, vec![DnsRecord::A("8.8.8.8".parse().unwrap())]);

        provider
            .set_rrset(
                aaaa_name.as_str(),
                DnsRecordType::AAAA,
                300,
                vec![DnsRecord::AAAA("2001:4860:4860::8888".parse().unwrap())],
                origin.as_str(),
            )
            .await
            .expect("set AAAA");

        provider
            .set_rrset(
                cname_name.as_str(),
                DnsRecordType::CNAME,
                300,
                vec![DnsRecord::CNAME(format!("target.{origin}"))],
                origin.as_str(),
            )
            .await
            .expect("set CNAME");

        provider
            .set_rrset(
                ns_name.as_str(),
                DnsRecordType::NS,
                300,
                vec![DnsRecord::NS(format!("ns1.{origin}"))],
                origin.as_str(),
            )
            .await
            .expect("set NS");

        provider
            .set_rrset(
                mx_name.as_str(),
                DnsRecordType::MX,
                300,
                vec![DnsRecord::MX(MXRecord {
                    exchange: format!("mail.{origin}"),
                    priority: 10,
                })],
                origin.as_str(),
            )
            .await
            .expect("set MX");

        provider
            .set_rrset(
                txt_name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![
                    DnsRecord::TXT("first-token".to_string()),
                    DnsRecord::TXT("second-token".to_string()),
                ],
                origin.as_str(),
            )
            .await
            .expect("set TXT");

        provider
            .remove_from_rrset(
                txt_name.as_str(),
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("first-token".to_string())],
                origin.as_str(),
            )
            .await
            .expect("remove one TXT");

        let txt_records = provider
            .list_rrset(txt_name.as_str(), DnsRecordType::TXT, origin.as_str())
            .await
            .expect("list TXT");
        assert_eq!(
            txt_records,
            vec![DnsRecord::TXT("second-token".to_string())]
        );

        provider
            .set_rrset(
                srv_name.as_str(),
                DnsRecordType::SRV,
                300,
                vec![DnsRecord::SRV(crate::SRVRecord {
                    priority: 10,
                    weight: 20,
                    port: 5060,
                    target: format!("sip.{origin}"),
                })],
                origin.as_str(),
            )
            .await
            .expect("set SRV");

        cleanup_rrset(&provider, &a_name, DnsRecordType::A, &origin).await;
        cleanup_rrset(&provider, &aaaa_name, DnsRecordType::AAAA, &origin).await;
        cleanup_rrset(&provider, &cname_name, DnsRecordType::CNAME, &origin).await;
        cleanup_rrset(&provider, &ns_name, DnsRecordType::NS, &origin).await;
        cleanup_rrset(&provider, &mx_name, DnsRecordType::MX, &origin).await;
        cleanup_rrset(&provider, &txt_name, DnsRecordType::TXT, &origin).await;
        cleanup_rrset(&provider, &srv_name, DnsRecordType::SRV, &origin).await;
    }

    #[tokio::test]
    #[ignore = "Requires INFOMANIAK_ACCESS_TOKEN, INFOMANIAK_ORIGIN, INFOMANIAK_FQDN env vars"]
    async fn integration_test_tlsa_create_update_delete() {
        let (provider, origin, base_fqdn) = integration_provider();
        let name = format!("_443._tcp.it-tlsa.{base_fqdn}");

        cleanup_rrset(&provider, &name, DnsRecordType::TLSA, &origin).await;

        let first = DnsRecord::TLSA(TLSARecord {
            cert_usage: TlsaCertUsage::DaneEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            cert_data: (0xA0..=0xBF).collect(),
        });

        let second = DnsRecord::TLSA(TLSARecord {
            cert_usage: TlsaCertUsage::DaneEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            cert_data: (0xC0..=0xDF).collect(),
        });

        provider
            .set_rrset(
                name.as_str(),
                DnsRecordType::TLSA,
                300,
                vec![first.clone()],
                origin.as_str(),
            )
            .await
            .expect("set TLSA");

        provider
            .add_to_rrset(
                name.as_str(),
                DnsRecordType::TLSA,
                300,
                vec![first.clone(), second.clone()],
                origin.as_str(),
            )
            .await
            .expect("add TLSA");

        let records = provider
            .list_rrset(name.as_str(), DnsRecordType::TLSA, origin.as_str())
            .await
            .expect("list TLSA");
        assert!(records.contains(&first));
        assert!(records.contains(&second));

        provider
            .remove_from_rrset(
                name.as_str(),
                DnsRecordType::TLSA,
                vec![first.clone()],
                origin.as_str(),
            )
            .await
            .expect("remove one TLSA");

        let records = provider
            .list_rrset(name.as_str(), DnsRecordType::TLSA, origin.as_str())
            .await
            .expect("list TLSA after remove");
        assert!(!records.contains(&first));
        assert!(records.contains(&second));

        cleanup_rrset(&provider, &name, DnsRecordType::TLSA, &origin).await;

        let records = provider
            .list_rrset(name.as_str(), DnsRecordType::TLSA, origin.as_str())
            .await
            .expect("list TLSA after cleanup");
        assert!(records.is_empty());
    }

    #[tokio::test]
    #[ignore = "Requires INFOMANIAK_ACCESS_TOKEN, INFOMANIAK_ORIGIN, INFOMANIAK_FQDN env vars"]
    async fn integration_test_dkim_rsa_txt_create_update_delete() {
        let (provider, origin, base_fqdn) = integration_provider();
        let name = format!("selector._domainkey.it-dkim-rsa.{base_fqdn}");

        cleanup_rrset(&provider, &name, DnsRecordType::TXT, &origin).await;

        let first = "v=DKIM1;k=rsa;p=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/wABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJico".to_string();
        let second = "v=DKIM1;k=rsa;p=KSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1A=".to_string();

        provider
            .set_rrset(
                name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(first.clone())],
                origin.as_str(),
            )
            .await
            .expect("set DKIM TXT");

        provider
            .set_rrset(
                name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(second.clone())],
                origin.as_str(),
            )
            .await
            .expect("update DKIM TXT");

        let records = provider
            .list_rrset(name.as_str(), DnsRecordType::TXT, origin.as_str())
            .await
            .expect("list DKIM TXT");
        assert_eq!(records, vec![DnsRecord::TXT(second)]);

        cleanup_rrset(&provider, &name, DnsRecordType::TXT, &origin).await;

        let records = provider
            .list_rrset(name.as_str(), DnsRecordType::TXT, origin.as_str())
            .await
            .expect("list DKIM TXT after cleanup");
        assert!(records.is_empty());
    }

    #[tokio::test]
    #[ignore = "Requires INFOMANIAK_ACCESS_TOKEN, INFOMANIAK_ORIGIN, INFOMANIAK_FQDN env vars"]
    async fn integration_test_dkim_ed25519_txt_create_update_delete() {
        let (provider, origin, base_fqdn) = integration_provider();
        let name = format!("selector._domainkey.it-dkim-ed25519.{base_fqdn}");

        cleanup_rrset(&provider, &name, DnsRecordType::TXT, &origin).await;

        let first = "v=DKIM1;k=ed25519;p=oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8=".to_string();
        let second = "v=DKIM1;k=ed25519;p=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_string();

        provider
            .set_rrset(
                name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(first.clone())],
                origin.as_str(),
            )
            .await
            .expect("set DKIM TXT");

        provider
            .set_rrset(
                name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(second.clone())],
                origin.as_str(),
            )
            .await
            .expect("update DKIM TXT");

        let records = provider
            .list_rrset(name.as_str(), DnsRecordType::TXT, origin.as_str())
            .await
            .expect("list DKIM TXT");
        assert_eq!(records, vec![DnsRecord::TXT(second)]);

        cleanup_rrset(&provider, &name, DnsRecordType::TXT, &origin).await;

        let records = provider
            .list_rrset(name.as_str(), DnsRecordType::TXT, origin.as_str())
            .await
            .expect("list DKIM TXT after cleanup");
        assert!(records.is_empty());
    }

    #[tokio::test]
    #[ignore = "Requires INFOMANIAK_ACCESS_TOKEN, INFOMANIAK_ORIGIN, INFOMANIAK_FQDN env vars"]
    async fn integration_test_caa_create_update_delete() {
        let (provider, origin, base_fqdn) = integration_provider();
        let name = format!("it-caa.{base_fqdn}");

        cleanup_rrset(&provider, &name, DnsRecordType::CAA, &origin).await;

        let first = DnsRecord::CAA(crate::CAARecord::Issue {
            issuer_critical: false,
            name: Some("letsencrypt.org".to_string()),
            options: vec![],
        });

        let second = DnsRecord::CAA(crate::CAARecord::IssueWild {
            issuer_critical: false,
            name: Some("digicert.com".to_string()),
            options: vec![],
        });

        provider
            .set_rrset(
                name.as_str(),
                DnsRecordType::CAA,
                300,
                vec![first.clone()],
                origin.as_str(),
            )
            .await
            .expect("set CAA");

        provider
            .set_rrset(
                name.as_str(),
                DnsRecordType::CAA,
                300,
                vec![second.clone()],
                origin.as_str(),
            )
            .await
            .expect("update CAA");

        let records = provider
            .list_rrset(name.as_str(), DnsRecordType::CAA, origin.as_str())
            .await
            .expect("list CAA");
        assert_eq!(records, vec![second]);

        cleanup_rrset(&provider, &name, DnsRecordType::CAA, &origin).await;

        let records = provider
            .list_rrset(name.as_str(), DnsRecordType::CAA, origin.as_str())
            .await
            .expect("list CAA after cleanup");
        assert!(records.is_empty());
    }
}
