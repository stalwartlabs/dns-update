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

    fn mock_domain_lookup(server: &mut ServerGuard, domain: &str, id: u64) -> Mock {
        server
            .mock("GET", "/1/product")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("service_name".into(), "domain".into()),
                Matcher::UrlEncoded("customer_name".into(), domain.into()),
            ]))
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"result":"success","data":[{{"id":{id},"customer_name":"{domain}"}}]}}"#
            ))
            .create()
    }

    fn mock_list(server: &mut ServerGuard, id: u64, body: serde_json::Value) -> Mock {
        server
            .mock("GET", format!("/1/domain/{id}/dns/record").as_str())
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
        let domain = mock_domain_lookup(&mut server, "example.com", 42);
        let list = mock_list(&mut server, 42, json!({"result":"success","data":[]}));

        let create_1 = server
            .mock("POST", "/1/domain/42/dns/record")
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
            .mock("POST", "/1/domain/42/dns/record")
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
        domain.assert();
        list.assert();
        create_1.assert();
        create_2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let _domain = mock_domain_lookup(&mut server, "example.com", 42);
        let _list = mock_list(
            &mut server,
            42,
            json!({"result":"success","data":[
                {"id":"rec-1","source":"host","type":"A","target":"1.1.1.1"}
            ]}),
        );
        let _no_post = server
            .mock("POST", "/1/domain/42/dns/record")
            .expect(0)
            .create();
        let _no_delete = server
            .mock("DELETE", Matcher::Regex("^/1/domain/42/dns/record/".into()))
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
        let _domain = mock_domain_lookup(&mut server, "example.com", 42);
        let _list = mock_list(
            &mut server,
            42,
            json!({"result":"success","data":[
                {"id":"rec-keep","source":"host","type":"A","target":"1.1.1.1"},
                {"id":"rec-stale","source":"host","type":"A","target":"9.9.9.9"}
            ]}),
        );

        let delete_stale = server
            .mock("DELETE", "/1/domain/42/dns/record/rec-stale")
            .with_status(200)
            .with_body(ok_envelope())
            .create();
        let create_new = server
            .mock("POST", "/1/domain/42/dns/record")
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
        let _domain = mock_domain_lookup(&mut server, "example.com", 42);
        let _list = mock_list(
            &mut server,
            42,
            json!({"result":"success","data":[
                {"id":"rec-a-1","source":"host","type":"A","target":"1.1.1.1"},
                {"id":"rec-a-2","source":"host","type":"A","target":"2.2.2.2"},
                {"id":"rec-txt","source":"host","type":"TXT","target":"\"keep-me\""}
            ]}),
        );

        let del1 = server
            .mock("DELETE", "/1/domain/42/dns/record/rec-a-1")
            .with_status(200)
            .with_body(ok_envelope())
            .create();
        let del2 = server
            .mock("DELETE", "/1/domain/42/dns/record/rec-a-2")
            .with_status(200)
            .with_body(ok_envelope())
            .create();
        let _no_txt_delete = server
            .mock("DELETE", "/1/domain/42/dns/record/rec-txt")
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
        let _domain = mock_domain_lookup(&mut server, "example.com", 42);
        let _list = mock_list(
            &mut server,
            42,
            json!({"result":"success","data":[
                {"id":"rec-txt","source":"shared","type":"TXT","target":"\"do-not-touch\""},
                {"id":"rec-other-a","source":"other","type":"A","target":"4.4.4.4"}
            ]}),
        );
        let _no_txt_delete = server
            .mock("DELETE", "/1/domain/42/dns/record/rec-txt")
            .expect(0)
            .create();
        let _no_other_a_delete = server
            .mock("DELETE", "/1/domain/42/dns/record/rec-other-a")
            .expect(0)
            .create();

        let create = server
            .mock("POST", "/1/domain/42/dns/record")
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
        let _domain = mock_domain_lookup(&mut server, "example.com", 42);
        let _list = mock_list(&mut server, 42, json!({"result":"success","data":[]}));

        let create = server
            .mock("POST", "/1/domain/42/dns/record")
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
        let _domain = mock_domain_lookup(&mut server, "example.com", 42);
        let _list = mock_list(
            &mut server,
            42,
            json!({"result":"success","data":[
                {"id":"rec-mx1","source":"","type":"MX","target":"mx1.example.com.","priority":10}
            ]}),
        );

        let create_backup = server
            .mock("POST", "/1/domain/42/dns/record")
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
            .mock("DELETE", "/1/domain/42/dns/record/rec-mx1")
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
        let _domain = mock_domain_lookup(&mut server, "example.com", 42);
        let _list = mock_list(
            &mut server,
            42,
            json!({"result":"success","data":[
                {"id":"rec-old","source":"_acme","type":"TXT","target":"\"existing\""}
            ]}),
        );

        let create_new = server
            .mock("POST", "/1/domain/42/dns/record")
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
        let _domain = mock_domain_lookup(&mut server, "example.com", 42);
        let _list = mock_list(
            &mut server,
            42,
            json!({"result":"success","data":[
                {"id":"rec-keep","source":"_acme","type":"TXT","target":"\"keep-me\""},
                {"id":"rec-drop","source":"_acme","type":"TXT","target":"\"drop-me\""}
            ]}),
        );

        let delete = server
            .mock("DELETE", "/1/domain/42/dns/record/rec-drop")
            .with_status(200)
            .with_body(ok_envelope())
            .create();
        let _no_keep_delete = server
            .mock("DELETE", "/1/domain/42/dns/record/rec-keep")
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
        let _domain = mock_domain_lookup(&mut server, "example.com", 42);
        let _list = mock_list(
            &mut server,
            42,
            json!({"result":"success","data":[
                {"id":"rec-keep","source":"host","type":"A","target":"1.1.1.1"}
            ]}),
        );
        let _no_delete = server
            .mock("DELETE", Matcher::Regex("^/1/domain/42/dns/record/".into()))
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
    async fn test_set_rrset_tlsa_is_rejected() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

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
        assert!(
            matches!(result, Err(Error::Api(ref m)) if m.contains("TLSA")),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_list_rrset_filters_by_type_and_source() {
        let mut server = mockito::Server::new_async().await;
        let _domain = mock_domain_lookup(&mut server, "example.com", 42);
        let _list = mock_list(
            &mut server,
            42,
            json!({"result":"success","data":[
                {"id":"rec-a-1","source":"host","type":"A","target":"1.1.1.1"},
                {"id":"rec-a-2","source":"host","type":"A","target":"2.2.2.2"},
                {"id":"rec-txt","source":"host","type":"TXT","target":"\"hello\""},
                {"id":"rec-other","source":"other","type":"A","target":"9.9.9.9"}
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
        let _domain = mock_domain_lookup(&mut server, "example.com", 42);
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
            42,
            serde_json::from_str::<serde_json::Value>(&format!(
                r#"{{"result":"success","data":[
                    {{"id":"rec-dkim","source":"selector._domainkey","type":"TXT","target":"{wire_for_response}"}}
                ]}}"#
            ))
            .unwrap(),
        );
        let _no_post = server
            .mock("POST", "/1/domain/42/dns/record")
            .expect(0)
            .create();
        let _no_delete = server
            .mock("DELETE", Matcher::Regex("^/1/domain/42/dns/record/".into()))
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

    #[tokio::test]
    #[ignore = "Requires INFOMANIAK_ACCESS_TOKEN, INFOMANIAK_ORIGIN, INFOMANIAK_FQDN env vars"]
    async fn integration_test() {
        let token = std::env::var("INFOMANIAK_ACCESS_TOKEN").unwrap_or_default();
        let origin = std::env::var("INFOMANIAK_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("INFOMANIAK_FQDN").unwrap_or_default();
        assert!(!token.is_empty(), "Set INFOMANIAK_ACCESS_TOKEN");
        assert!(!origin.is_empty(), "Set INFOMANIAK_ORIGIN");
        assert!(!fqdn.is_empty(), "Set INFOMANIAK_FQDN");

        let provider = InfomaniakProvider::new(token, Some(Duration::from_secs(30)));

        provider
            .set_rrset(
                fqdn.as_str(),
                DnsRecordType::A,
                300,
                vec![DnsRecord::A([1, 1, 1, 1].into())],
                origin.as_str(),
            )
            .await
            .expect("set_rrset A");

        provider
            .set_rrset(
                fqdn.as_str(),
                DnsRecordType::A,
                300,
                vec![],
                origin.as_str(),
            )
            .await
            .expect("set_rrset empty cleanup");
    }
}
