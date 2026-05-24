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
        CAARecord, DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord, TLSARecord, TlsaCertUsage,
        TlsaMatching, TlsaSelector, providers::websupport::WebSupportProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> WebSupportProvider {
        WebSupportProvider::new("api_key", "secret", Some(Duration::from_secs(2)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn services_body() -> &'static str {
        r#"{"items":[{"id":111,"serviceName":"domain","name":"example.com"}],"pager":{"pagesize":500,"items":1}}"#
    }

    fn mock_services(server: &mut ServerGuard) -> Mock {
        server
            .mock("GET", "/v1/user/self/service")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("page".into(), "1".into()),
                Matcher::UrlEncoded("pagesize".into(), "500".into()),
            ]))
            .match_header("authorization", Matcher::Regex("^Basic .+$".into()))
            .match_header("date", Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(services_body())
            .create()
    }

    fn mock_list(server: &mut ServerGuard, body: serde_json::Value) -> Mock {
        server
            .mock("GET", "/v2/service/111/dns/record")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_empty() {
        let mut server = mockito::Server::new_async().await;
        let services = mock_services(&mut server);
        let list = mock_list(&mut server, json!({"data":[]}));

        let create_1 = server
            .mock("POST", "/v2/service/111/dns/record")
            .match_body(Matcher::Json(json!({
                "type": "A",
                "name": "host",
                "content": "1.1.1.1",
                "ttl": 300
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":1}}"#)
            .create();
        let create_2 = server
            .mock("POST", "/v2/service/111/dns/record")
            .match_body(Matcher::Json(json!({
                "type": "A",
                "name": "host",
                "content": "2.2.2.2",
                "ttl": 300
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":2}}"#)
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
        services.assert();
        list.assert();
        create_1.assert();
        create_2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let services = mock_services(&mut server);
        let list = mock_list(
            &mut server,
            json!({"data":[
                {"id":7,"type":"A","name":"host","content":"1.1.1.1"}
            ]}),
        );
        let _no_post = server
            .mock("POST", "/v2/service/111/dns/record")
            .expect(0)
            .create();
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex("^/v2/service/111/dns/record/".into()),
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
        services.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_keeps_matching() {
        let mut server = mockito::Server::new_async().await;
        let services = mock_services(&mut server);
        let list = mock_list(
            &mut server,
            json!({"data":[
                {"id":1,"type":"A","name":"host","content":"1.1.1.1"},
                {"id":2,"type":"A","name":"host","content":"9.9.9.9"}
            ]}),
        );
        let delete_stale = server
            .mock("DELETE", "/v2/service/111/dns/record/2")
            .with_status(200)
            .with_body("{}")
            .create();
        let create_new = server
            .mock("POST", "/v2/service/111/dns/record")
            .match_body(Matcher::Json(json!({
                "type": "A",
                "name": "host",
                "content": "8.8.8.8",
                "ttl": 300
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":3}}"#)
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
        services.assert();
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_records_deletes_all() {
        let mut server = mockito::Server::new_async().await;
        let services = mock_services(&mut server);
        let list = mock_list(
            &mut server,
            json!({"data":[
                {"id":11,"type":"A","name":"gone","content":"1.2.3.4"},
                {"id":12,"type":"A","name":"gone","content":"5.6.7.8"}
            ]}),
        );
        let del_x = server
            .mock("DELETE", "/v2/service/111/dns/record/11")
            .with_status(200)
            .with_body("{}")
            .create();
        let del_y = server
            .mock("DELETE", "/v2/service/111/dns/record/12")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
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
        services.assert();
        list.assert();
        del_x.assert();
        del_y.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let services = mock_services(&mut server);
        let list = mock_list(
            &mut server,
            json!({"data":[
                {"id":50,"type":"A","name":"shared","content":"1.1.1.1"},
                {"id":51,"type":"TXT","name":"shared","content":"do-not-delete-me"},
                {"id":52,"type":"AAAA","name":"shared","content":"2001:db8::1"}
            ]}),
        );
        let no_del_txt = server
            .mock("DELETE", "/v2/service/111/dns/record/51")
            .expect(0)
            .create();
        let no_del_aaaa = server
            .mock("DELETE", "/v2/service/111/dns/record/52")
            .expect(0)
            .create();
        let create_a = server
            .mock("POST", "/v2/service/111/dns/record")
            .match_body(Matcher::PartialJson(json!({
                "type": "A",
                "name": "shared",
                "content": "9.9.9.9"
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":99}}"#)
            .create();
        let del_old_a = server
            .mock("DELETE", "/v2/service/111/dns/record/50")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "shared.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        services.assert();
        list.assert();
        no_del_txt.assert();
        no_del_aaaa.assert();
        create_a.assert();
        del_old_a.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_is_rejected() {
        let mut server = mockito::Server::new_async().await;
        let _services = server.mock("GET", Matcher::Any).expect(0).create();
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not-an-A".into())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_rejected() {
        let mut server = mockito::Server::new_async().await;
        let _no_calls = server.mock("GET", Matcher::Any).expect(0).create();
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
                    cert_data: vec![0xaa],
                })],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("TLSA")),
            "expected TLSA Api error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_input_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "host.example.com",
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
        let services = mock_services(&mut server);
        let list = mock_list(
            &mut server,
            json!({"data":[
                {"id":1,"type":"TXT","name":"_acme","content":"existing"}
            ]}),
        );
        let create_new = server
            .mock("POST", "/v2/service/111/dns/record")
            .match_body(Matcher::Json(json!({
                "type": "TXT",
                "name": "_acme",
                "content": "new-token",
                "ttl": 60
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":2}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                60,
                vec![
                    DnsRecord::TXT("existing".into()),
                    DnsRecord::TXT("new-token".into()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        services.assert();
        list.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_full_noop_when_everything_present() {
        let mut server = mockito::Server::new_async().await;
        let services = mock_services(&mut server);
        let list = mock_list(
            &mut server,
            json!({"data":[
                {"id":1,"type":"A","name":"host","content":"1.1.1.1"},
                {"id":2,"type":"A","name":"host","content":"8.8.8.8"}
            ]}),
        );
        let _no_post = server
            .mock("POST", "/v2/service/111/dns/record")
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
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
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        services.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_input_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset("host.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let services = mock_services(&mut server);
        let list = mock_list(
            &mut server,
            json!({"data":[
                {"id":10,"type":"TXT","name":"_acme","content":"keep-me"},
                {"id":11,"type":"TXT","name":"_acme","content":"drop-me"}
            ]}),
        );
        let del = server
            .mock("DELETE", "/v2/service/111/dns/record/11")
            .with_status(200)
            .with_body("{}")
            .create();
        let _no_other_delete = server
            .mock("DELETE", "/v2/service/111/dns/record/10")
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop-me".into())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        services.assert();
        list.assert();
        del.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_noop_when_values_absent() {
        let mut server = mockito::Server::new_async().await;
        let services = mock_services(&mut server);
        let list = mock_list(
            &mut server,
            json!({"data":[
                {"id":1,"type":"A","name":"host","content":"1.1.1.1"}
            ]}),
        );
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex("^/v2/service/111/dns/record/".into()),
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
        services.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_with_priorities() {
        let mut server = mockito::Server::new_async().await;
        let services = mock_services(&mut server);
        let list = mock_list(&mut server, json!({"data":[]}));
        let primary = server
            .mock("POST", "/v2/service/111/dns/record")
            .match_body(Matcher::Json(json!({
                "type": "MX",
                "name": "",
                "content": "mx1.example.com",
                "ttl": 3600,
                "priority": 10
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":1}}"#)
            .create();
        let backup = server
            .mock("POST", "/v2/service/111/dns/record")
            .match_body(Matcher::Json(json!({
                "type": "MX",
                "name": "",
                "content": "mx2.example.com",
                "ttl": 3600,
                "priority": 20
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":2}}"#)
            .create();

        let provider = setup_provider(server.url());
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
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        services.assert();
        list.assert();
        primary.assert();
        backup.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_sends_full_fields() {
        let mut server = mockito::Server::new_async().await;
        let services = mock_services(&mut server);
        let list = mock_list(&mut server, json!({"data":[]}));
        let create = server
            .mock("POST", "/v2/service/111/dns/record")
            .match_body(Matcher::Json(json!({
                "type": "SRV",
                "name": "_imaps._tcp",
                "content": "mail.example.com",
                "ttl": 300,
                "priority": 10,
                "port": 993,
                "weight": 5
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":1}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_imaps._tcp.example.com",
                DnsRecordType::SRV,
                300,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 993,
                    target: "mail.example.com".into(),
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        services.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_sends_bind_style_string() {
        let mut server = mockito::Server::new_async().await;
        let services = mock_services(&mut server);
        let list = mock_list(&mut server, json!({"data":[]}));
        let create = server
            .mock("POST", "/v2/service/111/dns/record")
            .match_body(Matcher::Json(json!({
                "type": "CAA",
                "name": "",
                "content": "0 issue \"letsencrypt.org\"",
                "ttl": 3600
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":1}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::CAA,
                3600,
                vec![DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".into()),
                    options: vec![],
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        services.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_records() {
        let mut server = mockito::Server::new_async().await;
        let services = mock_services(&mut server);
        let list = mock_list(
            &mut server,
            json!({"data":[
                {"id":1,"type":"A","name":"host","content":"1.1.1.1"},
                {"id":2,"type":"A","name":"host","content":"2.2.2.2"},
                {"id":3,"type":"TXT","name":"host","content":"ignore-me"}
            ]}),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");
        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
        services.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_obtain_service_id_paginates() {
        let mut server = mockito::Server::new_async().await;

        let page_1 = server
            .mock("GET", "/v1/user/self/service")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("page".into(), "1".into()),
                Matcher::UrlEncoded("pagesize".into(), "500".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"items":[{"id":1,"serviceName":"hosting","name":"other.com"}],"pager":{"pagesize":1,"items":2}}"#,
            )
            .create();

        let page_2 = server
            .mock("GET", "/v1/user/self/service")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("page".into(), "2".into()),
                Matcher::UrlEncoded("pagesize".into(), "500".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"items":[{"id":222,"serviceName":"domain","name":"example.com"}],"pager":{"pagesize":1,"items":2}}"#,
            )
            .create();

        let list = server
            .mock("GET", "/v2/service/222/dns/record")
            .with_status(200)
            .with_body(r#"{"data":[]}"#)
            .create();

        let create = server
            .mock("POST", "/v2/service/222/dns/record")
            .with_status(201)
            .with_body(r#"{"data":{"id":1}}"#)
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
        page_1.assert();
        page_2.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    #[ignore = "requires WEBSUPPORT_API_KEY, WEBSUPPORT_SECRET, WEBSUPPORT_DOMAIN env vars"]
    async fn test_live_websupport_roundtrip() {
        let api_key = std::env::var("WEBSUPPORT_API_KEY").expect("WEBSUPPORT_API_KEY");
        let secret = std::env::var("WEBSUPPORT_SECRET").expect("WEBSUPPORT_SECRET");
        let domain = std::env::var("WEBSUPPORT_DOMAIN").expect("WEBSUPPORT_DOMAIN");
        let provider =
            WebSupportProvider::new(api_key, secret, Some(Duration::from_secs(30))).unwrap();
        provider
            .set_rrset(
                format!("dns-update-test.{domain}"),
                DnsRecordType::TXT,
                600,
                vec![DnsRecord::TXT("hello".into())],
                &domain,
            )
            .await
            .unwrap();
        provider
            .set_rrset(
                format!("dns-update-test.{domain}"),
                DnsRecordType::TXT,
                600,
                vec![],
                &domain,
            )
            .await
            .unwrap();
    }
}
