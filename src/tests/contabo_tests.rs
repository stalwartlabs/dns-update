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
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, KeyValue, MXRecord, SRVRecord,
        TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector, providers::contabo::ContaboProvider,
    };
    use mockito::Matcher;
    use serde_json::{Value, json};
    use std::time::Duration;

    const RECORDS_PATH: &str = "/v1/dns/zones/example.com/records";
    const REQUEST_ID: &str =
        "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";

    fn provider(server: &mockito::ServerGuard) -> ContaboProvider {
        ContaboProvider::new(
            "client",
            "client-secret",
            "user@example.com",
            "password",
            Some(Duration::from_secs(5)),
        )
        .unwrap()
        .with_endpoints(server.url(), format!("{}/auth/token", server.url()))
    }

    fn mock_token(server: &mut mockito::ServerGuard) -> mockito::Mock {
        server
            .mock("POST", "/auth/token")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("grant_type".into(), "password".into()),
                Matcher::UrlEncoded("client_id".into(), "client".into()),
                Matcher::UrlEncoded("client_secret".into(), "client-secret".into()),
                Matcher::UrlEncoded("username".into(), "user@example.com".into()),
                Matcher::UrlEncoded("password".into(), "password".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"access_token":"tok","expires_in":300,"token_type":"Bearer"}"#)
            .expect(1)
            .create()
    }

    fn record(id: u64, name: &str, rtype: &str, ttl: u64, data: &str) -> Value {
        json!({
            "tenantId": "INT",
            "customerId": "12345",
            "recordId": id,
            "name": name,
            "type": rtype,
            "ttl": ttl,
            "prio": 0,
            "data": data,
            "port": null,
            "weight": null,
            "flag": null,
            "tag": null
        })
    }

    fn mock_list(server: &mut mockito::ServerGuard, path: &str, records: Value) -> mockito::Mock {
        server
            .mock("GET", path)
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("page".into(), "1".into()),
                Matcher::UrlEncoded("size".into(), "1000".into()),
            ]))
            .match_header("authorization", "Bearer tok")
            .match_header("x-request-id", Matcher::Regex(REQUEST_ID.into()))
            .with_status(200)
            .with_body(
                json!({
                    "_pagination": {"size": 1000, "totalElements": 1, "totalPages": 1, "page": 1},
                    "data": records,
                    "_links": {"self": path}
                })
                .to_string(),
            )
            .create()
    }

    fn mock_create(server: &mut mockito::ServerGuard, body: Value) -> mockito::Mock {
        server
            .mock("POST", RECORDS_PATH)
            .match_header("authorization", "Bearer tok")
            .match_header("content-type", "application/json")
            .match_header("x-request-id", Matcher::Regex(REQUEST_ID.into()))
            .match_body(Matcher::Json(body))
            .with_status(201)
            .with_body(r#"{"data":[{"recordId":99}],"_links":{"self":"x"}}"#)
            .expect(1)
            .create()
    }

    fn mock_delete(server: &mut mockito::ServerGuard, id: u64) -> mockito::Mock {
        server
            .mock("DELETE", format!("{RECORDS_PATH}/{id}").as_str())
            .match_header("authorization", "Bearer tok")
            .match_header("content-type", Matcher::Missing)
            .match_header("x-request-id", Matcher::Regex(REQUEST_ID.into()))
            .with_status(204)
            .expect(1)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_missing() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);
        let list = mock_list(&mut server, RECORDS_PATH, json!([]));
        let first = mock_create(
            &mut server,
            json!({"name": "www", "type": "A", "ttl": 300, "prio": 0, "data": "1.1.1.1"}),
        );
        let second = mock_create(
            &mut server,
            json!({"name": "www", "type": "A", "ttl": 300, "prio": 0, "data": "2.2.2.2"}),
        );

        provider(&server)
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                ],
                "example.com",
            )
            .await
            .unwrap();

        token.assert();
        list.assert();
        first.assert();
        second.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_replaces_existing() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _list = mock_list(
            &mut server,
            RECORDS_PATH,
            json!([
                record(1, "www", "A", 300, "1.1.1.1"),
                record(2, "www.example.com", "A", 300, "3.3.3.3"),
                record(3, "www", "AAAA", 300, "2001:db8::1"),
                record(4, "api", "A", 300, "3.3.3.3"),
            ]),
        );
        let delete = mock_delete(&mut server, 2);
        let create = mock_create(
            &mut server,
            json!({"name": "www", "type": "A", "ttl": 300, "prio": 0, "data": "2.2.2.2"}),
        );

        provider(&server)
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await
            .unwrap();

        delete.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_unchanged_is_noop_and_ttl_change_updates() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _list = mock_list(
            &mut server,
            RECORDS_PATH,
            json!([record(
                7,
                "WWW.Example.com.",
                "CNAME",
                300,
                "Target.example.net."
            )]),
        );
        let update = server
            .mock("PATCH", format!("{RECORDS_PATH}/7").as_str())
            .match_header("content-type", "application/json")
            .match_body(Matcher::Json(json!({
                "type": "CNAME", "ttl": 600, "prio": 0, "data": "target.example.net"
            })))
            .with_status(200)
            .with_body(r#"{"data":[{"recordId":7}]}"#)
            .expect(1)
            .create();
        let create = server.mock("POST", RECORDS_PATH).expect(0).create();
        let delete = server
            .mock("DELETE", Matcher::Regex(format!("^{RECORDS_PATH}/")))
            .expect(0)
            .create();

        let p = provider(&server);
        p.set_rrset(
            "www.example.com",
            DnsRecordType::CNAME,
            300,
            vec![DnsRecord::CNAME("target.example.net.".to_string())],
            "example.com",
        )
        .await
        .unwrap();
        p.set_rrset(
            "www.example.com",
            DnsRecordType::CNAME,
            600,
            vec![DnsRecord::CNAME("target.example.net".to_string())],
            "example.com",
        )
        .await
        .unwrap();

        update.assert();
        create.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_all() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _list = mock_list(
            &mut server,
            RECORDS_PATH,
            json!([
                record(10, "_dmarc", "TXT", 300, "v=DMARC1; p=none"),
                record(11, "_dmarc.example.com", "TXT", 300, "\"old\""),
            ]),
        );
        let first = mock_delete(&mut server, 10);
        let second = mock_delete(&mut server, 11);

        provider(&server)
            .set_rrset(
                "_dmarc.example.com.",
                DnsRecordType::TXT,
                300,
                vec![],
                "example.com.",
            )
            .await
            .unwrap();

        first.assert();
        second.assert();
    }

    #[tokio::test]
    async fn test_apex_names_match_every_form() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _list = mock_list(
            &mut server,
            RECORDS_PATH,
            json!([
                record(1, "", "MX", 300, "mx1.example.com"),
                record(2, "example.com", "MX", 300, "mx2.example.com."),
                record(3, "example.com.", "MX", 300, "mx3.example.com"),
                record(4, "@", "MX", 300, "mx4.example.com"),
                record(5, "mail", "MX", 300, "mx5.example.com"),
            ]),
        );

        let listed = provider(&server)
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .unwrap();
        let exchanges: Vec<String> = listed
            .into_iter()
            .map(|r| match r {
                DnsRecord::MX(mx) => mx.exchange,
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(
            exchanges,
            vec![
                "mx1.example.com",
                "mx2.example.com",
                "mx3.example.com",
                "mx4.example.com"
            ]
        );
    }

    #[tokio::test]
    async fn test_apex_create_uses_zone_name() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _list = mock_list(&mut server, RECORDS_PATH, json!([]));
        let create = mock_create(
            &mut server,
            json!({"name": "example.com", "type": "MX", "ttl": 3600, "prio": 10, "data": "mail.example.com"}),
        );

        provider(&server)
            .add_to_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com.".to_string(),
                    priority: 10,
                })],
                "example.com",
            )
            .await
            .unwrap();

        create.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_present_and_duplicate_values() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _list = mock_list(
            &mut server,
            RECORDS_PATH,
            json!([record(1, "_acme-challenge", "TXT", 60, "\"abc\"")]),
        );
        let create = mock_create(
            &mut server,
            json!({"name": "_acme-challenge", "type": "TXT", "ttl": 60, "prio": 0, "data": "def"}),
        );

        provider(&server)
            .add_to_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                60,
                vec![
                    DnsRecord::TXT("abc".to_string()),
                    DnsRecord::TXT("def".to_string()),
                    DnsRecord::TXT("def".to_string()),
                ],
                "example.com",
            )
            .await
            .unwrap();

        create.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_keeps_others() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _list = mock_list(
            &mut server,
            RECORDS_PATH,
            json!([
                record(1, "_acme-challenge", "TXT", 60, "abc"),
                record(2, "_acme-challenge", "TXT", 60, "def"),
            ]),
        );
        let delete = mock_delete(&mut server, 2);

        provider(&server)
            .remove_from_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                vec![
                    DnsRecord::TXT("def".to_string()),
                    DnsRecord::TXT("missing".to_string()),
                ],
                "example.com",
            )
            .await
            .unwrap();

        delete.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_srv_caa_and_txt() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let mut srv = record(1, "_imaps._tcp", "SRV", 300, "mail.example.com.");
        srv["prio"] = json!(0);
        srv["weight"] = json!(1);
        srv["port"] = json!(993);
        let mut caa = record(2, "", "CAA", 300, "letsencrypt.org");
        caa["flag"] = json!(0);
        caa["tag"] = json!("issue");
        let _list = mock_list(
            &mut server,
            RECORDS_PATH,
            json!([srv, caa, record(3, "", "TXT", 300, "\"v=spf1 \" \"-all\"")]),
        );

        let p = provider(&server);
        assert_eq!(
            p.list_rrset("_imaps._tcp.example.com", DnsRecordType::SRV, "example.com")
                .await
                .unwrap(),
            vec![DnsRecord::SRV(SRVRecord {
                target: "mail.example.com".to_string(),
                priority: 0,
                weight: 1,
                port: 993,
            })]
        );
        assert_eq!(
            p.list_rrset("example.com", DnsRecordType::CAA, "example.com")
                .await
                .unwrap(),
            vec![DnsRecord::CAA(CAARecord::Issue {
                issuer_critical: false,
                name: Some("letsencrypt.org".to_string()),
                options: vec![],
            })]
        );
        assert_eq!(
            p.list_rrset("example.com", DnsRecordType::TXT, "example.com")
                .await
                .unwrap(),
            vec![DnsRecord::TXT("v=spf1 -all".to_string())]
        );
    }

    #[tokio::test]
    async fn test_create_srv_and_caa_bodies() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _list = mock_list(&mut server, RECORDS_PATH, json!([]));
        let srv = mock_create(
            &mut server,
            json!({
                "name": "_submissions._tcp", "type": "SRV", "ttl": 300,
                "prio": 0, "weight": 1, "port": 465, "data": "mail.example.com"
            }),
        );
        let caa = mock_create(
            &mut server,
            json!({
                "name": "example.com", "type": "CAA", "ttl": 300,
                "prio": 0, "flag": 0, "tag": "issue", "data": "letsencrypt.org; validationmethods=dns-01"
            }),
        );

        let p = provider(&server);
        p.set_rrset(
            "_submissions._tcp.example.com",
            DnsRecordType::SRV,
            300,
            vec![DnsRecord::SRV(SRVRecord {
                target: "mail.example.com.".to_string(),
                priority: 0,
                weight: 1,
                port: 465,
            })],
            "example.com",
        )
        .await
        .unwrap();
        p.set_rrset(
            "example.com",
            DnsRecordType::CAA,
            300,
            vec![DnsRecord::CAA(CAARecord::Issue {
                issuer_critical: false,
                name: Some("letsencrypt.org".to_string()),
                options: vec![KeyValue {
                    key: "validationmethods".to_string(),
                    value: "dns-01".to_string(),
                }],
            })],
            "example.com",
        )
        .await
        .unwrap();

        srv.assert();
        caa.assert();
    }

    #[tokio::test]
    async fn test_reads_every_page() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let page = |n: &str, records: Value| {
            json!({
                "_pagination": {"size": 1000, "totalElements": 2, "totalPages": 2, "page": n},
                "data": records
            })
            .to_string()
        };
        let first = server
            .mock("GET", RECORDS_PATH)
            .match_query(Matcher::UrlEncoded("page".into(), "1".into()))
            .with_status(200)
            .with_body(page("1", json!([record(1, "www", "A", 300, "1.1.1.1")])))
            .expect(1)
            .create();
        let second = server
            .mock("GET", RECORDS_PATH)
            .match_query(Matcher::UrlEncoded("page".into(), "2".into()))
            .with_status(200)
            .with_body(page("2", json!([record(2, "www", "A", 300, "2.2.2.2")])))
            .expect(1)
            .create();

        let listed = provider(&server)
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();
        assert_eq!(listed.len(), 2);
        first.assert();
        second.assert();
    }

    #[tokio::test]
    async fn test_zone_lookup_walks_up_labels() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let missing = server
            .mock("GET", "/v1/dns/zones/mail.example.com/records")
            .match_query(Matcher::Any)
            .with_status(404)
            .with_body(r#"{"statusCode":404,"message":"Entry DNS Zone not found by zone name = mail.example.com"}"#)
            .expect(1)
            .create();
        let _list = mock_list(&mut server, RECORDS_PATH, json!([]));
        let create = mock_create(
            &mut server,
            json!({"name": "mail", "type": "A", "ttl": 300, "prio": 0, "data": "1.2.3.4"}),
        );

        provider(&server)
            .set_rrset(
                "mail.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "mail.example.com",
            )
            .await
            .unwrap();

        missing.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_zone_not_found() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _missing = server
            .mock("GET", RECORDS_PATH)
            .match_query(Matcher::Any)
            .with_status(404)
            .with_body(r#"{"statusCode":404,"message":"not found"}"#)
            .create();

        let result = provider(&server)
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "{result:?}");
    }

    #[tokio::test]
    async fn test_token_is_cached_across_calls() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);
        let list = server
            .mock("GET", RECORDS_PATH)
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(r#"{"_pagination":{"totalPages":1},"data":[]}"#)
            .expect(2)
            .create();

        let p = provider(&server);
        for _ in 0..2 {
            p.list_rrset("www.example.com", DnsRecordType::A, "example.com")
                .await
                .unwrap();
        }

        token.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_auth_failure() {
        let mut server = mockito::Server::new_async().await;
        let _auth = server
            .mock("POST", "/auth/token")
            .with_status(401)
            .with_body(r#"{"error":"unauthorized_client"}"#)
            .create();

        let result = provider(&server)
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await;
        assert!(matches!(result, Err(Error::Unauthorized)), "{result:?}");
    }

    #[tokio::test]
    async fn test_rejects_unsupported_types_and_mismatch() {
        let p = ContaboProvider::new("c", "s", "u", "p", None)
            .unwrap()
            .with_endpoints("http://127.0.0.1:1", "http://127.0.0.1:1/token");

        let tlsa = p
            .set_rrset(
                "_25._tcp.example.com",
                DnsRecordType::TLSA,
                60,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xab, 0xcd],
                })],
                "example.com",
            )
            .await;
        assert!(matches!(tlsa, Err(Error::Unsupported(_))), "{tlsa:?}");

        let ns = p
            .list_rrset("example.com", DnsRecordType::NS, "example.com")
            .await;
        assert!(matches!(ns, Err(Error::Unsupported(_))), "{ns:?}");

        let mismatch = p
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                60,
                vec![DnsRecord::TXT("x".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(mismatch, Err(Error::Api(_))), "{mismatch:?}");
    }

    #[test]
    fn test_new_rejects_empty_credentials() {
        assert!(ContaboProvider::new("", "s", "u", "p", None).is_err());
        assert!(ContaboProvider::new("c", "s", "u", "", None).is_err());
        assert!(DnsUpdater::new_contabo("c", "s", "u", "p", None).is_ok());
    }

    #[tokio::test]
    #[ignore = "Requires CONTABO_CLIENT_ID, CONTABO_CLIENT_SECRET, CONTABO_API_USER, CONTABO_API_PASSWORD and CONTABO_ORIGIN"]
    async fn integration_test() {
        let var = |key: &str| {
            let value = std::env::var(key).unwrap_or_default();
            assert!(!value.is_empty(), "Set {key}");
            value
        };
        let origin = var("CONTABO_ORIGIN");
        let updater = DnsUpdater::new_contabo(
            var("CONTABO_CLIENT_ID"),
            var("CONTABO_CLIENT_SECRET"),
            var("CONTABO_API_USER"),
            var("CONTABO_API_PASSWORD"),
            Some(Duration::from_secs(30)),
        )
        .unwrap();

        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let name = format!("dnsupdate-test-{run_id}.{origin}");
        let long_txt = format!("v=DKIM1; k=rsa; p={}", "A".repeat(400));

        let cases = vec![
            (
                DnsRecordType::A,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("8.8.8.8".parse().unwrap()),
                ],
            ),
            (
                DnsRecordType::AAAA,
                vec![DnsRecord::AAAA("2606:4700:4700::1111".parse().unwrap())],
            ),
            (
                DnsRecordType::MX,
                vec![DnsRecord::MX(MXRecord {
                    exchange: format!("mail.{origin}"),
                    priority: 10,
                })],
            ),
            (
                DnsRecordType::SRV,
                vec![DnsRecord::SRV(SRVRecord {
                    target: format!("mail.{origin}"),
                    priority: 0,
                    weight: 1,
                    port: 993,
                })],
            ),
            (
                DnsRecordType::CAA,
                vec![DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".to_string()),
                    options: vec![],
                })],
            ),
            (
                DnsRecordType::TXT,
                vec![
                    DnsRecord::TXT("first".to_string()),
                    DnsRecord::TXT(long_txt.clone()),
                ],
            ),
        ];

        for (record_type, records) in cases {
            updater
                .set_rrset(&name, record_type, 60, records.clone(), &origin)
                .await
                .unwrap();
            let mut listed = updater
                .list_rrset(&name, record_type, &origin)
                .await
                .unwrap();
            let mut expected = records.clone();
            listed.sort_by_key(|r| r.to_string());
            expected.sort_by_key(|r| r.to_string());
            assert_eq!(listed, expected, "{record_type:?}");

            updater
                .set_rrset(&name, record_type, 120, records.clone(), &origin)
                .await
                .unwrap();
            updater
                .remove_from_rrset(&name, record_type, records[..1].to_vec(), &origin)
                .await
                .unwrap();
            assert_eq!(
                updater
                    .list_rrset(&name, record_type, &origin)
                    .await
                    .unwrap()
                    .len(),
                records.len() - 1,
                "{record_type:?}"
            );
            updater
                .add_to_rrset(&name, record_type, 60, records.clone(), &origin)
                .await
                .unwrap();
            updater
                .set_rrset(&name, record_type, 60, vec![], &origin)
                .await
                .unwrap();
            assert!(
                updater
                    .list_rrset(&name, record_type, &origin)
                    .await
                    .unwrap()
                    .is_empty(),
                "{record_type:?}"
            );
        }

        let cname = format!("dnsupdate-test-{run_id}-cname.{origin}");
        updater
            .set_rrset(
                &cname,
                DnsRecordType::CNAME,
                60,
                vec![DnsRecord::CNAME(format!("mail.{origin}."))],
                &origin,
            )
            .await
            .unwrap();
        assert_eq!(
            updater
                .list_rrset(&cname, DnsRecordType::CNAME, &origin)
                .await
                .unwrap(),
            vec![DnsRecord::CNAME(format!("mail.{origin}"))]
        );
        updater
            .set_rrset(&cname, DnsRecordType::CNAME, 60, vec![], &origin)
            .await
            .unwrap();
    }
}
