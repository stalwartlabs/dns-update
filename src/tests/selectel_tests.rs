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
        TlsaMatching, TlsaSelector, providers::selectel::SelectelProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    const ZONE_ID: &str = "c3a1e2b0-0000-4000-8000-000000000001";
    const RRSET_ID: &str = "d4b2f3c1-0000-4000-8000-000000000002";

    fn provider(endpoint: String) -> SelectelProvider {
        SelectelProvider::new(
            "svc-user",
            "secret",
            "123456",
            "0123456789abcdef0123456789abcdef",
            Some(Duration::from_secs(5)),
        )
        .unwrap()
        .with_endpoint(endpoint)
    }

    fn mock_token(server: &mut mockito::ServerGuard) -> mockito::Mock {
        server
            .mock("POST", "/identity/v3/auth/tokens")
            .match_header("content-type", "application/json")
            .match_body(Matcher::Json(json!({
                "auth": {
                    "identity": {
                        "methods": ["password"],
                        "password": {
                            "user": {
                                "name": "svc-user",
                                "domain": {"name": "123456"},
                                "password": "secret"
                            }
                        }
                    },
                    "scope": {"project": {"id": "0123456789abcdef0123456789abcdef"}}
                }
            })))
            .with_status(201)
            .with_header("x-subject-token", "tok")
            .with_body(r#"{"token":{"expires_at":"2099-01-01T00:00:00.000000Z"}}"#)
            .expect(1)
            .create()
    }

    fn mock_zone(server: &mut mockito::ServerGuard) -> mockito::Mock {
        server
            .mock("GET", "/domains/v2/zones")
            .match_query(Matcher::UrlEncoded("filter".into(), "example.com".into()))
            .match_header("x-auth-token", "tok")
            .with_status(200)
            .with_body(
                json!({
                    "count": 1,
                    "next_offset": 0,
                    "result": [{"id": ZONE_ID, "name": "example.com."}]
                })
                .to_string(),
            )
            .create()
    }

    fn rrset_query(name: &str, rtype: &str) -> Matcher {
        Matcher::AllOf(vec![
            Matcher::UrlEncoded("name".into(), name.into()),
            Matcher::UrlEncoded("rrset_types".into(), rtype.into()),
        ])
    }

    fn mock_rrsets(
        server: &mut mockito::ServerGuard,
        name: &str,
        rtype: &str,
        result: serde_json::Value,
    ) -> mockito::Mock {
        server
            .mock("GET", format!("/domains/v2/zones/{ZONE_ID}/rrset").as_str())
            .match_query(rrset_query(name, rtype))
            .match_header("x-auth-token", "tok")
            .with_status(200)
            .with_body(json!({"count": 0, "next_offset": 0, "result": result}).to_string())
            .create()
    }

    fn existing_rrset(name: &str, rtype: &str, ttl: u32, contents: &[&str]) -> serde_json::Value {
        json!([{
            "id": RRSET_ID,
            "zone_id": ZONE_ID,
            "name": name,
            "type": rtype,
            "ttl": ttl,
            "records": contents
                .iter()
                .map(|c| json!({"content": c, "disabled": false}))
                .collect::<Vec<_>>(),
        }])
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_missing() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);
        let zone = mock_zone(&mut server);
        let list = mock_rrsets(&mut server, "www.example.com", "A", json!([]));
        let create = server
            .mock(
                "POST",
                format!("/domains/v2/zones/{ZONE_ID}/rrset").as_str(),
            )
            .match_header("x-auth-token", "tok")
            .match_body(Matcher::Json(json!({
                "name": "www.example.com.",
                "type": "A",
                "ttl": 300,
                "records": [
                    {"content": "1.1.1.1", "disabled": false},
                    {"content": "2.2.2.2", "disabled": false}
                ]
            })))
            .with_status(201)
            .with_body(r#"{"id":"new"}"#)
            .create();

        provider(server.url())
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

        token.assert();
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_replaces_existing() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _zone = mock_zone(&mut server);
        let _list = mock_rrsets(
            &mut server,
            "example.com",
            "MX",
            existing_rrset("example.com.", "MX", 3600, &["5 old.example.com."]),
        );
        let patch = server
            .mock(
                "PATCH",
                format!("/domains/v2/zones/{ZONE_ID}/rrset/{RRSET_ID}").as_str(),
            )
            .match_body(Matcher::Json(json!({
                "ttl": 600,
                "records": [{"content": "10 mx.example.com.", "disabled": false}]
            })))
            .with_status(204)
            .create();

        provider(server.url())
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                600,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mx.example.com".to_string(),
                    priority: 10,
                })],
                "example.com",
            )
            .await
            .unwrap();

        patch.assert();
    }

    // An RRSet that already holds the desired values and TTL is not rewritten.
    #[tokio::test]
    async fn test_set_rrset_unchanged_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _zone = mock_zone(&mut server);
        let _list = mock_rrsets(
            &mut server,
            "example.com",
            "MX",
            existing_rrset("example.com.", "MX", 60, &["10 MX.example.com."]),
        );
        let write = server.mock("PATCH", Matcher::Any).expect(0).create();

        provider(server.url())
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                30,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mx.example.com".to_string(),
                    priority: 10,
                })],
                "example.com",
            )
            .await
            .unwrap();

        write.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _zone = mock_zone(&mut server);
        let _list = mock_rrsets(
            &mut server,
            "www.example.com",
            "A",
            existing_rrset("www.example.com.", "A", 60, &["1.1.1.1"]),
        );
        let delete = server
            .mock(
                "DELETE",
                format!("/domains/v2/zones/{ZONE_ID}/rrset/{RRSET_ID}").as_str(),
            )
            .with_status(204)
            .create();

        provider(server.url())
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                60,
                vec![],
                "example.com",
            )
            .await
            .unwrap();

        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_missing_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _zone = mock_zone(&mut server);
        let _list = mock_rrsets(&mut server, "www.example.com", "A", json!([]));
        let delete = server.mock("DELETE", Matcher::Any).expect(0).create();

        provider(server.url())
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                60,
                vec![],
                "example.com",
            )
            .await
            .unwrap();

        delete.assert();
    }

    #[tokio::test]
    async fn test_zone_resolution_walks_up_labels() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let sub = server
            .mock("GET", "/domains/v2/zones")
            .match_query(Matcher::UrlEncoded(
                "filter".into(),
                "sub.example.com".into(),
            ))
            .with_status(200)
            .with_body(r#"{"count":0,"next_offset":0,"result":[]}"#)
            .create();
        let zone = mock_zone(&mut server);
        let _list = mock_rrsets(&mut server, "a.sub.example.com", "A", json!([]));
        let create = server
            .mock(
                "POST",
                format!("/domains/v2/zones/{ZONE_ID}/rrset").as_str(),
            )
            .match_body(Matcher::PartialJson(json!({"name": "a.sub.example.com."})))
            .with_status(201)
            .with_body("{}")
            .create();

        provider(server.url())
            .set_rrset(
                "a.sub.example.com",
                DnsRecordType::A,
                60,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "sub.example.com",
            )
            .await
            .unwrap();

        sub.assert();
        zone.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_zone_not_found() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _zones = server
            .mock("GET", "/domains/v2/zones")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(r#"{"count":1,"next_offset":0,"result":[{"id":"x","name":"other.com."}]}"#)
            .create();

        let result = provider(server.url())
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "{result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_merges_txt() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _zone = mock_zone(&mut server);
        let _list = mock_rrsets(
            &mut server,
            "_acme-challenge.example.com",
            "TXT",
            existing_rrset(
                "_acme-challenge.example.com.",
                "TXT",
                120,
                &["\"existing\""],
            ),
        );
        let patch = server
            .mock(
                "PATCH",
                format!("/domains/v2/zones/{ZONE_ID}/rrset/{RRSET_ID}").as_str(),
            )
            .match_body(Matcher::Json(json!({
                "ttl": 60,
                "records": [
                    {"content": "\"existing\"", "disabled": false},
                    {"content": "\"token\"", "disabled": false}
                ]
            })))
            .with_status(204)
            .create();

        provider(server.url())
            .add_to_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                60,
                vec![
                    DnsRecord::TXT("existing".to_string()),
                    DnsRecord::TXT("token".to_string()),
                ],
                "example.com",
            )
            .await
            .unwrap();

        patch.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_already_present_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _zone = mock_zone(&mut server);
        let _list = mock_rrsets(
            &mut server,
            "www.example.com",
            "CNAME",
            existing_rrset("www.example.com.", "CNAME", 60, &["Target.Example.com."]),
        );
        let write = server.mock("PATCH", Matcher::Any).expect(0).create();

        provider(server.url())
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::CNAME,
                60,
                vec![DnsRecord::CNAME("target.example.com".to_string())],
                "example.com",
            )
            .await
            .unwrap();

        write.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_creates_when_missing() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _zone = mock_zone(&mut server);
        let _list = mock_rrsets(&mut server, "_sip._tcp.example.com", "SRV", json!([]));
        let create = server
            .mock(
                "POST",
                format!("/domains/v2/zones/{ZONE_ID}/rrset").as_str(),
            )
            .match_body(Matcher::Json(json!({
                "name": "_sip._tcp.example.com.",
                "type": "SRV",
                "ttl": 60,
                "records": [{"content": "10 20 5060 sip.example.com.", "disabled": false}]
            })))
            .with_status(201)
            .with_body("{}")
            .create();

        provider(server.url())
            .add_to_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                30,
                vec![DnsRecord::SRV(SRVRecord {
                    target: "sip.example.com".to_string(),
                    priority: 10,
                    weight: 20,
                    port: 5060,
                })],
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
        let _zone = mock_zone(&mut server);
        let _list = mock_rrsets(
            &mut server,
            "www.example.com",
            "A",
            existing_rrset("www.example.com.", "A", 900, &["1.1.1.1", "2.2.2.2"]),
        );
        let patch = server
            .mock(
                "PATCH",
                format!("/domains/v2/zones/{ZONE_ID}/rrset/{RRSET_ID}").as_str(),
            )
            .match_body(Matcher::Json(json!({
                "ttl": 900,
                "records": [{"content": "2.2.2.2", "disabled": false}]
            })))
            .with_status(204)
            .create();

        provider(server.url())
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await
            .unwrap();

        patch.assert();
    }

    #[tokio::test]
    async fn test_remove_last_value_deletes_rrset() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _zone = mock_zone(&mut server);
        let _list = mock_rrsets(
            &mut server,
            "_acme-challenge.example.com",
            "TXT",
            existing_rrset("_acme-challenge.example.com.", "TXT", 60, &["\"token\""]),
        );
        let delete = server
            .mock(
                "DELETE",
                format!("/domains/v2/zones/{ZONE_ID}/rrset/{RRSET_ID}").as_str(),
            )
            .with_status(204)
            .create();

        provider(server.url())
            .remove_from_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("token".to_string())],
                "example.com",
            )
            .await
            .unwrap();

        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_missing_rrset_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _zone = mock_zone(&mut server);
        let _list = mock_rrsets(&mut server, "www.example.com", "A", json!([]));

        provider(server.url())
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_caa_and_ignores_other_names() {
        let mut server = mockito::Server::new_async().await;
        let _token = mock_token(&mut server);
        let _zone = mock_zone(&mut server);
        let _list = mock_rrsets(
            &mut server,
            "example.com",
            "CAA",
            json!([
                {
                    "id": "other",
                    "name": "sub.example.com.",
                    "type": "CAA",
                    "ttl": 60,
                    "records": [{"content": "0 issue \"other.ca\"", "disabled": false}]
                },
                {
                    "id": RRSET_ID,
                    "name": "example.com.",
                    "type": "CAA",
                    "ttl": 60,
                    "records": [{"content": "0 issue \"letsencrypt.org\"", "disabled": false}]
                }
            ]),
        );

        let records = provider(server.url())
            .list_rrset("example.com", DnsRecordType::CAA, "example.com")
            .await
            .unwrap();

        assert_eq!(
            records,
            vec![DnsRecord::CAA(CAARecord::Issue {
                issuer_critical: false,
                name: Some("letsencrypt.org".to_string()),
                options: vec![],
            })]
        );
    }

    #[tokio::test]
    async fn test_token_is_cached_across_calls() {
        let mut server = mockito::Server::new_async().await;
        let token = mock_token(&mut server);
        let _zone = mock_zone(&mut server);
        let _list = mock_rrsets(&mut server, "www.example.com", "A", json!([]));

        let p = provider(server.url());
        for _ in 0..3 {
            p.list_rrset("www.example.com", DnsRecordType::A, "example.com")
                .await
                .unwrap();
        }

        token.assert();
    }

    #[tokio::test]
    async fn test_auth_failure() {
        let mut server = mockito::Server::new_async().await;
        let _auth = server
            .mock("POST", "/identity/v3/auth/tokens")
            .with_status(401)
            .with_body(r#"{"error":{"code":401}}"#)
            .create();

        let result = provider(server.url())
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await;
        assert!(matches!(result, Err(Error::Unauthorized)), "{result:?}");
    }

    #[tokio::test]
    async fn test_rejects_tlsa_and_type_mismatch() {
        let p = provider("http://127.0.0.1:1".to_string());

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
        assert!(SelectelProvider::new("", "p", "1", "proj", None).is_err());
        assert!(SelectelProvider::new("u", "p", "1", "", None).is_err());
    }

    #[tokio::test]
    #[ignore = "Requires SELECTEL_USERNAME, SELECTEL_PASSWORD, SELECTEL_ACCOUNT_ID, SELECTEL_PROJECT_ID and SELECTEL_ORIGIN"]
    async fn integration_test() {
        let var = |key: &str| {
            let value = std::env::var(key).unwrap_or_default();
            assert!(!value.is_empty(), "Set {key}");
            value
        };
        let origin = var("SELECTEL_ORIGIN");
        let updater = SelectelProvider::new(
            var("SELECTEL_USERNAME"),
            var("SELECTEL_PASSWORD"),
            var("SELECTEL_ACCOUNT_ID"),
            var("SELECTEL_PROJECT_ID"),
            Some(Duration::from_secs(30)),
        )
        .unwrap();

        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let name = format!("dnsupdate-test-{run_id}.{origin}");

        updater
            .set_rrset(
                &name,
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("first".to_string())],
                &origin,
            )
            .await
            .unwrap();
        updater
            .add_to_rrset(
                &name,
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("second".to_string())],
                &origin,
            )
            .await
            .unwrap();
        let mut listed = updater
            .list_rrset(&name, DnsRecordType::TXT, &origin)
            .await
            .unwrap();
        listed.sort_by_key(|r| r.to_string());
        assert_eq!(
            listed,
            vec![
                DnsRecord::TXT("first".to_string()),
                DnsRecord::TXT("second".to_string()),
            ]
        );

        updater
            .remove_from_rrset(
                &name,
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("first".to_string())],
                &origin,
            )
            .await
            .unwrap();
        assert_eq!(
            updater
                .list_rrset(&name, DnsRecordType::TXT, &origin)
                .await
                .unwrap(),
            vec![DnsRecord::TXT("second".to_string())]
        );

        updater
            .set_rrset(&name, DnsRecordType::TXT, 60, vec![], &origin)
            .await
            .unwrap();
        assert!(
            updater
                .list_rrset(&name, DnsRecordType::TXT, &origin)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
