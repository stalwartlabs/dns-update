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
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, SRVRecord, TLSARecord,
        TlsaCertUsage, TlsaMatching, TlsaSelector, providers::ns1::Ns1Provider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> Ns1Provider {
        Ns1Provider::new("test_key", Some(Duration::from_secs(5))).with_endpoint(endpoint)
    }

    fn rrset_path(domain: &str, rr_type: &str) -> String {
        format!("/zones/example.com/{domain}/{rr_type}")
    }

    fn get_404(server: &mut mockito::ServerGuard, domain: &str, rr_type: &str) -> mockito::Mock {
        server
            .mock("GET", rrset_path(domain, rr_type).as_str())
            .match_header("x-nsone-key", "test_key")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"record not found"}"#)
            .create()
    }

    fn get_ok(
        server: &mut mockito::ServerGuard,
        domain: &str,
        rr_type: &str,
        body: serde_json::Value,
    ) -> mockito::Mock {
        server
            .mock("GET", rrset_path(domain, rr_type).as_str())
            .match_header("x-nsone-key", "test_key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_uses_put_when_rrset_missing() {
        let mut server = mockito::Server::new_async().await;
        let get = get_404(&mut server, "test.example.com", "A");

        let put = server
            .mock("PUT", "/zones/example.com/test.example.com/A")
            .match_header("x-nsone-key", "test_key")
            .match_body(Matcher::Json(json!({
                "zone": "example.com",
                "domain": "test.example.com",
                "type": "A",
                "ttl": 300,
                "answers": [
                    {"answer": ["1.1.1.1"]},
                    {"answer": ["2.2.2.2"]},
                ],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
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
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_uses_post_when_rrset_exists() {
        let mut server = mockito::Server::new_async().await;
        let get = get_ok(
            &mut server,
            "host.example.com",
            "A",
            json!({
                "zone": "example.com",
                "domain": "host.example.com",
                "type": "A",
                "ttl": 300,
                "answers": [{"answer": ["9.9.9.9"]}],
            }),
        );

        let post = server
            .mock("POST", "/zones/example.com/host.example.com/A")
            .match_body(Matcher::Json(json!({
                "zone": "example.com",
                "domain": "host.example.com",
                "type": "A",
                "ttl": 60,
                "answers": [{"answer": ["8.8.8.8"]}],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                60,
                vec![DnsRecord::A("8.8.8.8".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        get.assert();
        post.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_rrset() {
        let mut server = mockito::Server::new_async().await;
        let delete = server
            .mock("DELETE", "/zones/example.com/gone.example.com/A")
            .match_header("x-nsone-key", "test_key")
            .with_status(200)
            .with_body("{}")
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
        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_tolerates_404() {
        let mut server = mockito::Server::new_async().await;
        let delete = server
            .mock("DELETE", "/zones/example.com/gone.example.com/A")
            .with_status(404)
            .with_body(r#"{"message":"record not found"}"#)
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
        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_returns_error() {
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
    async fn test_set_rrset_url_targets_type_isolating_other_types() {
        let mut server = mockito::Server::new_async().await;
        let get = get_404(&mut server, "shared.example.com", "A");

        let put = server
            .mock("PUT", "/zones/example.com/shared.example.com/A")
            .with_status(200)
            .with_body("{}")
            .create();

        let _no_txt_get = server
            .mock("GET", "/zones/example.com/shared.example.com/TXT")
            .expect(0)
            .create();
        let _no_txt_delete = server
            .mock("DELETE", "/zones/example.com/shared.example.com/TXT")
            .expect(0)
            .create();
        let _no_txt_post = server
            .mock("POST", "/zones/example.com/shared.example.com/TXT")
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

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_two_tlsa_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let get = get_404(&mut server, "_25._tcp.mail.example.com", "TLSA");

        let put = server
            .mock("PUT", "/zones/example.com/_25._tcp.mail.example.com/TLSA")
            .match_body(Matcher::Json(json!({
                "zone": "example.com",
                "domain": "_25._tcp.mail.example.com",
                "type": "TLSA",
                "ttl": 300,
                "answers": [
                    {"answer": ["3", "1", "1", "aa"]},
                    {"answer": ["2", "1", "1", "bb"]},
                ],
            })))
            .with_status(200)
            .with_body("{}")
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
                        cert_data: vec![0xaa],
                    }),
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneTa,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xbb],
                    }),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_uses_decompose() {
        let mut server = mockito::Server::new_async().await;
        let get = get_404(&mut server, "example.com", "CAA");

        let put = server
            .mock("PUT", "/zones/example.com/example.com/CAA")
            .match_body(Matcher::Json(json!({
                "zone": "example.com",
                "domain": "example.com",
                "type": "CAA",
                "ttl": 3600,
                "answers": [{"answer": ["0", "issue", "letsencrypt.org"]}],
            })))
            .with_status(200)
            .with_body("{}")
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
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_format() {
        let mut server = mockito::Server::new_async().await;
        let get = get_404(&mut server, "_imaps._tcp.example.com", "SRV");

        let put = server
            .mock("PUT", "/zones/example.com/_imaps._tcp.example.com/SRV")
            .match_body(Matcher::Json(json!({
                "zone": "example.com",
                "domain": "_imaps._tcp.example.com",
                "type": "SRV",
                "ttl": 3600,
                "answers": [{"answer": ["10", "5", "993", "mail.example.com"]}],
            })))
            .with_status(200)
            .with_body("{}")
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
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let _no_put = server.mock("PUT", Matcher::Any).expect(0).create();
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
    async fn test_add_to_rrset_creates_with_put_when_missing() {
        let mut server = mockito::Server::new_async().await;
        let get = get_404(&mut server, "fresh.example.com", "A");

        let put = server
            .mock("PUT", "/zones/example.com/fresh.example.com/A")
            .match_body(Matcher::Json(json!({
                "zone": "example.com",
                "domain": "fresh.example.com",
                "type": "A",
                "ttl": 300,
                "answers": [{"answer": ["9.9.9.9"]}],
            })))
            .with_status(200)
            .with_body("{}")
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
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_merges_with_existing_via_post() {
        let mut server = mockito::Server::new_async().await;
        let get = get_ok(
            &mut server,
            "_acme.example.com",
            "TXT",
            json!({
                "zone": "example.com",
                "domain": "_acme.example.com",
                "type": "TXT",
                "ttl": 60,
                "answers": [{"answer": ["existing"]}],
            }),
        );

        let post = server
            .mock("POST", "/zones/example.com/_acme.example.com/TXT")
            .match_body(Matcher::Json(json!({
                "zone": "example.com",
                "domain": "_acme.example.com",
                "type": "TXT",
                "ttl": 60,
                "answers": [
                    {"answer": ["existing"]},
                    {"answer": ["new-token"]},
                ],
            })))
            .with_status(200)
            .with_body("{}")
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
        get.assert();
        post.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_when_value_already_present() {
        let mut server = mockito::Server::new_async().await;
        let get = get_ok(
            &mut server,
            "test.example.com",
            "A",
            json!({
                "zone": "example.com",
                "domain": "test.example.com",
                "type": "A",
                "ttl": 60,
                "answers": [
                    {"answer": ["1.1.1.1"]},
                    {"answer": ["8.8.8.8"]},
                ],
            }),
        );

        let post = server
            .mock("POST", "/zones/example.com/test.example.com/A")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                60,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("8.8.8.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        get.assert();
        post.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_type_mismatch_returns_error() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let _no_get = server.mock("GET", Matcher::Any).expect(0).create();
        let _no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();
        let _no_post = server.mock("POST", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_filters_and_posts_remainder() {
        let mut server = mockito::Server::new_async().await;
        let get_initial = get_ok(
            &mut server,
            "_acme.example.com",
            "TXT",
            json!({
                "zone": "example.com",
                "domain": "_acme.example.com",
                "type": "TXT",
                "ttl": 120,
                "answers": [
                    {"answer": ["keep-me"]},
                    {"answer": ["drop-me"]},
                ],
            }),
        );

        let post = server
            .mock("POST", "/zones/example.com/_acme.example.com/TXT")
            .match_body(Matcher::Json(json!({
                "zone": "example.com",
                "domain": "_acme.example.com",
                "type": "TXT",
                "ttl": 120,
                "answers": [{"answer": ["keep-me"]}],
            })))
            .with_status(200)
            .with_body("{}")
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
        get_initial.assert();
        post.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_when_remainder_empty() {
        let mut server = mockito::Server::new_async().await;
        let get = get_ok(
            &mut server,
            "test.example.com",
            "A",
            json!({
                "zone": "example.com",
                "domain": "test.example.com",
                "type": "A",
                "ttl": 60,
                "answers": [{"answer": ["1.1.1.1"]}],
            }),
        );

        let delete = server
            .mock("DELETE", "/zones/example.com/test.example.com/A")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        get.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_noop_when_rrset_missing() {
        let mut server = mockito::Server::new_async().await;
        let get = get_404(&mut server, "test.example.com", "A");
        let _no_post = server
            .mock("POST", "/zones/example.com/test.example.com/A")
            .expect(0)
            .create();
        let _no_delete = server
            .mock("DELETE", "/zones/example.com/test.example.com/A")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        get.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_noop_when_value_absent() {
        let mut server = mockito::Server::new_async().await;
        let get = get_ok(
            &mut server,
            "test.example.com",
            "A",
            json!({
                "zone": "example.com",
                "domain": "test.example.com",
                "type": "A",
                "ttl": 60,
                "answers": [{"answer": ["1.1.1.1"]}],
            }),
        );
        let _no_delete = server
            .mock("DELETE", "/zones/example.com/test.example.com/A")
            .expect(0)
            .create();
        let post = server
            .mock("POST", "/zones/example.com/test.example.com/A")
            .match_body(Matcher::Json(json!({
                "zone": "example.com",
                "domain": "test.example.com",
                "type": "A",
                "ttl": 60,
                "answers": [{"answer": ["1.1.1.1"]}],
            })))
            .with_status(200)
            .with_body("{}")
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

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        get.assert();
        post.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_type_mismatch_returns_error() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_list_rrset_returns_records() {
        let mut server = mockito::Server::new_async().await;
        let get = get_ok(
            &mut server,
            "test.example.com",
            "A",
            json!({
                "zone": "example.com",
                "domain": "test.example.com",
                "type": "A",
                "ttl": 300,
                "answers": [
                    {"answer": ["1.1.1.1"]},
                    {"answer": ["2.2.2.2"]},
                ],
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("test.example.com", DnsRecordType::A, "example.com")
            .await;

        let records = result.expect("list_rrset");
        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(records.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
        get.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_empty_on_404() {
        let mut server = mockito::Server::new_async().await;
        let get = get_404(&mut server, "missing.example.com", "TXT");

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("missing.example.com", DnsRecordType::TXT, "example.com")
            .await;

        let records = result.expect("list_rrset");
        assert!(records.is_empty());
        get.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_caa_and_tlsa() {
        let mut server = mockito::Server::new_async().await;
        let get_caa = get_ok(
            &mut server,
            "example.com",
            "CAA",
            json!({
                "zone": "example.com",
                "domain": "example.com",
                "type": "CAA",
                "ttl": 3600,
                "answers": [{"answer": ["0", "issue", "letsencrypt.org"]}],
            }),
        );
        let get_tlsa = get_ok(
            &mut server,
            "_25._tcp.mail.example.com",
            "TLSA",
            json!({
                "zone": "example.com",
                "domain": "_25._tcp.mail.example.com",
                "type": "TLSA",
                "ttl": 300,
                "answers": [{"answer": ["3", "1", "1", "deadbeef"]}],
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let caa = provider
            .list_rrset("example.com", DnsRecordType::CAA, "example.com")
            .await
            .expect("list CAA");
        assert_eq!(caa.len(), 1);
        match &caa[0] {
            DnsRecord::CAA(CAARecord::Issue {
                issuer_critical,
                name,
                ..
            }) => {
                assert!(!*issuer_critical);
                assert_eq!(name.as_deref(), Some("letsencrypt.org"));
            }
            other => panic!("expected CAA Issue, got {other:?}"),
        }

        let tlsa = provider
            .list_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                "example.com",
            )
            .await
            .expect("list TLSA");
        assert_eq!(tlsa.len(), 1);
        match &tlsa[0] {
            DnsRecord::TLSA(record) => {
                assert_eq!(record.cert_data, vec![0xde, 0xad, 0xbe, 0xef]);
            }
            other => panic!("expected TLSA, got {other:?}"),
        }

        get_caa.assert();
        get_tlsa.assert();
    }

    #[test]
    fn provider_creation() {
        let provider = Ns1Provider::new("mock", Some(Duration::from_secs(1)));
        let _ = provider;
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_ns1("mock", Some(Duration::from_secs(30)));
        assert!(matches!(updater, Ok(DnsUpdater::Ns1(..))));
    }
}
