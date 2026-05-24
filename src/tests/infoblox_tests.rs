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
        TlsaCertUsage, TlsaMatching, TlsaSelector,
        providers::infoblox::{InfobloxConfig, InfobloxProvider},
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn config() -> InfobloxConfig {
        InfobloxConfig {
            host: "grid.example.com".into(),
            port: None,
            username: "admin".into(),
            password: "secret".into(),
            wapi_version: None,
            dns_view: None,
            request_timeout: Some(Duration::from_secs(2)),
        }
    }

    fn setup(server_url: &str) -> InfobloxProvider {
        InfobloxProvider::new(config())
            .expect("provider")
            .with_endpoint(server_url)
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_infoblox(config());
        assert!(matches!(updater, Ok(DnsUpdater::Infoblox(..))));
    }

    #[tokio::test]
    async fn set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", "/record:a")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "host.example.com".into()),
                Matcher::UrlEncoded("view".into(), "External".into()),
            ]))
            .with_status(200)
            .with_body("[]")
            .create();
        let create_first = server
            .mock("POST", "/record:a")
            .match_body(Matcher::Json(json!({
                "name": "host.example.com",
                "ipv4addr": "1.1.1.1",
                "ttl": 300,
                "use_ttl": true,
                "view": "External",
            })))
            .with_status(201)
            .with_body(r#""record:a/REFA""#)
            .create();
        let create_second = server
            .mock("POST", "/record:a")
            .match_body(Matcher::Json(json!({
                "name": "host.example.com",
                "ipv4addr": "2.2.2.2",
                "ttl": 300,
                "use_ttl": true,
                "view": "External",
            })))
            .with_status(201)
            .with_body(r#""record:a/REFB""#)
            .create();

        let provider = setup(server.url().as_str());
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
        assert!(result.is_ok(), "{result:?}");
        lookup.assert();
        create_first.assert();
        create_second.assert();
    }

    #[tokio::test]
    async fn set_rrset_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", "/record:a")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "host.example.com".into()),
                Matcher::UrlEncoded("view".into(), "External".into()),
            ]))
            .with_status(200)
            .with_body(
                r#"[{"_ref":"record:a/KEEP:host.example.com/External","name":"host.example.com","ipv4addr":"1.1.1.1"}]"#,
            )
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
        lookup.assert();
    }

    #[tokio::test]
    async fn set_rrset_deletes_extras_and_keeps_matches() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", "/record:a")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "host.example.com".into()),
                Matcher::UrlEncoded("view".into(), "External".into()),
            ]))
            .with_status(200)
            .with_body(
                r#"[
                    {"_ref":"record:a/KEEP:host.example.com/External","name":"host.example.com","ipv4addr":"1.1.1.1"},
                    {"_ref":"record:a/STALE:host.example.com/External","name":"host.example.com","ipv4addr":"9.9.9.9"}
                ]"#,
            )
            .create();
        let delete_stale = server
            .mock("DELETE", "/record:a/STALE:host.example.com/External")
            .with_status(200)
            .with_body(r#""record:a/STALE:host.example.com/External""#)
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
        lookup.assert();
        delete_stale.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_vec_deletes_all() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", "/record:a")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "gone.example.com".into()),
                Matcher::UrlEncoded("view".into(), "External".into()),
            ]))
            .with_status(200)
            .with_body(
                r#"[
                    {"_ref":"record:a/X:gone.example.com/External","name":"gone.example.com","ipv4addr":"1.2.3.4"},
                    {"_ref":"record:a/Y:gone.example.com/External","name":"gone.example.com","ipv4addr":"5.6.7.8"}
                ]"#,
            )
            .create();
        let delete_x = server
            .mock("DELETE", "/record:a/X:gone.example.com/External")
            .with_status(200)
            .with_body(r#""record:a/X""#)
            .create();
        let delete_y = server
            .mock("DELETE", "/record:a/Y:gone.example.com/External")
            .with_status(200)
            .with_body(r#""record:a/Y""#)
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
        lookup.assert();
        delete_x.assert();
        delete_y.assert();
    }

    #[tokio::test]
    async fn set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", "/record:a")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "host.example.com".into()),
                Matcher::UrlEncoded("view".into(), "External".into()),
            ]))
            .with_status(200)
            .with_body("[]")
            .create();
        let create_a = server
            .mock("POST", "/record:a")
            .match_body(Matcher::Json(json!({
                "name": "host.example.com",
                "ipv4addr": "1.1.1.1",
                "ttl": 300,
                "use_ttl": true,
                "view": "External",
            })))
            .with_status(201)
            .with_body(r#""record:a/NEW""#)
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
        lookup.assert();
        create_a.assert();
    }

    #[tokio::test]
    async fn set_rrset_type_mismatch_returns_error() {
        let provider = setup("http://127.0.0.1:1/wapi/v2.11");
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::CNAME("other.example.com".into())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))));
    }

    #[tokio::test]
    async fn add_to_rrset_empty_vec_is_noop() {
        let provider = setup("http://127.0.0.1:1/wapi/v2.11");
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", "/record:txt")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "_acme.example.com".into()),
                Matcher::UrlEncoded("view".into(), "External".into()),
            ]))
            .with_status(200)
            .with_body(
                r#"[{"_ref":"record:txt/OLD:_acme.example.com/External","name":"_acme.example.com","text":"existing"}]"#,
            )
            .create();
        let create_new = server
            .mock("POST", "/record:txt")
            .match_body(Matcher::Json(json!({
                "name": "_acme.example.com",
                "text": "new-token",
                "ttl": 60,
                "use_ttl": true,
                "view": "External",
            })))
            .with_status(201)
            .with_body(r#""record:txt/NEW""#)
            .create();

        let provider = setup(server.url().as_str());
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
        assert!(result.is_ok(), "{result:?}");
        lookup.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_vec_is_noop() {
        let provider = setup("http://127.0.0.1:1/wapi/v2.11");
        let result = provider
            .remove_from_rrset("host.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", "/record:txt")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "_acme.example.com".into()),
                Matcher::UrlEncoded("view".into(), "External".into()),
            ]))
            .with_status(200)
            .with_body(
                r#"[
                    {"_ref":"record:txt/KEEP:_acme.example.com/External","name":"_acme.example.com","text":"keep-me"},
                    {"_ref":"record:txt/DROP:_acme.example.com/External","name":"_acme.example.com","text":"drop-me"}
                ]"#,
            )
            .create();
        let delete_drop = server
            .mock("DELETE", "/record:txt/DROP:_acme.example.com/External")
            .with_status(200)
            .with_body(r#""record:txt/DROP""#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![
                    DnsRecord::TXT("drop-me".into()),
                    DnsRecord::TXT("absent".into()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        lookup.assert();
        delete_drop.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_caa_compares_full_value() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", "/record:caa")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "example.com".into()),
                Matcher::UrlEncoded("view".into(), "External".into()),
            ]))
            .with_status(200)
            .with_body(
                r#"[
                    {"_ref":"record:caa/A:example.com/External","name":"example.com","ca_flag":0,"ca_tag":"issue","ca_value":"letsencrypt.org"},
                    {"_ref":"record:caa/B:example.com/External","name":"example.com","ca_flag":0,"ca_tag":"issue","ca_value":"digicert.com"}
                ]"#,
            )
            .create();
        let delete_b = server
            .mock("DELETE", "/record:caa/B:example.com/External")
            .with_status(200)
            .with_body(r#""record:caa/B""#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "example.com",
                DnsRecordType::CAA,
                vec![DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("digicert.com".into()),
                    options: vec![],
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        lookup.assert();
        delete_b.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_records() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", "/record:srv")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "_sip._tcp.example.com".into()),
                Matcher::UrlEncoded("view".into(), "External".into()),
            ]))
            .with_status(200)
            .with_body(
                r#"[
                    {"_ref":"record:srv/A:_sip._tcp.example.com/External","name":"_sip._tcp.example.com","target":"sip1.example.com","port":5060,"priority":10,"weight":60}
                ]"#,
            )
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .list_rrset("_sip._tcp.example.com", DnsRecordType::SRV, "example.com")
            .await;
        assert!(result.is_ok(), "{result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0],
            DnsRecord::SRV(SRVRecord {
                target: "sip1.example.com".into(),
                priority: 10,
                weight: 60,
                port: 5060,
            })
        );
        lookup.assert();
    }

    #[tokio::test]
    async fn set_rrset_tlsa_full_cycle() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", "/record:tlsa")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "_443._tcp.example.com".into()),
                Matcher::UrlEncoded("view".into(), "External".into()),
            ]))
            .with_status(200)
            .with_body(
                r#"[{"_ref":"record:tlsa/KEEP:_443._tcp.example.com/External","name":"_443._tcp.example.com","certificate_usage":3,"selector":1,"matched_type":1,"certificate_data":"00ff"}]"#,
            )
            .create();
        let create_new = server
            .mock("POST", "/record:tlsa")
            .match_body(Matcher::Json(json!({
                "name": "_443._tcp.example.com",
                "certificate_usage": 2,
                "selector": 1,
                "matched_type": 1,
                "certificate_data": "aabb",
                "ttl": 300,
                "use_ttl": true,
                "view": "External",
            })))
            .with_status(201)
            .with_body(r#""record:tlsa/NEW""#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .set_rrset(
                "_443._tcp.example.com",
                DnsRecordType::TLSA,
                300,
                vec![
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneEe,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0x00, 0xff],
                    }),
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneTa,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xaa, 0xbb],
                    }),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        lookup.assert();
        create_new.assert();
    }

    #[tokio::test]
    #[ignore = "Requires Infoblox grid manager credentials"]
    async fn integration_test() {
        let host = ""; // <-- e.g. "grid.example.com"
        let user = ""; // <-- WAPI user
        let pass = ""; // <-- WAPI password
        let zone = ""; // <-- managed zone (e.g. "example.com")
        assert!(!host.is_empty() && !user.is_empty() && !pass.is_empty() && !zone.is_empty());
        let provider = InfobloxProvider::new(InfobloxConfig {
            host: host.into(),
            port: None,
            username: user.into(),
            password: pass.into(),
            wapi_version: None,
            dns_view: None,
            request_timeout: Some(Duration::from_secs(30)),
        })
        .expect("provider");
        let name = format!("test.{zone}");
        provider
            .set_rrset(
                name.as_str(),
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                zone,
            )
            .await
            .expect("set_rrset create");
        provider
            .set_rrset(name.as_str(), DnsRecordType::A, 300, vec![], zone)
            .await
            .expect("set_rrset delete");
    }
}
