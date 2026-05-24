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
        TlsaMatching, TlsaSelector, providers::cloudflare::CloudflareProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const ZONE_ID: &str = "abc123zoneid";

    fn setup_provider(endpoint: String) -> CloudflareProvider {
        CloudflareProvider::new("test_token", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn mock_zone_lookup(server: &mut ServerGuard, zone_name: &str) -> Mock {
        server
            .mock("GET", "/zones")
            .match_query(Matcher::UrlEncoded("name".into(), zone_name.into()))
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"errors":[],"success":true,"result":[{{"id":"{ZONE_ID}","name":"{zone_name}"}}]}}"#
            ))
            .create()
    }

    fn mock_list(
        server: &mut ServerGuard,
        name: &str,
        record_type: &str,
        body: serde_json::Value,
    ) -> Mock {
        server
            .mock("GET", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), name.into()),
                Matcher::UrlEncoded("type".into(), record_type.into()),
                Matcher::UrlEncoded("match".into(), "all".into()),
                Matcher::UrlEncoded("per_page".into(), "100".into()),
            ]))
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    fn ok_body() -> &'static str {
        r#"{"errors":[],"success":true,"result":{}}"#
    }

    fn ok_result(items: serde_json::Value) -> serde_json::Value {
        json!({"errors": [], "success": true, "result": items})
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "mail.example.com",
            "TLSA",
            ok_result(json!([])),
        );

        let create_1 = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::Json(json!({
                "ttl": 300,
                "proxied": false,
                "name": "mail.example.com",
                "type": "TLSA",
                "data": {
                    "usage": 3,
                    "selector": 1,
                    "matching_type": 1,
                    "certificate": "00",
                },
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let create_2 = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::Json(json!({
                "ttl": 300,
                "proxied": false,
                "name": "mail.example.com",
                "type": "TLSA",
                "data": {
                    "usage": 2,
                    "selector": 1,
                    "matching_type": 1,
                    "certificate": "ff",
                },
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
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
        zone.assert();
        list.assert();
        create_1.assert();
        create_2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "test.example.com",
            "A",
            ok_result(json!([
                {"id": "rec-1", "type": "A", "content": "1.1.1.1"},
            ])),
        );

        let provider = setup_provider(server.url());
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
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_keeps_matching() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "host.example.com",
            "A",
            ok_result(json!([
                {"id": "rec-keep", "type": "A", "content": "1.1.1.1"},
                {"id": "rec-stale", "type": "A", "content": "9.9.9.9"},
            ])),
        );

        let delete_stale = server
            .mock(
                "DELETE",
                format!("/zones/{ZONE_ID}/dns_records/rec-stale").as_str(),
            )
            .with_status(200)
            .with_body(ok_body())
            .create();

        let create_new = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::Json(json!({
                "ttl": 300,
                "proxied": false,
                "name": "host.example.com",
                "type": "A",
                "content": "8.8.8.8",
            })))
            .with_status(200)
            .with_body(ok_body())
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
        zone.assert();
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_records_deletes_all() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "gone.example.com",
            "A",
            ok_result(json!([
                {"id": "rec-x", "type": "A", "content": "1.2.3.4"},
                {"id": "rec-y", "type": "A", "content": "5.6.7.8"},
            ])),
        );

        let delete_x = server
            .mock(
                "DELETE",
                format!("/zones/{ZONE_ID}/dns_records/rec-x").as_str(),
            )
            .with_status(200)
            .with_body(ok_body())
            .create();
        let delete_y = server
            .mock(
                "DELETE",
                format!("/zones/{ZONE_ID}/dns_records/rec-y").as_str(),
            )
            .with_status(200)
            .with_body(ok_body())
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
        zone.assert();
        list.assert();
        delete_x.assert();
        delete_y.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "_acme.example.com",
            "TXT",
            ok_result(json!([
                {"id": "rec-old", "type": "TXT", "content": "\"existing\""},
            ])),
        );

        let create_new = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::Json(json!({
                "ttl": 60,
                "proxied": false,
                "name": "_acme.example.com",
                "type": "TXT",
                "content": "\"new-token\"",
            })))
            .with_status(200)
            .with_body(ok_body())
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
        zone.assert();
        list.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "_acme.example.com",
            "TXT",
            ok_result(json!([
                {"id": "rec-keep", "type": "TXT", "content": "\"keep-me\""},
                {"id": "rec-drop", "type": "TXT", "content": "\"drop-me\""},
            ])),
        );

        let delete = server
            .mock(
                "DELETE",
                format!("/zones/{ZONE_ID}/dns_records/rec-drop").as_str(),
            )
            .with_status(200)
            .with_body(ok_body())
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
        zone.assert();
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_replaces_two_tlsa_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "_25._tcp.mail.example.com",
            "TLSA",
            ok_result(json!([
                {"id": "old-ee", "type": "TLSA", "data": {
                    "usage": 3, "selector": 1, "matching_type": 1, "certificate": "aa"
                }},
                {"id": "old-ta", "type": "TLSA", "data": {
                    "usage": 2, "selector": 1, "matching_type": 1, "certificate": "bb"
                }},
            ])),
        );

        let delete_ee = server
            .mock(
                "DELETE",
                format!("/zones/{ZONE_ID}/dns_records/old-ee").as_str(),
            )
            .with_status(200)
            .with_body(ok_body())
            .create();
        let delete_ta = server
            .mock(
                "DELETE",
                format!("/zones/{ZONE_ID}/dns_records/old-ta").as_str(),
            )
            .with_status(200)
            .with_body(ok_body())
            .create();
        let create_ee = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::PartialJson(json!({
                "data": {"usage": 3, "certificate": "cc"}
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();
        let create_ta = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::PartialJson(json!({
                "data": {"usage": 2, "certificate": "dd"}
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
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
        zone.assert();
        list.assert();
        delete_ee.assert();
        delete_ta.assert();
        create_ee.assert();
        create_ta.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_records_must_match_declared_type() {
        let mut server = mockito::Server::new_async().await;
        let _zone = mock_zone_lookup(&mut server, "example.com");
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
    async fn test_obtain_zone_id_walks_up_to_parent_zone() {
        let mut server = mockito::Server::new_async().await;

        let zone_miss = server
            .mock("GET", "/zones")
            .match_query(Matcher::UrlEncoded("name".into(), "sub.example.com".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"errors":[],"success":true,"result":[]}"#)
            .create();

        let zone_hit = mock_zone_lookup(&mut server, "example.com");

        let list = mock_list(
            &mut server,
            "host.sub.example.com",
            "A",
            ok_result(json!([])),
        );

        let create = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.sub.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "sub.example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone_miss.assert();
        zone_hit.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("GET", "/zones")
            .match_query(Matcher::UrlEncoded("name".into(), "example.com".into()))
            .with_status(401)
            .with_body(
                r#"{"errors":[{"code":10000,"message":"Unauthorized"}],"success":false,"result":[]}"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                3600,
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

    #[tokio::test]
    async fn test_api_success_false_surfaces_as_api_error() {
        let mut server = mockito::Server::new_async().await;
        let failure = server
            .mock("GET", "/zones")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(
                r#"{"errors":[{"code":1003,"message":"Invalid zone identifier"}],"success":false,"result":[]}"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
        failure.assert();
    }

    #[tokio::test]
    async fn test_mx_create_sends_priority_via_set_rrset() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(&mut server, "example.com", "MX", ok_result(json!([])));

        let create = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::Json(json!({
                "ttl": 3600,
                "priority": 10,
                "proxied": false,
                "name": "example.com",
                "type": "MX",
                "content": "mail.example.com",
            })))
            .with_status(200)
            .with_body(ok_body())
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
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_caa_via_set_rrset_uses_data_struct() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(&mut server, "example.com", "CAA", ok_result(json!([])));

        let create = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::Json(json!({
                "ttl": 3600,
                "proxied": false,
                "name": "example.com",
                "type": "CAA",
                "data": {
                    "flags": 0,
                    "tag": "issue",
                    "value": "letsencrypt.org",
                },
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
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
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_srv_via_set_rrset_uses_data_struct() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "_imaps._tcp.example.com",
            "SRV",
            ok_result(json!([])),
        );

        let create = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::Json(json!({
                "ttl": 3600,
                "proxied": false,
                "name": "_imaps._tcp.example.com",
                "type": "SRV",
                "data": {
                    "priority": 10,
                    "weight": 5,
                    "port": 993,
                    "target": "mail.example.com",
                },
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
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
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_list_filter_by_type_protects_other_types_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let list = server
            .mock("GET", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "shared.example.com".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
                Matcher::UrlEncoded("match".into(), "all".into()),
                Matcher::UrlEncoded("per_page".into(), "100".into()),
            ]))
            .with_status(200)
            .with_body(serde_json::to_string(&ok_result(json!([]))).unwrap())
            .expect(1)
            .create();

        // No GET for TXT records and no DELETE: TXT records at the same owner
        // are not even discovered, let alone touched.
        let _txt_get_must_not_fire = server
            .mock("GET", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_query(Matcher::UrlEncoded("type".into(), "TXT".into()))
            .with_status(500)
            .expect(0)
            .create();

        let create = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::PartialJson(json!({
                "name": "shared.example.com",
                "type": "A",
                "content": "1.1.1.1",
            })))
            .with_status(200)
            .with_body(ok_body())
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
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_txt_with_embedded_quotes_roundtrips_correctly() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "test.example.com",
            "TXT",
            ok_result(json!([
                {"id": "rec-1", "type": "TXT", "content": "\"hello \\\"world\\\"\""},
            ])),
        );
        // No POST and no DELETE: the listed record matches what we want.
        let _no_post = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(r#"hello "world""#.to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_is_full_noop_when_everything_present() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "test.example.com",
            "A",
            ok_result(json!([
                {"id": "rec-1", "type": "A", "content": "1.1.1.1"},
                {"id": "rec-2", "type": "A", "content": "8.8.8.8"},
            ])),
        );
        // No POST: nothing to add.
        let _no_post = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
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
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_creates_rrset_from_empty_owner() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(&mut server, "fresh.example.com", "A", ok_result(json!([])));

        let create = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::PartialJson(json!({
                "name": "fresh.example.com",
                "type": "A",
                "content": "9.9.9.9",
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
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
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_noop_when_values_absent() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "test.example.com",
            "A",
            ok_result(json!([
                {"id": "rec-1", "type": "A", "content": "1.1.1.1"},
            ])),
        );
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex(format!("^/zones/{ZONE_ID}/dns_records/")),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_input_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        // No zone lookup, no list, no delete: empty input short-circuits.
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let _no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
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
    async fn test_list_response_tolerates_extra_cloudflare_fields() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "test.example.com",
            "A",
            ok_result(json!([
                {
                    "id": "rec-1",
                    "name": "test.example.com",
                    "type": "A",
                    "content": "1.1.1.1",
                    "ttl": 3600,
                    "proxied": false,
                    "comment": "user added",
                    "tags": ["env:prod"],
                    "meta": {"auto_added": false, "managed_by_apps": false},
                    "created_on": "2024-01-01T00:00:00Z",
                    "modified_on": "2024-01-01T00:00:00Z",
                    "zone_id": ZONE_ID,
                    "zone_name": "example.com",
                    "locked": false,
                },
            ])),
        );
        let _no_mutation = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
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
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_replaces_then_creates_when_completely_different() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "swap.example.com",
            "A",
            ok_result(json!([
                {"id": "old-1", "type": "A", "content": "1.1.1.1"},
                {"id": "old-2", "type": "A", "content": "1.1.1.2"},
            ])),
        );

        let del1 = server
            .mock(
                "DELETE",
                format!("/zones/{ZONE_ID}/dns_records/old-1").as_str(),
            )
            .with_status(200)
            .with_body(ok_body())
            .create();
        let del2 = server
            .mock(
                "DELETE",
                format!("/zones/{ZONE_ID}/dns_records/old-2").as_str(),
            )
            .with_status(200)
            .with_body(ok_body())
            .create();
        let create1 = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::PartialJson(json!({"content": "2.2.2.1"})))
            .with_status(200)
            .with_body(ok_body())
            .create();
        let create2 = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::PartialJson(json!({"content": "2.2.2.2"})))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "swap.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("2.2.2.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        del1.assert();
        del2.assert();
        create1.assert();
        create2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_apex_name_publishes_with_zone_root() {
        // When name == origin, we publish at the zone apex. Cloudflare wants
        // the apex name spelled out (e.g. "example.com"), not "@".
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(&mut server, "example.com", "MX", ok_result(json!([])));

        let create = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::PartialJson(json!({
                "name": "example.com",
                "type": "MX",
                "content": "mail.example.com",
                "priority": 10,
            })))
            .with_status(200)
            .with_body(ok_body())
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
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_with_different_priorities() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(&mut server, "example.com", "MX", ok_result(json!([])));

        let primary = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::PartialJson(json!({
                "priority": 10, "content": "mx1.example.com"
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();
        let backup = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::PartialJson(json!({
                "priority": 20, "content": "mx2.example.com"
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
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
        zone.assert();
        list.assert();
        primary.assert();
        backup.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_long_txt_dkim_key_sent_as_one_quoted_string() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "selector._domainkey.example.com",
            "TXT",
            ok_result(json!([])),
        );

        let long_value: String = "v=DKIM1;k=rsa;p=".to_string() + &"A".repeat(380);
        let expected_sent = format!("\"{}\"", long_value);

        let create = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::PartialJson(json!({
                "type": "TXT",
                "content": expected_sent,
            })))
            .with_status(200)
            .with_body(ok_body())
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
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    #[ignore = "Requires CLOUDFLARE_API_TOKEN and CLOUDFLARE_ORIGIN"]
    async fn integration_test() {
        use crate::providers::cloudflare::DnsContent;

        let token = std::env::var("CLOUDFLARE_API_TOKEN").unwrap_or_default();
        let origin = std::env::var("CLOUDFLARE_ORIGIN").unwrap_or_default();
        assert!(!token.is_empty(), "Set CLOUDFLARE_API_TOKEN");
        assert!(
            !origin.is_empty(),
            "Set CLOUDFLARE_ORIGIN (e.g. example.com)"
        );

        // All test owners live under a unique prefix so concurrent runs from
        // different machines won't trample each other. The whole tree is
        // wiped at the end.
        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let label = |kind: &str| format!("dnsupdate-poc-{run_id}-{kind}.{origin}");
        let srv = |service: &str, kind: &str| {
            format!("_{service}._tcp.dnsupdate-poc-{run_id}-{kind}.{origin}")
        };

        let updater = CloudflareProvider::new(&token, Some(Duration::from_secs(30))).unwrap();

        let assert_contents = |label: String,
                               record_type: DnsRecordType,
                               expected: Vec<DnsContent>| {
            let updater = updater.clone();
            let origin = origin.clone();
            async move {
                let mut got = updater
                    .list_contents_for_tests(label.as_str(), record_type, origin.as_str())
                    .await
                    .unwrap_or_else(|err| panic!("list {label} failed: {err}"));
                let mut want = expected;
                let normalize = |v: &mut Vec<DnsContent>| {
                    v.sort_by_key(|c| serde_json::to_string(c).unwrap_or_default());
                };
                normalize(&mut got);
                normalize(&mut want);
                assert_eq!(
                    got, want,
                    "RRSet at {label}/{record_type:?} mismatch:\n  want: {want:?}\n  got:  {got:?}"
                );
            }
        };

        // ============================================================
        // PHASE 1: A record edge cases
        // ============================================================
        let a_name = label("a");
        let a1 = DnsRecord::A([10, 11, 12, 1].into());
        let a2 = DnsRecord::A([10, 11, 12, 2].into());
        let a3 = DnsRecord::A([10, 11, 12, 3].into());

        eprintln!("[phase 1.1] set_rrset from empty to two A records");
        updater
            .set_rrset(
                a_name.as_str(),
                DnsRecordType::A,
                300,
                vec![a1.clone(), a2.clone()],
                origin.as_str(),
            )
            .await
            .expect("set_rrset initial A");
        assert_contents(
            a_name.clone(),
            DnsRecordType::A,
            vec![
                DnsContent::A {
                    content: [10, 11, 12, 1].into(),
                },
                DnsContent::A {
                    content: [10, 11, 12, 2].into(),
                },
            ],
        )
        .await;

        eprintln!("[phase 1.2] set_rrset with same values must be a no-op");
        updater
            .set_rrset(
                a_name.as_str(),
                DnsRecordType::A,
                300,
                vec![a1.clone(), a2.clone()],
                origin.as_str(),
            )
            .await
            .expect("set_rrset idempotent A");
        assert_contents(
            a_name.clone(),
            DnsRecordType::A,
            vec![
                DnsContent::A {
                    content: [10, 11, 12, 1].into(),
                },
                DnsContent::A {
                    content: [10, 11, 12, 2].into(),
                },
            ],
        )
        .await;

        eprintln!(
            "[phase 1.3] set_rrset to a partially-overlapping set: drops a2, keeps a1, adds a3"
        );
        updater
            .set_rrset(
                a_name.as_str(),
                DnsRecordType::A,
                300,
                vec![a1.clone(), a3.clone()],
                origin.as_str(),
            )
            .await
            .expect("set_rrset partial-overlap A");
        assert_contents(
            a_name.clone(),
            DnsRecordType::A,
            vec![
                DnsContent::A {
                    content: [10, 11, 12, 1].into(),
                },
                DnsContent::A {
                    content: [10, 11, 12, 3].into(),
                },
            ],
        )
        .await;

        eprintln!("[phase 1.4] add_to_rrset adds a2 alongside existing");
        updater
            .add_to_rrset(
                a_name.as_str(),
                DnsRecordType::A,
                300,
                vec![a2.clone()],
                origin.as_str(),
            )
            .await
            .expect("add_to_rrset A");
        assert_contents(
            a_name.clone(),
            DnsRecordType::A,
            vec![
                DnsContent::A {
                    content: [10, 11, 12, 1].into(),
                },
                DnsContent::A {
                    content: [10, 11, 12, 2].into(),
                },
                DnsContent::A {
                    content: [10, 11, 12, 3].into(),
                },
            ],
        )
        .await;

        eprintln!("[phase 1.5] add_to_rrset with already-present value is a no-op");
        updater
            .add_to_rrset(
                a_name.as_str(),
                DnsRecordType::A,
                300,
                vec![a1.clone()],
                origin.as_str(),
            )
            .await
            .expect("add_to_rrset idempotent A");
        assert_contents(
            a_name.clone(),
            DnsRecordType::A,
            vec![
                DnsContent::A {
                    content: [10, 11, 12, 1].into(),
                },
                DnsContent::A {
                    content: [10, 11, 12, 2].into(),
                },
                DnsContent::A {
                    content: [10, 11, 12, 3].into(),
                },
            ],
        )
        .await;

        eprintln!("[phase 1.6] remove_from_rrset removes only a2");
        updater
            .remove_from_rrset(
                a_name.as_str(),
                DnsRecordType::A,
                vec![a2.clone()],
                origin.as_str(),
            )
            .await
            .expect("remove_from_rrset A");
        assert_contents(
            a_name.clone(),
            DnsRecordType::A,
            vec![
                DnsContent::A {
                    content: [10, 11, 12, 1].into(),
                },
                DnsContent::A {
                    content: [10, 11, 12, 3].into(),
                },
            ],
        )
        .await;

        eprintln!("[phase 1.7] remove_from_rrset on absent value is a no-op");
        updater
            .remove_from_rrset(
                a_name.as_str(),
                DnsRecordType::A,
                vec![DnsRecord::A([10, 11, 12, 99].into())],
                origin.as_str(),
            )
            .await
            .expect("remove_from_rrset absent A");
        assert_contents(
            a_name.clone(),
            DnsRecordType::A,
            vec![
                DnsContent::A {
                    content: [10, 11, 12, 1].into(),
                },
                DnsContent::A {
                    content: [10, 11, 12, 3].into(),
                },
            ],
        )
        .await;

        eprintln!("[phase 1.8] set_rrset(empty) wipes the entire RRSet");
        updater
            .set_rrset(
                a_name.as_str(),
                DnsRecordType::A,
                300,
                vec![],
                origin.as_str(),
            )
            .await
            .expect("set_rrset empty A");
        assert_contents(a_name.clone(), DnsRecordType::A, vec![]).await;

        // ============================================================
        // PHASE 2: cross-type isolation
        //   set_rrset on A must NOT touch TXT at the same owner.
        // ============================================================
        let mixed_name = label("mixed");
        let txt_marker = "do-not-delete-me";

        eprintln!(
            "[phase 2.1] seed a TXT record at {mixed_name} that simulates a user-managed record"
        );
        updater
            .set_rrset(
                mixed_name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(txt_marker.to_string())],
                origin.as_str(),
            )
            .await
            .expect("seed TXT");

        eprintln!("[phase 2.2] set_rrset for A at the same owner");
        updater
            .set_rrset(
                mixed_name.as_str(),
                DnsRecordType::A,
                300,
                vec![DnsRecord::A([10, 12, 0, 1].into())],
                origin.as_str(),
            )
            .await
            .expect("set_rrset A under mixed owner");

        eprintln!("[phase 2.3] TXT at {mixed_name} must survive untouched");
        assert_contents(
            mixed_name.clone(),
            DnsRecordType::TXT,
            vec![DnsContent::TXT {
                content: format!("\"{txt_marker}\""),
            }],
        )
        .await;
        assert_contents(
            mixed_name.clone(),
            DnsRecordType::A,
            vec![DnsContent::A {
                content: [10, 12, 0, 1].into(),
            }],
        )
        .await;

        eprintln!("[phase 2.4] cleanup TXT and A at mixed owner");
        updater
            .set_rrset(
                mixed_name.as_str(),
                DnsRecordType::A,
                300,
                vec![],
                origin.as_str(),
            )
            .await
            .expect("cleanup A");
        updater
            .set_rrset(
                mixed_name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![],
                origin.as_str(),
            )
            .await
            .expect("cleanup TXT");

        // ============================================================
        // PHASE 3: TXT with embedded quotes
        // ============================================================
        let txt_name = label("txt");
        let txt_value = r#"v=verify;token="abc;def""#;
        eprintln!("[phase 3.1] set TXT with embedded quotes; rerun must be a no-op");
        updater
            .set_rrset(
                txt_name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(txt_value.to_string())],
                origin.as_str(),
            )
            .await
            .expect("set TXT with quotes");
        updater
            .set_rrset(
                txt_name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(txt_value.to_string())],
                origin.as_str(),
            )
            .await
            .expect("set TXT with quotes (idempotent)");

        let listed = updater
            .list_contents_for_tests(txt_name.as_str(), DnsRecordType::TXT, origin.as_str())
            .await
            .expect("list TXT");
        assert_eq!(
            listed.len(),
            1,
            "expected 1 TXT record after idempotent reruns, got {}",
            listed.len()
        );
        if let DnsContent::TXT { content } = &listed[0] {
            assert!(
                content.contains(r#"abc;def"#),
                "TXT content should preserve embedded chars: got {content}"
            );
        } else {
            panic!("expected TXT content, got {:?}", listed[0]);
        }
        updater
            .set_rrset(
                txt_name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![],
                origin.as_str(),
            )
            .await
            .expect("cleanup TXT");

        // ============================================================
        // PHASE 4: TLSA - the original motivator (two records at same owner)
        // ============================================================
        let tlsa_name = srv("25", "tlsa");
        let leaf = vec![0xaa; 32];
        let intermediate = vec![0xbb; 32];
        let leaf_renewed = vec![0xcc; 32];
        let intermediate_renewed = vec![0xdd; 32];

        eprintln!("[phase 4.1] publish two TLSA records at the same owner in one call");
        updater
            .set_rrset(
                tlsa_name.as_str(),
                DnsRecordType::TLSA,
                300,
                vec![
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneEe,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: leaf.clone(),
                    }),
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneTa,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: intermediate.clone(),
                    }),
                ],
                origin.as_str(),
            )
            .await
            .expect("set_rrset two TLSA");
        let listed = updater
            .list_contents_for_tests(tlsa_name.as_str(), DnsRecordType::TLSA, origin.as_str())
            .await
            .expect("list TLSA");
        assert_eq!(
            listed.len(),
            2,
            "expected 2 TLSA records, got {}",
            listed.len()
        );

        eprintln!(
            "[phase 4.2] cert renewal: same owner gets two new TLSA hashes; old ones must be gone"
        );
        updater
            .set_rrset(
                tlsa_name.as_str(),
                DnsRecordType::TLSA,
                300,
                vec![
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneEe,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: leaf_renewed.clone(),
                    }),
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneTa,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: intermediate_renewed.clone(),
                    }),
                ],
                origin.as_str(),
            )
            .await
            .expect("set_rrset two TLSA renewed");
        let listed = updater
            .list_contents_for_tests(tlsa_name.as_str(), DnsRecordType::TLSA, origin.as_str())
            .await
            .expect("list TLSA after renewal");
        assert_eq!(
            listed.len(),
            2,
            "after renewal expected 2 TLSA, got {}",
            listed.len()
        );
        for content in &listed {
            if let DnsContent::TLSA { data } = content {
                assert!(
                    data.certificate == "cc".repeat(32) || data.certificate == "dd".repeat(32),
                    "TLSA cert data should be the renewed hashes, got {}",
                    data.certificate
                );
            } else {
                panic!("expected TLSA, got {content:?}");
            }
        }
        updater
            .set_rrset(
                tlsa_name.as_str(),
                DnsRecordType::TLSA,
                300,
                vec![],
                origin.as_str(),
            )
            .await
            .expect("cleanup TLSA");

        // ============================================================
        // PHASE 5: MX with two priorities
        // ============================================================
        let mx_name = label("mx");
        eprintln!("[phase 5.1] set two MX records with different priorities");
        updater
            .set_rrset(
                mx_name.as_str(),
                DnsRecordType::MX,
                300,
                vec![
                    DnsRecord::MX(MXRecord {
                        exchange: format!("mx1.{}.", origin),
                        priority: 10,
                    }),
                    DnsRecord::MX(MXRecord {
                        exchange: format!("mx2.{}.", origin),
                        priority: 20,
                    }),
                ],
                origin.as_str(),
            )
            .await
            .expect("set_rrset two MX");
        let listed = updater
            .list_contents_for_tests(mx_name.as_str(), DnsRecordType::MX, origin.as_str())
            .await
            .expect("list MX");
        assert_eq!(listed.len(), 2, "expected 2 MX, got {}", listed.len());
        updater
            .set_rrset(
                mx_name.as_str(),
                DnsRecordType::MX,
                300,
                vec![],
                origin.as_str(),
            )
            .await
            .expect("cleanup MX");

        // ============================================================
        // PHASE 6: SRV at underscore-labeled owner
        // ============================================================
        let srv_name = srv("imaps", "srv");
        eprintln!("[phase 6.1] set SRV at {srv_name}");
        updater
            .set_rrset(
                srv_name.as_str(),
                DnsRecordType::SRV,
                300,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 993,
                    target: format!("mail.{}.", origin),
                })],
                origin.as_str(),
            )
            .await
            .expect("set_rrset SRV");
        let listed = updater
            .list_contents_for_tests(srv_name.as_str(), DnsRecordType::SRV, origin.as_str())
            .await
            .expect("list SRV");
        assert_eq!(listed.len(), 1, "expected 1 SRV, got {}", listed.len());
        updater
            .set_rrset(
                srv_name.as_str(),
                DnsRecordType::SRV,
                300,
                vec![],
                origin.as_str(),
            )
            .await
            .expect("cleanup SRV");

        // ============================================================
        // PHASE 7: long TXT (DKIM-style)
        // ============================================================
        let dkim_name = format!("selector{run_id}._domainkey.{origin}");
        let dkim_value = format!("v=DKIM1;k=rsa;p={}", "A".repeat(390));
        eprintln!(
            "[phase 7.1] publish long TXT (DKIM-shaped, {} bytes)",
            dkim_value.len()
        );
        updater
            .set_rrset(
                dkim_name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(dkim_value.clone())],
                origin.as_str(),
            )
            .await
            .expect("set_rrset long TXT");

        eprintln!("[phase 7.2] rerun must be a no-op (long TXT comparison roundtrips)");
        updater
            .set_rrset(
                dkim_name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(dkim_value)],
                origin.as_str(),
            )
            .await
            .expect("set_rrset long TXT idempotent");
        let listed = updater
            .list_contents_for_tests(dkim_name.as_str(), DnsRecordType::TXT, origin.as_str())
            .await
            .expect("list long TXT");
        assert_eq!(listed.len(), 1, "expected 1 long TXT, got {}", listed.len());
        updater
            .set_rrset(
                dkim_name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![],
                origin.as_str(),
            )
            .await
            .expect("cleanup long TXT");

        // ============================================================
        // PHASE 8: public list_rrset round-trips and add_to_rrset
        //          idempotency under live conditions
        // ============================================================
        let list_name = label("list");

        eprintln!("[phase 8.1] list_rrset on a never-set owner returns empty");
        let empty = updater
            .list_rrset(list_name.as_str(), DnsRecordType::A, origin.as_str())
            .await
            .expect("list_rrset on absent owner");
        assert!(empty.is_empty(), "expected empty, got {empty:?}");

        eprintln!("[phase 8.2] set_rrset then list_rrset round-trips A records");
        let want_addrs = vec![
            DnsRecord::A([10, 90, 0, 1].into()),
            DnsRecord::A([10, 90, 0, 2].into()),
        ];
        updater
            .set_rrset(
                list_name.as_str(),
                DnsRecordType::A,
                300,
                want_addrs.clone(),
                origin.as_str(),
            )
            .await
            .expect("set A");
        let mut got_addrs = updater
            .list_rrset(list_name.as_str(), DnsRecordType::A, origin.as_str())
            .await
            .expect("list A");
        got_addrs.sort_by_key(|r| match r {
            DnsRecord::A(a) => *a,
            _ => unreachable!(),
        });
        let mut want_sorted = want_addrs.clone();
        want_sorted.sort_by_key(|r| match r {
            DnsRecord::A(a) => *a,
            _ => unreachable!(),
        });
        assert_eq!(got_addrs, want_sorted, "list_rrset A roundtrip mismatch");

        eprintln!("[phase 8.3] add_to_rrset with already-present value is a no-op");
        updater
            .add_to_rrset(
                list_name.as_str(),
                DnsRecordType::A,
                300,
                vec![DnsRecord::A([10, 90, 0, 1].into())],
                origin.as_str(),
            )
            .await
            .expect("add existing");
        let after_dup_add = updater
            .list_rrset(list_name.as_str(), DnsRecordType::A, origin.as_str())
            .await
            .expect("list after dup add");
        assert_eq!(
            after_dup_add.len(),
            2,
            "add_to_rrset re-added an existing value: {after_dup_add:?}"
        );

        eprintln!("[phase 8.4] add_to_rrset with a new value increments");
        updater
            .add_to_rrset(
                list_name.as_str(),
                DnsRecordType::A,
                300,
                vec![DnsRecord::A([10, 90, 0, 3].into())],
                origin.as_str(),
            )
            .await
            .expect("add new");
        let mut after_new_add = updater
            .list_rrset(list_name.as_str(), DnsRecordType::A, origin.as_str())
            .await
            .expect("list after new add");
        after_new_add.sort_by_key(|r| match r {
            DnsRecord::A(a) => *a,
            _ => unreachable!(),
        });
        assert_eq!(
            after_new_add,
            vec![
                DnsRecord::A([10, 90, 0, 1].into()),
                DnsRecord::A([10, 90, 0, 2].into()),
                DnsRecord::A([10, 90, 0, 3].into()),
            ]
        );

        eprintln!("[phase 8.5] remove_from_rrset then list_rrset");
        updater
            .remove_from_rrset(
                list_name.as_str(),
                DnsRecordType::A,
                vec![DnsRecord::A([10, 90, 0, 2].into())],
                origin.as_str(),
            )
            .await
            .expect("remove A2");
        let mut after_remove = updater
            .list_rrset(list_name.as_str(), DnsRecordType::A, origin.as_str())
            .await
            .expect("list after remove");
        after_remove.sort_by_key(|r| match r {
            DnsRecord::A(a) => *a,
            _ => unreachable!(),
        });
        assert_eq!(
            after_remove,
            vec![
                DnsRecord::A([10, 90, 0, 1].into()),
                DnsRecord::A([10, 90, 0, 3].into()),
            ]
        );

        eprintln!("[phase 8.6] list_rrset round-trips a TLSA record by value");
        let tlsa_list_name = srv("443", "tlsa-list");
        let tlsa_record = DnsRecord::TLSA(TLSARecord {
            cert_usage: TlsaCertUsage::DaneEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            cert_data: vec![0x77; 32],
        });
        updater
            .set_rrset(
                tlsa_list_name.as_str(),
                DnsRecordType::TLSA,
                300,
                vec![tlsa_record.clone()],
                origin.as_str(),
            )
            .await
            .expect("set TLSA");
        let tlsa_listed = updater
            .list_rrset(
                tlsa_list_name.as_str(),
                DnsRecordType::TLSA,
                origin.as_str(),
            )
            .await
            .expect("list TLSA");
        assert_eq!(
            tlsa_listed,
            vec![tlsa_record],
            "list_rrset TLSA roundtrip mismatch"
        );

        eprintln!("[phase 8.7] cleanup");
        updater
            .set_rrset(
                list_name.as_str(),
                DnsRecordType::A,
                300,
                vec![],
                origin.as_str(),
            )
            .await
            .expect("cleanup list A");
        updater
            .set_rrset(
                tlsa_list_name.as_str(),
                DnsRecordType::TLSA,
                300,
                vec![],
                origin.as_str(),
            )
            .await
            .expect("cleanup TLSA");

        eprintln!("[done] all live edge-case phases passed");
    }
}
