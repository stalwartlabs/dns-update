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
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, SRVRecord, TLSARecord,
        TlsaCertUsage, TlsaMatching, TlsaSelector, providers::scaleway::ScalewayProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> ScalewayProvider {
        ScalewayProvider::new("test_token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    fn mock_patch(server: &mut ServerGuard, body: serde_json::Value) -> Mock {
        server
            .mock("PATCH", "/dns-zones/example.com/records")
            .match_header("x-auth-token", "test_token")
            .match_body(Matcher::Json(body))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create()
    }

    fn mock_list(
        server: &mut ServerGuard,
        zone: &str,
        name: &str,
        record_type: &str,
        body: serde_json::Value,
    ) -> Mock {
        server
            .mock("GET", format!("/dns-zones/{zone}/records").as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), name.into()),
                Matcher::UrlEncoded("type".into(), record_type.into()),
            ]))
            .match_header("x-auth-token", "test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_sends_single_set_change() {
        let mut server = mockito::Server::new_async().await;
        let patch = mock_patch(
            &mut server,
            json!({
                "return_all_records": false,
                "disallow_new_zone_creation": true,
                "changes": [{
                    "set": {
                        "id_fields": {"name": "www", "type": "A"},
                        "records": [
                            {"name": "www", "type": "A", "data": "1.1.1.1", "ttl": 300},
                            {"name": "www", "type": "A", "data": "8.8.8.8", "ttl": 300},
                        ]
                    }
                }]
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
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
        patch.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_vec_is_deletion() {
        let mut server = mockito::Server::new_async().await;
        let patch = mock_patch(
            &mut server,
            json!({
                "return_all_records": false,
                "disallow_new_zone_creation": true,
                "changes": [{
                    "delete": {
                        "id_fields": {"name": "gone", "type": "A"}
                    }
                }]
            }),
        );

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
        patch.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_apex_uses_at_sign() {
        let mut server = mockito::Server::new_async().await;
        let patch = mock_patch(
            &mut server,
            json!({
                "return_all_records": false,
                "disallow_new_zone_creation": true,
                "changes": [{
                    "set": {
                        "id_fields": {"name": "@", "type": "MX"},
                        "records": [{
                            "name": "@",
                            "type": "MX",
                            "data": "10 mail.example.com.",
                            "ttl": 3600,
                            "priority": 10,
                        }]
                    }
                }]
            }),
        );

        let provider = setup_provider(server.url());
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

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        patch.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_with_two_priorities() {
        let mut server = mockito::Server::new_async().await;
        let patch = mock_patch(
            &mut server,
            json!({
                "return_all_records": false,
                "disallow_new_zone_creation": true,
                "changes": [{
                    "set": {
                        "id_fields": {"name": "@", "type": "MX"},
                        "records": [
                            {"name": "@", "type": "MX", "data": "10 mail1.example.com.", "ttl": 3600, "priority": 10},
                            {"name": "@", "type": "MX", "data": "20 mail2.example.com.", "ttl": 3600, "priority": 20},
                        ]
                    }
                }]
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![
                    DnsRecord::MX(MXRecord {
                        exchange: "mail1.example.com.".to_string(),
                        priority: 10,
                    }),
                    DnsRecord::MX(MXRecord {
                        exchange: "mail2.example.com.".to_string(),
                        priority: 20,
                    }),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        patch.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_three_field_data() {
        let mut server = mockito::Server::new_async().await;
        let patch = mock_patch(
            &mut server,
            json!({
                "return_all_records": false,
                "disallow_new_zone_creation": true,
                "changes": [{
                    "set": {
                        "id_fields": {"name": "_imaps._tcp", "type": "SRV"},
                        "records": [{
                            "name": "_imaps._tcp",
                            "type": "SRV",
                            "data": "5 993 mail.example.com",
                            "ttl": 3600,
                            "priority": 10,
                        }]
                    }
                }]
            }),
        );

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
        patch.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_uses_bind_form() {
        let mut server = mockito::Server::new_async().await;
        let patch = mock_patch(
            &mut server,
            json!({
                "return_all_records": false,
                "disallow_new_zone_creation": true,
                "changes": [{
                    "set": {
                        "id_fields": {"name": "_25._tcp.mail", "type": "TLSA"},
                        "records": [{
                            "name": "_25._tcp.mail",
                            "type": "TLSA",
                            "data": "3 1 1 ff",
                            "ttl": 3600,
                        }]
                    }
                }]
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                3600,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xff],
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        patch.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_uses_bind_form() {
        let mut server = mockito::Server::new_async().await;
        let patch = mock_patch(
            &mut server,
            json!({
                "return_all_records": false,
                "disallow_new_zone_creation": true,
                "changes": [{
                    "set": {
                        "id_fields": {"name": "@", "type": "CAA"},
                        "records": [{
                            "name": "@",
                            "type": "CAA",
                            "data": "0 issue \"letsencrypt.org\"",
                            "ttl": 3600,
                        }]
                    }
                }]
            }),
        );

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
        patch.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_txt_quotes_value() {
        let mut server = mockito::Server::new_async().await;
        let patch = mock_patch(
            &mut server,
            json!({
                "return_all_records": false,
                "disallow_new_zone_creation": true,
                "changes": [{
                    "set": {
                        "id_fields": {"name": "_acme-challenge", "type": "TXT"},
                        "records": [{
                            "name": "_acme-challenge",
                            "type": "TXT",
                            "data": "\"v=spf1 -all\"",
                            "ttl": 300,
                        }]
                    }
                }]
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("v=spf1 -all".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        patch.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_records_must_match_declared_type() {
        let server = mockito::Server::new_async().await;
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
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("RRSet record type mismatch")),
            "expected Api(type mismatch), got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_add_to_rrset_sends_add_change() {
        let mut server = mockito::Server::new_async().await;
        let patch = mock_patch(
            &mut server,
            json!({
                "return_all_records": false,
                "disallow_new_zone_creation": true,
                "changes": [{
                    "add": {
                        "records": [
                            {"name": "www", "type": "A", "data": "1.1.1.1", "ttl": 300},
                            {"name": "www", "type": "A", "data": "2.2.2.2", "ttl": 300},
                        ]
                    }
                }]
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        patch.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let must_not_fire = server
            .mock("PATCH", "/dns-zones/example.com/records")
            .expect(0)
            .with_status(500)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        must_not_fire.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_type_mismatch() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Api error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_remove_from_rrset_sends_delete_per_record() {
        let mut server = mockito::Server::new_async().await;
        let patch = mock_patch(
            &mut server,
            json!({
                "return_all_records": false,
                "disallow_new_zone_creation": true,
                "changes": [
                    {"delete": {"id_fields": {"name": "www", "type": "A", "data": "1.1.1.1"}}},
                    {"delete": {"id_fields": {"name": "www", "type": "A", "data": "2.2.2.2"}}},
                ]
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        patch.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let must_not_fire = server
            .mock("PATCH", "/dns-zones/example.com/records")
            .expect(0)
            .with_status(500)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset("www.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        must_not_fire.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_type_mismatch() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Api error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_list_rrset_returns_a_records() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "www",
            "A",
            json!({
                "total_count": 2,
                "records": [
                    {"id": "id-1", "name": "www", "type": "A", "data": "1.1.1.1", "ttl": 300, "priority": 0},
                    {"id": "id-2", "name": "www", "type": "A", "data": "8.8.8.8", "ttl": 300, "priority": 0},
                ]
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(records.contains(&DnsRecord::A("8.8.8.8".parse().unwrap())));
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_apex_uses_at() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "@",
            "MX",
            json!({
                "total_count": 1,
                "records": [
                    {"id": "id-1", "name": "@", "type": "MX", "data": "10 mail.example.com.", "ttl": 3600, "priority": 10}
                ]
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0],
            DnsRecord::MX(MXRecord {
                priority: 10,
                exchange: "mail.example.com".to_string(),
            })
        );
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_filters_out_other_types() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "shared",
            "A",
            json!({
                "total_count": 1,
                "records": [
                    {"id": "id-1", "name": "shared", "type": "A", "data": "1.1.1.1", "ttl": 300, "priority": 0}
                ]
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("shared.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 1);
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_empty_response() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            "missing",
            "A",
            json!({"total_count": 0, "records": []}),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("missing.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        assert!(result.unwrap().is_empty());
        list.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("PATCH", "/dns-zones/example.com/records")
            .with_status(401)
            .with_body(r#"{"message":"denied authentication"}"#)
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
    #[ignore = "Requires Scaleway API token, zone, and FQDN"]
    async fn integration_test() {
        let token = std::env::var("SCALEWAY_API_TOKEN").unwrap_or_default();
        let origin = std::env::var("SCALEWAY_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("SCALEWAY_FQDN").unwrap_or_default();

        assert!(!token.is_empty(), "Set SCALEWAY_API_TOKEN to run this test");
        assert!(!origin.is_empty(), "Set SCALEWAY_ORIGIN to run this test");
        assert!(!fqdn.is_empty(), "Set SCALEWAY_FQDN to run this test");

        let updater = DnsUpdater::new_scaleway(token, Some(Duration::from_secs(30))).unwrap();

        let set_result = updater
            .set_rrset(
                &fqdn,
                DnsRecordType::A,
                300,
                vec![DnsRecord::A([1, 1, 1, 1].into())],
                &origin,
            )
            .await;
        assert!(set_result.is_ok(), "set_rrset failed: {set_result:?}");

        let add_result = updater
            .add_to_rrset(
                &fqdn,
                DnsRecordType::A,
                300,
                vec![DnsRecord::A([8, 8, 8, 8].into())],
                &origin,
            )
            .await;
        assert!(add_result.is_ok(), "add_to_rrset failed: {add_result:?}");

        let remove_result = updater
            .remove_from_rrset(
                &fqdn,
                DnsRecordType::A,
                vec![DnsRecord::A([8, 8, 8, 8].into())],
                &origin,
            )
            .await;
        assert!(
            remove_result.is_ok(),
            "remove_from_rrset failed: {remove_result:?}"
        );

        let delete_result = updater
            .set_rrset(&fqdn, DnsRecordType::A, 300, vec![], &origin)
            .await;
        assert!(
            delete_result.is_ok(),
            "set_rrset(empty) failed: {delete_result:?}"
        );
    }
}
