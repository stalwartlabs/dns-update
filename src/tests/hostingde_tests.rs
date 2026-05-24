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
        TlsaMatching, TlsaSelector, providers::hostingde::HostingDeProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> HostingDeProvider {
        HostingDeProvider::new("auth-token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    fn zone_find_response() -> String {
        json!({
            "status": "success",
            "errors": [],
            "response": {
                "data": [{
                    "id": "zone-1",
                    "name": "example.com",
                    "status": "active"
                }]
            }
        })
        .to_string()
    }

    fn mock_zone(server: &mut ServerGuard) -> Mock {
        server
            .mock("POST", "/zoneConfigsFind")
            .match_body(Matcher::PartialJson(json!({
                "authToken": "auth-token",
                "filter": {"field": "zoneName", "value": "example.com"},
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(zone_find_response())
            .create()
    }

    fn mock_records_find(
        server: &mut ServerGuard,
        name: &str,
        record_type: &str,
        records: serde_json::Value,
    ) -> Mock {
        server
            .mock("POST", "/recordsFind")
            .match_body(Matcher::PartialJson(json!({
                "authToken": "auth-token",
                "filter": {
                    "subFilterConnective": "AND",
                    "subFilter": [
                        {"field": "zoneConfigId", "value": "zone-1"},
                        {"field": "recordName", "value": name},
                        {"field": "recordType", "value": record_type},
                    ],
                },
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "status": "success",
                    "errors": [],
                    "response": {"data": records},
                })
                .to_string(),
            )
            .create()
    }

    fn ok_update_body() -> &'static str {
        r#"{"status":"success","errors":[],"response":{}}"#
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(&mut server, "fresh.example.com", "A", json!([]));

        let update = server
            .mock("POST", "/zoneUpdate")
            .match_body(Matcher::PartialJson(json!({
                "recordsToAdd": [
                    {"name": "fresh.example.com", "type": "A", "content": "1.1.1.1", "ttl": 300},
                    {"name": "fresh.example.com", "type": "A", "content": "2.2.2.2", "ttl": 300},
                ]
            })))
            .with_status(200)
            .with_body(ok_update_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "fresh.example.com",
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
        zone.assert();
        list.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(
            &mut server,
            "test.example.com",
            "A",
            json!([{
                "id": "rec-1",
                "name": "test.example.com",
                "type": "A",
                "content": "1.1.1.1",
                "ttl": 300
            }]),
        );
        let _no_update = server.mock("POST", "/zoneUpdate").expect(0).create();

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
        let zone = mock_zone(&mut server);
        let list = mock_records_find(
            &mut server,
            "host.example.com",
            "A",
            json!([
                {"id": "rec-keep", "name": "host.example.com", "type": "A", "content": "1.1.1.1"},
                {"id": "rec-stale", "name": "host.example.com", "type": "A", "content": "9.9.9.9"},
            ]),
        );

        let update = server
            .mock("POST", "/zoneUpdate")
            .match_body(Matcher::AllOf(vec![
                Matcher::PartialJson(json!({
                    "recordsToAdd": [
                        {"name": "host.example.com", "type": "A", "content": "8.8.8.8", "ttl": 300},
                    ],
                })),
                Matcher::PartialJson(json!({
                    "recordsToDelete": [
                        {"id": "rec-stale", "name": "host.example.com", "type": "A", "content": "9.9.9.9"},
                    ],
                })),
            ]))
            .with_status(200)
            .with_body(ok_update_body())
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
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_records_deletes_all() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(
            &mut server,
            "gone.example.com",
            "A",
            json!([
                {"id": "rec-x", "name": "gone.example.com", "type": "A", "content": "1.2.3.4"},
                {"id": "rec-y", "name": "gone.example.com", "type": "A", "content": "5.6.7.8"},
            ]),
        );

        let update = server
            .mock("POST", "/zoneUpdate")
            .match_body(Matcher::AllOf(vec![Matcher::PartialJson(json!({
                "recordsToDelete": [
                    {"id": "rec-x", "name": "gone.example.com", "type": "A", "content": "1.2.3.4"},
                    {"id": "rec-y", "name": "gone.example.com", "type": "A", "content": "5.6.7.8"},
                ],
            }))]))
            .with_status(200)
            .with_body(ok_update_body())
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
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_records_noop_when_already_empty() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(&mut server, "gone.example.com", "A", json!([]));
        let _no_update = server.mock("POST", "/zoneUpdate").expect(0).create();

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
    }

    #[tokio::test]
    async fn test_set_rrset_records_must_match_declared_type() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("POST", Matcher::Any).expect(0).create();

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
    async fn test_add_to_rrset_empty_input_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("POST", Matcher::Any).expect(0).create();

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
        let zone = mock_zone(&mut server);
        let list = mock_records_find(
            &mut server,
            "_acme.example.com",
            "TXT",
            json!([
                {"id": "rec-old", "name": "_acme.example.com", "type": "TXT", "content": "\"existing\""},
            ]),
        );

        let update = server
            .mock("POST", "/zoneUpdate")
            .match_body(Matcher::PartialJson(json!({
                "recordsToAdd": [
                    {"name": "_acme.example.com", "type": "TXT", "content": "\"new-token\"", "ttl": 60}
                ]
            })))
            .with_status(200)
            .with_body(ok_update_body())
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
        update.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_full_noop_when_everything_present() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(
            &mut server,
            "test.example.com",
            "A",
            json!([
                {"id": "rec-1", "name": "test.example.com", "type": "A", "content": "1.1.1.1"},
                {"id": "rec-2", "name": "test.example.com", "type": "A", "content": "8.8.8.8"},
            ]),
        );
        let _no_update = server.mock("POST", "/zoneUpdate").expect(0).create();

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
    async fn test_remove_from_rrset_empty_input_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("POST", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(
            &mut server,
            "_acme.example.com",
            "TXT",
            json!([
                {"id": "rec-keep", "name": "_acme.example.com", "type": "TXT", "content": "\"keep-me\""},
                {"id": "rec-drop", "name": "_acme.example.com", "type": "TXT", "content": "\"drop-me\""},
            ]),
        );

        let update = server
            .mock("POST", "/zoneUpdate")
            .match_body(Matcher::PartialJson(json!({
                "recordsToDelete": [
                    {"id": "rec-drop", "name": "_acme.example.com", "type": "TXT", "content": "\"drop-me\""}
                ]
            })))
            .with_status(200)
            .with_body(ok_update_body())
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
        update.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_noop_when_values_absent() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(
            &mut server,
            "test.example.com",
            "A",
            json!([
                {"id": "rec-1", "name": "test.example.com", "type": "A", "content": "1.1.1.1"},
            ]),
        );
        let _no_update = server.mock("POST", "/zoneUpdate").expect(0).create();

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
    async fn test_list_rrset_returns_records() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(
            &mut server,
            "test.example.com",
            "A",
            json!([
                {"id": "rec-1", "name": "test.example.com", "type": "A", "content": "1.1.1.1"},
                {"id": "rec-2", "name": "test.example.com", "type": "A", "content": "2.2.2.2"},
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("test.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], DnsRecord::A("1.1.1.1".parse().unwrap()));
        assert_eq!(result[1], DnsRecord::A("2.2.2.2".parse().unwrap()));
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_cross_type_isolation_only_filters_requested_type() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(&mut server, "shared.example.com", "A", json!([]));
        let _no_other_type = server
            .mock("POST", "/recordsFind")
            .match_body(Matcher::PartialJson(json!({
                "filter": {"subFilter": [
                    {"field": "zoneConfigId", "value": "zone-1"},
                    {"field": "recordName", "value": "shared.example.com"},
                    {"field": "recordType", "value": "TXT"},
                ]},
            })))
            .expect(0)
            .create();

        let update = server
            .mock("POST", "/zoneUpdate")
            .match_body(Matcher::PartialJson(json!({
                "recordsToAdd": [
                    {"name": "shared.example.com", "type": "A", "content": "1.1.1.1", "ttl": 300}
                ]
            })))
            .with_status(200)
            .with_body(ok_update_body())
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
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_long_txt_is_chunked() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(
            &mut server,
            "selector._domainkey.example.com",
            "TXT",
            json!([]),
        );

        let long_value: String = "v=DKIM1;k=rsa;p=".to_string() + &"A".repeat(380);
        let mut expected_content = String::new();
        crate::utils::txt_chunks_to_text(&mut expected_content, &long_value, " ");
        assert!(
            expected_content.contains("\" \""),
            "expected chunked output to contain a quoted-string separator, got {expected_content}"
        );

        let update = server
            .mock("POST", "/zoneUpdate")
            .match_body(Matcher::PartialJson(json!({
                "recordsToAdd": [
                    {
                        "name": "selector._domainkey.example.com",
                        "type": "TXT",
                        "content": expected_content,
                        "ttl": 300,
                    }
                ]
            })))
            .with_status(200)
            .with_body(ok_update_body())
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
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_is_supported() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(&mut server, "_25._tcp.mail.example.com", "TLSA", json!([]));

        let update = server
            .mock("POST", "/zoneUpdate")
            .match_body(Matcher::PartialJson(json!({
                "recordsToAdd": [
                    {
                        "name": "_25._tcp.mail.example.com",
                        "type": "TLSA",
                        "content": "3 1 1 aabbcc",
                        "ttl": 300,
                    }
                ]
            })))
            .with_status(200)
            .with_body(ok_update_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xaa, 0xbb, 0xcc],
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_two_tlsa_at_same_owner_replaces() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(
            &mut server,
            "_25._tcp.mail.example.com",
            "TLSA",
            json!([
                {"id": "old-ee", "name": "_25._tcp.mail.example.com", "type": "TLSA", "content": "3 1 1 aa"},
                {"id": "old-ta", "name": "_25._tcp.mail.example.com", "type": "TLSA", "content": "2 1 1 bb"},
            ]),
        );

        let update = server
            .mock("POST", "/zoneUpdate")
            .match_body(Matcher::AllOf(vec![
                Matcher::PartialJson(json!({
                    "recordsToAdd": [
                        {"type": "TLSA", "content": "3 1 1 cc"},
                        {"type": "TLSA", "content": "2 1 1 dd"},
                    ],
                })),
                Matcher::PartialJson(json!({
                    "recordsToDelete": [
                        {"id": "old-ee"},
                        {"id": "old-ta"},
                    ],
                })),
            ]))
            .with_status(200)
            .with_body(ok_update_body())
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
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_with_priorities() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(&mut server, "example.com", "MX", json!([]));

        let update = server
            .mock("POST", "/zoneUpdate")
            .match_body(Matcher::PartialJson(json!({
                "recordsToAdd": [
                    {"name": "example.com", "type": "MX", "content": "mx1.example.com", "ttl": 3600, "priority": 10},
                    {"name": "example.com", "type": "MX", "content": "mx2.example.com", "ttl": 3600, "priority": 20},
                ]
            })))
            .with_status(200)
            .with_body(ok_update_body())
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
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(&mut server, "_imaps._tcp.example.com", "SRV", json!([]));

        let update = server
            .mock("POST", "/zoneUpdate")
            .match_body(Matcher::PartialJson(json!({
                "recordsToAdd": [
                    {
                        "name": "_imaps._tcp.example.com",
                        "type": "SRV",
                        "content": "5 993 mail.example.com",
                        "ttl": 3600,
                        "priority": 10
                    }
                ]
            })))
            .with_status(200)
            .with_body(ok_update_body())
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
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(&mut server, "example.com", "CAA", json!([]));

        let update = server
            .mock("POST", "/zoneUpdate")
            .match_body(Matcher::PartialJson(json!({
                "recordsToAdd": [
                    {
                        "name": "example.com",
                        "type": "CAA",
                        "content": "0 issue \"letsencrypt.org\"",
                        "ttl": 3600,
                    }
                ]
            })))
            .with_status(200)
            .with_body(ok_update_body())
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
        update.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_mixed_types() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_records_find(
            &mut server,
            "example.com",
            "MX",
            json!([
                {"id": "rec-1", "name": "example.com", "type": "MX", "content": "mail.example.com", "priority": 10},
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .expect("list_rrset");
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            DnsRecord::MX(MXRecord {
                exchange: "mail.example.com".to_string(),
                priority: 10,
            })
        );
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    #[ignore = "Requires HOSTINGDE_API_KEY, HOSTINGDE_ORIGIN, HOSTINGDE_FQDN env vars"]
    async fn integration_test() {
        let api_key = std::env::var("HOSTINGDE_API_KEY").unwrap_or_default();
        let origin = std::env::var("HOSTINGDE_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("HOSTINGDE_FQDN").unwrap_or_default();
        assert!(!api_key.is_empty(), "Set HOSTINGDE_API_KEY");
        assert!(!origin.is_empty(), "Set HOSTINGDE_ORIGIN");
        assert!(!fqdn.is_empty(), "Set HOSTINGDE_FQDN");

        let provider = HostingDeProvider::new(api_key, Some(Duration::from_secs(30)));

        let a1 = DnsRecord::A([10, 11, 12, 1].into());
        let a2 = DnsRecord::A([10, 11, 12, 2].into());
        let a3 = DnsRecord::A([10, 11, 12, 3].into());

        provider
            .set_rrset(
                &fqdn,
                DnsRecordType::A,
                300,
                vec![a1.clone(), a2.clone()],
                &origin,
            )
            .await
            .expect("set_rrset initial");

        let listed = provider
            .list_rrset(&fqdn, DnsRecordType::A, &origin)
            .await
            .expect("list");
        assert_eq!(listed.len(), 2);

        provider
            .set_rrset(
                &fqdn,
                DnsRecordType::A,
                300,
                vec![a1.clone(), a2.clone()],
                &origin,
            )
            .await
            .expect("set_rrset idempotent");

        provider
            .add_to_rrset(&fqdn, DnsRecordType::A, 300, vec![a3.clone()], &origin)
            .await
            .expect("add_to_rrset");
        let listed = provider
            .list_rrset(&fqdn, DnsRecordType::A, &origin)
            .await
            .expect("list");
        assert_eq!(listed.len(), 3);

        provider
            .remove_from_rrset(&fqdn, DnsRecordType::A, vec![a2.clone()], &origin)
            .await
            .expect("remove_from_rrset");

        provider
            .set_rrset(&fqdn, DnsRecordType::A, 300, vec![], &origin)
            .await
            .expect("cleanup");

        let listed = provider
            .list_rrset(&fqdn, DnsRecordType::A, &origin)
            .await
            .expect("list after cleanup");
        assert!(listed.is_empty(), "expected empty, got {listed:?}");
    }
}
