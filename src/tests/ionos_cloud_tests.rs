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
        TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector,
        providers::ionos_cloud::{IonosCloudProvider, build_record, record_from_api},
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::{Value, json};
    use std::time::Duration;

    const ZONE_ID: &str = "zone-1";
    const RECORDS_PATH: &str = "/zones/zone-1/records";

    fn setup_provider(endpoint: String) -> IonosCloudProvider {
        IonosCloudProvider::new("test_token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    fn mock_zones(server: &mut ServerGuard, zones: Value) -> Mock {
        server
            .mock("GET", "/zones")
            .match_header("authorization", "Bearer test_token")
            .match_query(Matcher::UrlEncoded("limit".into(), "1000".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({"items": zones}).to_string())
            .create()
    }

    fn zone(zone_name: &str) -> Value {
        json!({
            "id": ZONE_ID,
            "type": "zone",
            "properties": {"zoneName": zone_name}
        })
    }

    fn mock_records(server: &mut ServerGuard, items: Value) -> Mock {
        server
            .mock("GET", RECORDS_PATH)
            .match_header("authorization", "Bearer test_token")
            .match_query(Matcher::UrlEncoded("limit".into(), "1000".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({"items": items}).to_string())
            .create()
    }

    fn api_record(name: &str, record_type: &str, content: &str, ttl: u32) -> Value {
        json!({
            "id": "record-1",
            "type": "record",
            "properties": {
                "name": name,
                "type": record_type,
                "content": content,
                "ttl": ttl,
                "enabled": true
            }
        })
    }

    fn record_response(properties: &Value) -> String {
        json!({"id": "record-new", "type": "record", "properties": properties}).to_string()
    }

    #[tokio::test]
    async fn test_set_creates_record_with_cloud_api_shape() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zones(&mut server, json!([zone("example.com")]));
        let records = mock_records(&mut server, json!([]));
        let body = json!({
            "properties": {
                "name": "www",
                "type": "A",
                "content": "192.0.2.1",
                "ttl": 60,
                "enabled": true
            }
        });
        let create = server
            .mock("POST", RECORDS_PATH)
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(body.clone()))
            .with_status(202)
            .with_body(record_response(&body["properties"]))
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                1,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zones.assert();
        records.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_updates_existing_record_by_id() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zones(&mut server, json!([zone("example.com")]));
        let records = mock_records(
            &mut server,
            json!([api_record("www", "A", "192.0.2.1", 300)]),
        );
        let body = json!({
            "properties": {
                "name": "www",
                "type": "A",
                "content": "192.0.2.2",
                "ttl": 300,
                "enabled": true
            }
        });
        let update = server
            .mock("PUT", "/zones/zone-1/records/record-1")
            .match_body(Matcher::Json(body.clone()))
            .with_status(202)
            .with_body(record_response(&body["properties"]))
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("192.0.2.2".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zones.assert();
        records.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_set_empty_rrset_deletes_records() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zones(&mut server, json!([zone("example.com")]));
        let records = mock_records(
            &mut server,
            json!([api_record("www", "A", "192.0.2.1", 300)]),
        );
        let delete = server
            .mock("DELETE", "/zones/zone-1/records/record-1")
            .with_status(202)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zones.assert();
        records.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_reads_cloud_properties() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zones(&mut server, json!([zone("example.com")]));
        let records = mock_records(
            &mut server,
            json!([
                {
                    "id": "mx-1",
                    "type": "record",
                    "properties": {
                        "name": "mail",
                        "type": "MX",
                        "content": "mx.example.com",
                        "ttl": 3600,
                        "priority": 10,
                        "enabled": true
                    }
                },
                {
                    "id": "mx-2",
                    "type": "record",
                    "properties": {
                        "name": "mail",
                        "type": "MX",
                        "content": "mx2.example.com",
                        "ttl": 3600,
                        "priority": 20,
                        "enabled": true
                    }
                },
                api_record("unrelated", "MX", "ignored.example.com", 3600)
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("mail.example.com", DnsRecordType::MX, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        assert_eq!(
            result.unwrap(),
            vec![
                DnsRecord::MX(MXRecord {
                    exchange: "mx.example.com".to_string(),
                    priority: 10,
                }),
                DnsRecord::MX(MXRecord {
                    exchange: "mx2.example.com".to_string(),
                    priority: 20,
                })
            ]
        );
        zones.assert();
        records.assert();
    }

    #[tokio::test]
    async fn test_zone_and_record_lists_follow_cursor_pagination() {
        let mut server = mockito::Server::new_async().await;
        let first_zone_page = server
            .mock("GET", "/zones")
            .match_query(Matcher::UrlEncoded("limit".into(), "1000".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "items": [{
                        "id": "zone-parent",
                        "type": "zone",
                        "properties": {"zoneName": "example.com"}
                    }],
                    "pagination": {"token": "zones-next"}
                })
                .to_string(),
            )
            .create();
        let second_zone_page = server
            .mock("GET", "/zones")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("limit".into(), "1000".into()),
                Matcher::UrlEncoded("pagination.token".into(), "zones-next".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "items": [{
                        "id": "zone-sub",
                        "type": "zone",
                        "properties": {"zoneName": "Sub.Example.COM."}
                    }]
                })
                .to_string(),
            )
            .create();
        let first_record_page = server
            .mock("GET", "/zones/zone-sub/records")
            .match_query(Matcher::UrlEncoded("limit".into(), "1000".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({"items": [], "pagination": {"token": "records-next"}}).to_string())
            .create();
        let second_record_page = server
            .mock("GET", "/zones/zone-sub/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("limit".into(), "1000".into()),
                Matcher::UrlEncoded("pagination.token".into(), "records-next".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({"items": [api_record("", "A", "192.0.2.8", 300)]}).to_string())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("SUB.example.com.", DnsRecordType::A, "EXAMPLE.COM.")
            .await;

        assert_eq!(
            result.unwrap(),
            vec![DnsRecord::A("192.0.2.8".parse().unwrap())]
        );
        first_zone_page.assert();
        second_zone_page.assert();
        first_record_page.assert();
        second_record_page.assert();
    }

    #[test]
    fn test_record_variants_round_trip() {
        let records = vec![
            (DnsRecord::A("192.0.2.1".parse().unwrap()), DnsRecordType::A),
            (
                DnsRecord::AAAA("2001:db8::1".parse().unwrap()),
                DnsRecordType::AAAA,
            ),
            (
                DnsRecord::CNAME("target.example.com".to_string()),
                DnsRecordType::CNAME,
            ),
            (
                DnsRecord::NS("ns.example.com".to_string()),
                DnsRecordType::NS,
            ),
            (
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                }),
                DnsRecordType::MX,
            ),
            (DnsRecord::TXT("plain text".to_string()), DnsRecordType::TXT),
            (
                DnsRecord::SRV(SRVRecord {
                    priority: 5,
                    weight: 6,
                    port: 443,
                    target: "service.example.com".to_string(),
                }),
                DnsRecordType::SRV,
            ),
            (
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xab, 0xcd],
                }),
                DnsRecordType::TLSA,
            ),
            (
                DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".to_string()),
                    options: vec![KeyValue {
                        key: "account".to_string(),
                        value: "123".to_string(),
                    }],
                }),
                DnsRecordType::CAA,
            ),
        ];

        for (record, record_type) in records {
            let properties = build_record(&record, "www", 300).unwrap();
            assert_eq!(record_from_api(&properties, record_type).unwrap(), record);
        }
    }

    #[tokio::test]
    async fn test_type_mismatch_is_rejected_before_requests() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("value".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(message)) if message.contains("mismatch")));
    }

    #[tokio::test]
    async fn test_add_rrset_value() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zones(&mut server, json!([zone("example.com")]));
        let records = mock_records(&mut server, json!([]));
        let body = json!({
            "properties": {
                "name": "www",
                "type": "A",
                "content": "192.0.2.3",
                "ttl": 300,
                "enabled": true
            }
        });
        let create = server
            .mock("POST", RECORDS_PATH)
            .match_body(Matcher::Json(body.clone()))
            .with_status(202)
            .with_body(record_response(&body["properties"]))
            .create();

        let provider = setup_provider(server.url());
        provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("192.0.2.3".parse().unwrap())],
                "example.com",
            )
            .await
            .unwrap();
        zones.assert();
        records.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_remove_rrset_value() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zones(&mut server, json!([zone("example.com")]));
        let records = mock_records(
            &mut server,
            json!([api_record("www", "A", "192.0.2.3", 300)]),
        );
        let delete = server
            .mock("DELETE", "/zones/zone-1/records/record-1")
            .with_status(202)
            .create();

        let provider = setup_provider(server.url());
        provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("192.0.2.3".parse().unwrap())],
                "example.com",
            )
            .await
            .unwrap();
        zones.assert();
        records.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_names_outside_origin_are_rejected_before_requests() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("notexample.com", DnsRecordType::A, "example.com")
            .await;
        assert!(
            matches!(result, Err(Error::Api(message)) if message.contains("not within origin"))
        );
    }

    #[tokio::test]
    async fn test_parent_zone_for_subdomain_origin_and_relative_name() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zones(&mut server, json!([zone("example.com")]));
        let records = mock_records(
            &mut server,
            json!([api_record("host.sub", "TXT", "\"literal\"\\value", 300)]),
        );
        let provider = setup_provider(server.url());
        let values = provider
            .list_rrset(
                "HOST.SUB.example.com.",
                DnsRecordType::TXT,
                "sub.example.com",
            )
            .await
            .unwrap();
        assert_eq!(values, vec![DnsRecord::TXT("\"literal\"\\value".into())]);
        zones.assert();
        records.assert();
    }

    #[tokio::test]
    async fn test_missing_zone_returns_error() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zones(&mut server, json!([zone("other.com")]));
        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await;
        assert!(
            matches!(result, Err(Error::Api(message)) if message.contains("No IONOS Cloud DNS zone"))
        );
        zones.assert();
    }

    #[tokio::test]
    async fn test_optional_fields_default_and_invalid_values_fail() {
        for invalid in [None, Some("ttl"), Some("enabled")] {
            let mut server = mockito::Server::new_async().await;
            let zones = mock_zones(&mut server, json!([zone("example.com")]));
            let mut unrelated = json!({
                "id": "unrelated",
                "properties": {"name": "other", "type": "A", "content": "192.0.2.2"}
            });
            if let Some(field) = invalid {
                unrelated["properties"][field] = json!("invalid");
            }
            let records = mock_records(
                &mut server,
                json!([
                    {
                        "id": "target",
                        "properties": {"name": "www", "type": "A", "content": "192.0.2.1"}
                    },
                    unrelated
                ]),
            );
            let provider = setup_provider(server.url());
            let result = provider
                .set_rrset(
                    "www.example.com",
                    DnsRecordType::A,
                    3600,
                    vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                    "example.com",
                )
                .await;
            if invalid.is_some() {
                assert!(matches!(result, Err(Error::Serialize(_))));
            } else {
                assert!(result.is_ok(), "{result:?}");
            }
            zones.assert();
            records.assert();
        }
    }

    #[tokio::test]
    async fn test_equivalent_values_are_idempotent_for_set_and_add() {
        let cases = [
            (
                "AAAA",
                "2001:0db8:0:0:0:0:0:1",
                DnsRecord::AAAA("2001:db8::1".parse().unwrap()),
            ),
            (
                "NS",
                "NS.EXAMPLE.COM.",
                DnsRecord::NS("ns.example.com".into()),
            ),
        ];
        for (api_type, content, value) in cases {
            for set in [true, false] {
                let mut server = mockito::Server::new_async().await;
                let zones = mock_zones(&mut server, json!([zone("example.com")]));
                let records = mock_records(
                    &mut server,
                    json!([api_record("www", api_type, content, 300)]),
                );
                let provider = setup_provider(server.url());
                let result = if set {
                    provider
                        .set_rrset(
                            "www.example.com",
                            value.as_type(),
                            300,
                            vec![value.clone()],
                            "example.com",
                        )
                        .await
                } else {
                    provider
                        .add_to_rrset(
                            "www.example.com",
                            value.as_type(),
                            300,
                            vec![value.clone()],
                            "example.com",
                        )
                        .await
                };
                assert!(result.is_ok(), "{result:?}");
                zones.assert();
                records.assert();
            }
        }
    }

    #[tokio::test]
    async fn test_set_preserves_matches_before_replacing_stale_records() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zones(&mut server, json!([zone("example.com")]));
        let mut keep = api_record("www", "A", "192.0.2.1", 300);
        keep["id"] = json!("keep");
        let mut stale = api_record("www", "A", "192.0.2.2", 300);
        stale["id"] = json!("stale");
        let records = mock_records(&mut server, json!([keep, stale]));
        let body = json!({
            "properties": {
                "name": "www", "type": "A", "content": "192.0.2.3",
                "ttl": 300, "enabled": true
            }
        });
        let update = server
            .mock("PUT", "/zones/zone-1/records/stale")
            .match_body(Matcher::Json(body.clone()))
            .with_status(202)
            .with_body(record_response(&body["properties"]))
            .create();
        let provider = setup_provider(server.url());
        provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("192.0.2.3".parse().unwrap()),
                    DnsRecord::A("192.0.2.1".parse().unwrap()),
                ],
                "example.com",
            )
            .await
            .unwrap();
        zones.assert();
        records.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_remove_matches_mx_and_srv_names_but_respects_priority() {
        let cases = [
            (
                "MX",
                "MAIL.EXAMPLE.COM.",
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".into(),
                    priority: 10,
                }),
            ),
            (
                "SRV",
                "5 443 SERVICE.EXAMPLE.COM.",
                DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 443,
                    target: "service.example.com".into(),
                }),
            ),
        ];
        for (api_type, content, value) in cases {
            let mut server = mockito::Server::new_async().await;
            let zones = mock_zones(&mut server, json!([zone("example.com")]));
            let mut matching = api_record("www", api_type, content, 300);
            matching["properties"]["priority"] = json!(10);
            let mut different = matching.clone();
            different["id"] = json!("different-priority");
            different["properties"]["priority"] = json!(20);
            let records = mock_records(&mut server, json!([matching, different]));
            let delete = server
                .mock("DELETE", "/zones/zone-1/records/record-1")
                .with_status(202)
                .create();
            let provider = setup_provider(server.url());
            provider
                .remove_from_rrset(
                    "www.example.com",
                    value.as_type(),
                    vec![value],
                    "example.com",
                )
                .await
                .unwrap();
            zones.assert();
            records.assert();
            delete.assert();
        }
    }

    #[tokio::test]
    async fn test_caa_value_whitespace_is_preserved_in_comparisons() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zones(&mut server, json!([zone("example.com")]));
        let records = mock_records(
            &mut server,
            json!([api_record("www", "CAA", "0 iodef \"mailto:a  b\"", 300)]),
        );
        let provider = setup_provider(server.url());
        provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::CAA,
                vec![DnsRecord::CAA(CAARecord::Iodef {
                    issuer_critical: false,
                    url: "mailto:a b".into(),
                })],
                "example.com",
            )
            .await
            .unwrap();
        zones.assert();
        records.assert();
    }

    #[tokio::test]
    async fn test_remove_matches_equivalent_ipv6_and_hostname() {
        let cases = [
            (
                "AAAA",
                "2001:0db8:0:0:0:0:0:1",
                DnsRecord::AAAA("2001:db8::1".parse().unwrap()),
            ),
            (
                "CNAME",
                "TARGET.EXAMPLE.COM.",
                DnsRecord::CNAME("target.example.com".into()),
            ),
        ];
        for (api_type, content, value) in cases {
            let mut server = mockito::Server::new_async().await;
            let zones = mock_zones(&mut server, json!([zone("example.com")]));
            let records = mock_records(
                &mut server,
                json!([api_record("www", api_type, content, 300)]),
            );
            let delete = server
                .mock("DELETE", "/zones/zone-1/records/record-1")
                .with_status(202)
                .create();
            let provider = setup_provider(server.url());
            provider
                .remove_from_rrset(
                    "www.example.com",
                    value.as_type(),
                    vec![value],
                    "example.com",
                )
                .await
                .unwrap();
            zones.assert();
            records.assert();
            delete.assert();
        }
    }

    #[tokio::test]
    async fn test_invalid_existing_record_fails_before_mutation() {
        for operation in 0..3 {
            let mut server = mockito::Server::new_async().await;
            let zones = mock_zones(&mut server, json!([zone("example.com")]));
            let records = mock_records(
                &mut server,
                json!([api_record("www", "AAAA", "invalid-address", 300)]),
            );
            let provider = setup_provider(server.url());
            let value = DnsRecord::AAAA("2001:db8::1".parse().unwrap());
            let result = match operation {
                0 => {
                    provider
                        .set_rrset(
                            "www.example.com",
                            DnsRecordType::AAAA,
                            300,
                            vec![value],
                            "example.com",
                        )
                        .await
                }
                1 => {
                    provider
                        .add_to_rrset(
                            "www.example.com",
                            DnsRecordType::AAAA,
                            300,
                            vec![value],
                            "example.com",
                        )
                        .await
                }
                _ => {
                    provider
                        .remove_from_rrset(
                            "www.example.com",
                            DnsRecordType::AAAA,
                            vec![value],
                            "example.com",
                        )
                        .await
                }
            };
            assert!(matches!(result, Err(Error::Parse(_))), "{result:?}");
            zones.assert();
            records.assert();
        }
    }

    async fn live_txt_round_trip(
        updater: &DnsUpdater,
        fqdn: &str,
        origin: &str,
        value: String,
    ) -> crate::Result<()> {
        if !updater
            .list_rrset(fqdn, DnsRecordType::TXT, origin)
            .await?
            .is_empty()
        {
            return Err(Error::Api(format!("Test TXT RRSet at {fqdn} is not empty")));
        }
        updater
            .set_rrset(
                fqdn,
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(value.clone())],
                origin,
            )
            .await?;
        let verification = updater
            .list_rrset(fqdn, DnsRecordType::TXT, origin)
            .await
            .and_then(|records| {
                if records == vec![DnsRecord::TXT(value)] {
                    Ok(())
                } else {
                    Err(Error::Api(format!(
                        "Unexpected test TXT records: {records:?}"
                    )))
                }
            });
        let cleanup = updater
            .set_rrset(fqdn, DnsRecordType::TXT, 300, vec![], origin)
            .await;
        match (verification, cleanup) {
            (Err(verify), Err(cleanup)) => Err(Error::Api(format!(
                "Test verification failed: {verify}; cleanup failed: {cleanup}"
            ))),
            (Err(error), _) | (_, Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    async fn live_rrset_round_trip(
        updater: &DnsUpdater,
        fqdn: &str,
        origin: &str,
        record_type: DnsRecordType,
        record: DnsRecord,
        expected: DnsRecord,
    ) -> crate::Result<()> {
        if !updater
            .list_rrset(fqdn, record_type, origin)
            .await?
            .is_empty()
        {
            return Err(Error::Api(format!(
                "Test {record_type:?} RRSet at {fqdn} is not empty"
            )));
        }
        updater
            .set_rrset(fqdn, record_type, 300, vec![record], origin)
            .await?;
        let verification = updater
            .list_rrset(fqdn, record_type, origin)
            .await
            .and_then(|records| {
                if records == vec![expected] {
                    Ok(())
                } else {
                    Err(Error::Api(format!(
                        "Unexpected test {record_type:?} records: {records:?}"
                    )))
                }
            });
        let cleanup = updater
            .set_rrset(fqdn, record_type, 300, vec![], origin)
            .await;
        match (verification, cleanup) {
            (Err(verify), Err(cleanup)) => Err(Error::Api(format!(
                "Test verification failed: {verify}; cleanup failed: {cleanup}"
            ))),
            (Err(error), _) | (_, Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    async fn live_update_round_trip(
        updater: &DnsUpdater,
        fqdn: &str,
        origin: &str,
        initial: DnsRecord,
        updated: DnsRecord,
    ) -> crate::Result<()> {
        if !updater
            .list_rrset(fqdn, DnsRecordType::A, origin)
            .await?
            .is_empty()
        {
            return Err(Error::Api(format!("Test A RRSet at {fqdn} is not empty")));
        }

        let create = updater
            .set_rrset(fqdn, DnsRecordType::A, 300, vec![initial], origin)
            .await;
        let update = match create {
            Ok(()) => {
                updater
                    .set_rrset(fqdn, DnsRecordType::A, 300, vec![updated.clone()], origin)
                    .await
            }
            Err(error) => Err(error),
        };
        let verification = match update {
            Ok(()) => updater
                .list_rrset(fqdn, DnsRecordType::A, origin)
                .await
                .and_then(|records| {
                    if records == vec![updated] {
                        Ok(())
                    } else {
                        Err(Error::Api(format!(
                            "Unexpected test updated A records: {records:?}"
                        )))
                    }
                }),
            Err(error) => Err(error),
        };
        let cleanup = updater
            .set_rrset(fqdn, DnsRecordType::A, 300, vec![], origin)
            .await;
        match (verification, cleanup) {
            (Err(verify), Err(cleanup)) => Err(Error::Api(format!(
                "Test verification failed: {verify}; cleanup failed: {cleanup}"
            ))),
            (Err(error), _) | (_, Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    #[tokio::test]
    async fn test_live_workflow_refuses_existing_txt() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zones(&mut server, json!([zone("example.com")]));
        let records = mock_records(
            &mut server,
            json!([api_record("test", "TXT", "existing", 300)]),
        );
        let updater = DnsUpdater::IonosCloud(setup_provider(server.url()));
        let result =
            live_txt_round_trip(&updater, "test.example.com", "example.com", "test".into()).await;
        assert!(matches!(result, Err(Error::Api(message)) if message.contains("not empty")));
        zones.assert();
        records.assert();
    }

    #[tokio::test]
    async fn test_live_workflow_attempts_cleanup_when_verification_fails() {
        let mut server = mockito::Server::new_async().await;
        let zones = server
            .mock("GET", "/zones")
            .match_query(Matcher::UrlEncoded("limit".into(), "1000".into()))
            .with_status(200)
            .with_body(json!({"items": [zone("example.com")]}).to_string())
            .expect(4)
            .create();
        let records = server
            .mock("GET", RECORDS_PATH)
            .match_query(Matcher::UrlEncoded("limit".into(), "1000".into()))
            .with_status(200)
            .with_body(json!({"items": []}).to_string())
            .expect(4)
            .create();
        let properties = json!({
            "name": "test", "type": "TXT", "content": "test-value",
            "ttl": 300, "enabled": true
        });
        let create = server
            .mock("POST", RECORDS_PATH)
            .match_body(Matcher::Json(json!({"properties": properties})))
            .with_status(202)
            .with_body(record_response(&properties))
            .create();
        let updater = DnsUpdater::IonosCloud(setup_provider(server.url()));
        let result = live_txt_round_trip(
            &updater,
            "test.example.com",
            "example.com",
            "test-value".into(),
        )
        .await;
        assert!(
            matches!(result, Err(Error::Api(message)) if message.contains("Unexpected test TXT"))
        );
        zones.assert();
        records.assert();
        create.assert();
    }

    #[tokio::test]
    #[ignore = "Requires IONOS_CLOUD_API_TOKEN and IONOS_CLOUD_ORIGIN with DNS write access"]
    async fn test_ionos_cloud_integration() {
        let token = std::env::var("IONOS_CLOUD_API_TOKEN").expect("IONOS_CLOUD_API_TOKEN");
        let origin = std::env::var("IONOS_CLOUD_ORIGIN").expect("IONOS_CLOUD_ORIGIN");
        let updater = DnsUpdater::new_ionos_cloud(token, None).unwrap();
        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let label = |kind: &str| format!("dnsupdate-poc-{run_id}-{kind}.{origin}");

        live_rrset_round_trip(
            &updater,
            &label("a"),
            &origin,
            DnsRecordType::A,
            DnsRecord::A("192.0.2.1".parse().unwrap()),
            DnsRecord::A("192.0.2.1".parse().unwrap()),
        )
        .await
        .unwrap();

        live_update_round_trip(
            &updater,
            &label("a-update"),
            &origin,
            DnsRecord::A("192.0.2.10".parse().unwrap()),
            DnsRecord::A("192.0.2.11".parse().unwrap()),
        )
        .await
        .unwrap();

        live_rrset_round_trip(
            &updater,
            &label("aaaa"),
            &origin,
            DnsRecordType::AAAA,
            DnsRecord::AAAA("2001:db8::1".parse().unwrap()),
            DnsRecord::AAAA("2001:db8::1".parse().unwrap()),
        )
        .await
        .unwrap();

        live_rrset_round_trip(
            &updater,
            &label("cname"),
            &origin,
            DnsRecordType::CNAME,
            DnsRecord::CNAME("target.example.com.".to_string()),
            DnsRecord::CNAME("target.example.com".to_string()),
        )
        .await
        .unwrap();

        live_rrset_round_trip(
            &updater,
            &label("ns"),
            &origin,
            DnsRecordType::NS,
            DnsRecord::NS("ns1.example.com.".to_string()),
            DnsRecord::NS("ns1.example.com".to_string()),
        )
        .await
        .unwrap();

        live_rrset_round_trip(
            &updater,
            &label("mx"),
            &origin,
            DnsRecordType::MX,
            DnsRecord::MX(MXRecord {
                exchange: "mail.example.com.".to_string(),
                priority: 10,
            }),
            DnsRecord::MX(MXRecord {
                exchange: "mail.example.com".to_string(),
                priority: 10,
            }),
        )
        .await
        .unwrap();

        live_rrset_round_trip(
            &updater,
            &label("txt"),
            &origin,
            DnsRecordType::TXT,
            DnsRecord::TXT(format!("dns-update-test-{run_id}")),
            DnsRecord::TXT(format!("dns-update-test-{run_id}")),
        )
        .await
        .unwrap();

        live_rrset_round_trip(
            &updater,
            &format!("_sip._tcp.{}", label("srv")),
            &origin,
            DnsRecordType::SRV,
            DnsRecord::SRV(SRVRecord {
                target: "sip.example.com.".to_string(),
                priority: 10,
                weight: 20,
                port: 5060,
            }),
            DnsRecord::SRV(SRVRecord {
                target: "sip.example.com".to_string(),
                priority: 10,
                weight: 20,
                port: 5060,
            }),
        )
        .await
        .unwrap();

        live_rrset_round_trip(
            &updater,
            &format!("_443._tcp.{}", label("tlsa")),
            &origin,
            DnsRecordType::TLSA,
            DnsRecord::TLSA(TLSARecord {
                cert_usage: TlsaCertUsage::DaneEe,
                selector: TlsaSelector::Spki,
                matching: TlsaMatching::Sha256,
                cert_data: vec![0xab; 32],
            }),
            DnsRecord::TLSA(TLSARecord {
                cert_usage: TlsaCertUsage::DaneEe,
                selector: TlsaSelector::Spki,
                matching: TlsaMatching::Sha256,
                cert_data: vec![0xab; 32],
            }),
        )
        .await
        .unwrap();

        live_rrset_round_trip(
            &updater,
            &label("caa"),
            &origin,
            DnsRecordType::CAA,
            DnsRecord::CAA(CAARecord::Issue {
                issuer_critical: false,
                name: Some("letsencrypt.org".to_string()),
                options: vec![],
            }),
            DnsRecord::CAA(CAARecord::Issue {
                issuer_critical: false,
                name: Some("letsencrypt.org".to_string()),
                options: vec![],
            }),
        )
        .await
        .unwrap();
    }
}
