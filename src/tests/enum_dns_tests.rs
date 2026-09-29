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
        TlsaMatching, TlsaSelector, providers::enum_dns::EnumProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const PROJECT_ID: &str = "proj-01kmyy3t719crcnrrvk1mgyjd0";
    const ZONE_ID: &str = "dnszone-01m23faytfe84sxabv306xjee2";

    fn setup_provider(endpoint: String) -> EnumProvider {
        EnumProvider::new("test_key", PROJECT_ID, Some(Duration::from_secs(1)))
            .with_endpoint(endpoint)
    }

    fn mock_call(
        server: &mut ServerGuard,
        method: &str,
        body: serde_json::Value,
        status: usize,
        response: serde_json::Value,
    ) -> Mock {
        server
            .mock("POST", format!("/{method}").as_str())
            .match_header("authorization", "Bearer test_key")
            .match_header("content-type", "application/json")
            .match_body(Matcher::Json(body))
            .with_status(status)
            .with_header("content-type", "application/json")
            .with_body(response.to_string())
            .create()
    }

    fn mock_zone(server: &mut ServerGuard, name: &str) -> Mock {
        mock_call(
            server,
            "GetZoneByName",
            json!({"projectId": PROJECT_ID, "name": name}),
            200,
            json!({"zone": {"id": ZONE_ID, "name": format!("{name}.")}}),
        )
    }

    fn not_found() -> serde_json::Value {
        json!({"code": "not_found", "message": "resource not found"})
    }

    fn key(name: &str, record_type: &str) -> serde_json::Value {
        json!({"projectId": PROJECT_ID, "zoneId": ZONE_ID, "name": name, "type": record_type})
    }

    fn with(mut base: serde_json::Value, extra: serde_json::Value) -> serde_json::Value {
        base.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        base
    }

    #[tokio::test]
    async fn test_zone_lookup_walks_up_origin() {
        let mut server = mockito::Server::new_async().await;
        let miss = mock_call(
            &mut server,
            "GetZoneByName",
            json!({"projectId": PROJECT_ID, "name": "mail.example.com"}),
            404,
            not_found(),
        );
        let zone = mock_zone(&mut server, "example.com");
        let add = mock_call(
            &mut server,
            "AddRecordSetValue",
            with(
                key("_acme-challenge.mail.example.com", "TXT"),
                json!({"ttl": 60, "value": {"content": "\"token\""}}),
            ),
            200,
            json!({"recordSet": {}}),
        );

        setup_provider(server.url())
            .add_to_rrset(
                "_acme-challenge.mail.example.com",
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("token".into())],
                "mail.example.com",
            )
            .await
            .unwrap();

        miss.assert();
        zone.assert();
        add.assert();
    }

    #[tokio::test]
    async fn test_zone_lookup_fails_when_no_zone_matches() {
        let mut server = mockito::Server::new_async().await;
        let miss = server
            .mock("POST", "/GetZoneByName")
            .with_status(404)
            .with_body(not_found().to_string())
            .expect(2)
            .create();

        let result = setup_provider(server.url())
            .list_rrset("www.example.com", DnsRecordType::A, "www.example.com")
            .await;

        assert!(matches!(result, Err(Error::Api(msg)) if msg.contains("No enum zone found")));
        miss.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_updates_existing_set() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server, "example.com");
        let update = mock_call(
            &mut server,
            "UpdateRecordSet",
            with(
                key("www.example.com", "A"),
                json!({"ttl": 300, "records": [{"content": "192.0.2.1"}, {"content": "192.0.2.2"}]}),
            ),
            200,
            json!({"recordSet": {}}),
        );

        setup_provider(server.url())
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("192.0.2.1".parse().unwrap()),
                    DnsRecord::A("192.0.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await
            .unwrap();

        zone.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_creates_missing_set() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server, "example.com");
        let body = with(
            key("example.com", "MX"),
            json!({"ttl": 3600, "records": [{"content": "10 mail.example.com."}]}),
        );
        let update = mock_call(
            &mut server,
            "UpdateRecordSet",
            body.clone(),
            404,
            not_found(),
        );
        let create = mock_call(
            &mut server,
            "CreateRecordSet",
            body,
            200,
            json!({"recordSet": {}}),
        );

        setup_provider(server.url())
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".into(),
                    priority: 10,
                })],
                "example.com",
            )
            .await
            .unwrap();

        zone.assert();
        update.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_set() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server, "example.com");
        let delete = mock_call(
            &mut server,
            "DeleteRecordSet",
            key("www.example.com", "A"),
            404,
            not_found(),
        );

        setup_provider(server.url())
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await
            .unwrap();

        zone.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_adds_each_value() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server, "example.com");
        let long = "a".repeat(300);
        let first = mock_call(
            &mut server,
            "AddRecordSetValue",
            with(
                key("example.com", "TXT"),
                json!({"ttl": 300, "value": {"content": "\"v=spf1 include:\\\"x\\\" -all\""}}),
            ),
            200,
            json!({"recordSet": {}}),
        );
        let second = mock_call(
            &mut server,
            "AddRecordSetValue",
            with(
                key("example.com", "TXT"),
                json!({"ttl": 300, "value": {"content": format!("\"{}\" \"{}\"", "a".repeat(255), "a".repeat(45))}}),
            ),
            200,
            json!({"recordSet": {}}),
        );

        setup_provider(server.url())
            .add_to_rrset(
                "Example.COM",
                DnsRecordType::TXT,
                300,
                vec![
                    DnsRecord::TXT("v=spf1 include:\"x\" -all".into()),
                    DnsRecord::TXT(long),
                ],
                "example.com",
            )
            .await
            .unwrap();

        zone.assert();
        first.assert();
        second.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_removes_each_value() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server, "example.com");
        let remove = mock_call(
            &mut server,
            "RemoveRecordSetValue",
            with(
                key("example.com", "CAA"),
                json!({"content": "0 issue \"letsencrypt.org\""}),
            ),
            200,
            json!({}),
        );

        setup_provider(server.url())
            .remove_from_rrset(
                "example.com",
                DnsRecordType::CAA,
                vec![DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".into()),
                    options: vec![],
                })],
                "example.com",
            )
            .await
            .unwrap();

        zone.assert();
        remove.assert();
    }

    #[tokio::test]
    async fn test_empty_add_and_remove_are_noops() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());

        provider
            .add_to_rrset("example.com", DnsRecordType::TXT, 60, vec![], "example.com")
            .await
            .unwrap();
        provider
            .remove_from_rrset("example.com", DnsRecordType::TXT, vec![], "example.com")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_records() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server, "example.com");
        let get = mock_call(
            &mut server,
            "GetRecordSet",
            key("example.com", "TXT"),
            200,
            json!({"recordSet": {
                "name": "example.com.",
                "type": "TXT",
                "ttl": 300,
                "records": [
                    {"content": "\"part one\" \"part two\""},
                    {"content": "\"hidden\"", "disabled": true},
                ],
            }}),
        );

        let records = setup_provider(server.url())
            .list_rrset("example.com", DnsRecordType::TXT, "example.com")
            .await
            .unwrap();

        assert_eq!(records, vec![DnsRecord::TXT("part onepart two".into())]);
        zone.assert();
        get.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_caa_and_mx() {
        let mut server = mockito::Server::new_async().await;
        let zone = server
            .mock("POST", "/GetZoneByName")
            .match_body(Matcher::Json(
                json!({"projectId": PROJECT_ID, "name": "example.com"}),
            ))
            .with_status(200)
            .with_body(json!({"zone": {"id": ZONE_ID}}).to_string())
            .expect(2)
            .create();
        let caa = mock_call(
            &mut server,
            "GetRecordSet",
            key("example.com", "CAA"),
            200,
            json!({"recordSet": {"records": [{"content": "128 issuewild \"letsencrypt.org\""}]}}),
        );
        let mx = mock_call(
            &mut server,
            "GetRecordSet",
            key("example.com", "MX"),
            200,
            json!({"recordSet": {"records": [{"content": "10 mail.example.com."}]}}),
        );
        let provider = setup_provider(server.url());

        assert_eq!(
            provider
                .list_rrset("example.com", DnsRecordType::CAA, "example.com")
                .await
                .unwrap(),
            vec![DnsRecord::CAA(CAARecord::IssueWild {
                issuer_critical: true,
                name: Some("letsencrypt.org".into()),
                options: vec![],
            })]
        );
        assert_eq!(
            provider
                .list_rrset("example.com", DnsRecordType::MX, "example.com")
                .await
                .unwrap(),
            vec![DnsRecord::MX(MXRecord {
                exchange: "mail.example.com".into(),
                priority: 10,
            })]
        );

        zone.assert();
        caa.assert();
        mx.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_missing_set_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server, "example.com");
        let get = mock_call(
            &mut server,
            "GetRecordSet",
            key("www.example.com", "AAAA"),
            404,
            not_found(),
        );

        let records = setup_provider(server.url())
            .list_rrset("www.example.com", DnsRecordType::AAAA, "example.com")
            .await
            .unwrap();

        assert!(records.is_empty());
        zone.assert();
        get.assert();
    }

    #[tokio::test]
    async fn test_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let zone = server
            .mock("POST", "/GetZoneByName")
            .with_status(401)
            .with_body(
                json!({"code": "unauthenticated", "message": "authentication failed"}).to_string(),
            )
            .create();

        let result = setup_provider(server.url())
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(matches!(result, Err(Error::Unauthorized)));
        zone.assert();
    }

    #[tokio::test]
    async fn test_rejects_tlsa_and_type_mismatch_without_requests() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());

        let tlsa = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
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
        assert!(matches!(tlsa, Err(Error::Unsupported(_))));

        let mismatch = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("nope".into())],
                "example.com",
            )
            .await;
        assert!(matches!(mismatch, Err(Error::Api(msg)) if msg.contains("mismatch")));
    }

    #[tokio::test]
    #[ignore = "Requires ENUM_API_KEY, ENUM_PROJECT_ID and ENUM_ORIGIN"]
    async fn integration_test() {
        let api_key = std::env::var("ENUM_API_KEY").unwrap_or_default();
        let project_id = std::env::var("ENUM_PROJECT_ID").unwrap_or_default();
        let origin = std::env::var("ENUM_ORIGIN").unwrap_or_default();
        assert!(!api_key.is_empty(), "Set ENUM_API_KEY");
        assert!(!project_id.is_empty(), "Set ENUM_PROJECT_ID");
        assert!(!origin.is_empty(), "Set ENUM_ORIGIN (e.g. example.com)");

        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let txt_name = format!("_acme-challenge.dnsupdate-{run_id}.{origin}");
        let a_name = format!("dnsupdate-{run_id}.{origin}");
        let provider = EnumProvider::new(&api_key, &project_id, Some(Duration::from_secs(30)));

        let first = DnsRecord::TXT("first-token".into());
        let second = DnsRecord::TXT("second-token".into());
        provider
            .add_to_rrset(
                &txt_name,
                DnsRecordType::TXT,
                60,
                vec![first.clone()],
                &origin,
            )
            .await
            .unwrap();
        provider
            .add_to_rrset(
                &txt_name,
                DnsRecordType::TXT,
                60,
                vec![first.clone(), second.clone()],
                &origin,
            )
            .await
            .unwrap();
        let mut listed = provider
            .list_rrset(&txt_name, DnsRecordType::TXT, &origin)
            .await
            .unwrap();
        listed.sort_by_key(|record| record.to_string());
        assert_eq!(listed, vec![first.clone(), second.clone()]);

        provider
            .remove_from_rrset(&txt_name, DnsRecordType::TXT, vec![first], &origin)
            .await
            .unwrap();
        assert_eq!(
            provider
                .list_rrset(&txt_name, DnsRecordType::TXT, &origin)
                .await
                .unwrap(),
            vec![second.clone()]
        );
        provider
            .remove_from_rrset(&txt_name, DnsRecordType::TXT, vec![second], &origin)
            .await
            .unwrap();
        assert!(
            provider
                .list_rrset(&txt_name, DnsRecordType::TXT, &origin)
                .await
                .unwrap()
                .is_empty()
        );

        let a_records = vec![
            DnsRecord::A("192.0.2.1".parse().unwrap()),
            DnsRecord::A("192.0.2.2".parse().unwrap()),
        ];
        provider
            .set_rrset(&a_name, DnsRecordType::A, 300, a_records.clone(), &origin)
            .await
            .unwrap();
        provider
            .set_rrset(
                &a_name,
                DnsRecordType::A,
                300,
                vec![a_records[0].clone()],
                &origin,
            )
            .await
            .unwrap();
        assert_eq!(
            provider
                .list_rrset(&a_name, DnsRecordType::A, &origin)
                .await
                .unwrap(),
            vec![a_records[0].clone()]
        );
        provider
            .set_rrset(&a_name, DnsRecordType::A, 300, vec![], &origin)
            .await
            .unwrap();
        assert!(
            provider
                .list_rrset(&a_name, DnsRecordType::A, &origin)
                .await
                .unwrap()
                .is_empty()
        );

        let srv_name = format!("_sip._tcp.{a_name}");
        let round_trips = vec![
            (
                a_name.clone(),
                DnsRecordType::MX,
                vec![DnsRecord::MX(MXRecord {
                    exchange: format!("mail.{origin}"),
                    priority: 10,
                })],
            ),
            (
                a_name.clone(),
                DnsRecordType::TXT,
                vec![DnsRecord::TXT(format!(
                    "v=DKIM1; k=rsa; p={}",
                    "A".repeat(400)
                ))],
            ),
            (
                srv_name,
                DnsRecordType::SRV,
                vec![DnsRecord::SRV(SRVRecord {
                    target: format!("sip.{origin}"),
                    priority: 10,
                    weight: 5,
                    port: 5060,
                })],
            ),
            (
                a_name.clone(),
                DnsRecordType::CAA,
                vec![
                    DnsRecord::CAA(CAARecord::Issue {
                        issuer_critical: false,
                        name: Some("letsencrypt.org".into()),
                        options: vec![],
                    }),
                    DnsRecord::CAA(CAARecord::Iodef {
                        issuer_critical: false,
                        url: "mailto:security@example.com".into(),
                    }),
                ],
            ),
        ];

        for (name, record_type, records) in round_trips {
            provider
                .set_rrset(&name, record_type, 300, records.clone(), &origin)
                .await
                .unwrap_or_else(|err| panic!("set {name} {record_type:?} failed: {err}"));
            let mut listed = provider
                .list_rrset(&name, record_type, &origin)
                .await
                .unwrap();
            let mut expected = records;
            listed.sort_by_key(|record| record.to_string());
            expected.sort_by_key(|record| record.to_string());
            assert_eq!(listed, expected, "{name} {record_type:?}");
            provider
                .set_rrset(&name, record_type, 300, vec![], &origin)
                .await
                .unwrap();
        }
    }
}
