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
        DnsRecord, DnsRecordType, DnsUpdater, Error, SRVRecord, TLSARecord, TlsaCertUsage,
        TlsaMatching, TlsaSelector, providers::spaceship::SpaceshipProvider,
    };
    use mockito::{Matcher, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> SpaceshipProvider {
        SpaceshipProvider::new(
            "test_api_key",
            "test_api_secret",
            Some(Duration::from_secs(1)),
        )
        .with_endpoint(endpoint)
    }

    fn mock_list(server: &mut ServerGuard, domain: &str, body: serde_json::Value) -> mockito::Mock {
        server
            .mock("GET", format!("/dns/records/{domain}").as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("take".into(), "100".into()),
                Matcher::UrlEncoded("skip".into(), "0".into()),
            ]))
            .match_header("x-api-key", "test_api_key")
            .match_header("x-api-secret", "test_api_secret")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body.to_string())
            .create()
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_spaceship(
            "test_api_key",
            "test_api_secret",
            Some(Duration::from_secs(30)),
        );

        assert!(updater.is_ok());
        assert!(
            matches!(updater, Ok(DnsUpdater::Spaceship(..))),
            "Expected Spaceship updater to provide a Spaceship provider"
        );
    }

    #[tokio::test]
    async fn set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [
                    {"type":"A","name":"other","address":"9.9.9.9","ttl":300}
                ],
                "total": 1,
            }),
        );

        let put = server
            .mock("PUT", "/dns/records/example.com")
            .match_body(Matcher::Json(json!({
                "items": [
                    {"type":"A","name":"host","address":"1.1.1.1","ttl":300},
                    {"type":"A","name":"host","address":"2.2.2.2","ttl":300}
                ]
            })))
            .with_status(200)
            .create();

        let provider = setup_provider(server.url().as_str());
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
        list.assert();
        put.assert();
    }

    #[tokio::test]
    async fn set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [
                    {"type":"A","name":"host","address":"1.1.1.1","ttl":300}
                ],
                "total": 1,
            }),
        );

        let provider = setup_provider(server.url().as_str());
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
        list.assert();
    }

    #[tokio::test]
    async fn set_rrset_deletes_extras_and_adds_missing() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [
                    {"type":"A","name":"host","address":"1.1.1.1","ttl":300},
                    {"type":"A","name":"host","address":"9.9.9.9","ttl":300}
                ],
                "total": 2,
            }),
        );

        let delete = server
            .mock("DELETE", "/dns/records/example.com")
            .match_body(Matcher::Json(json!([
                {"type":"A","name":"host","address":"9.9.9.9"}
            ])))
            .with_status(200)
            .create();

        let put = server
            .mock("PUT", "/dns/records/example.com")
            .match_body(Matcher::Json(json!({
                "items": [
                    {"type":"A","name":"host","address":"8.8.8.8","ttl":300}
                ]
            })))
            .with_status(200)
            .create();

        let provider = setup_provider(server.url().as_str());
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
        list.assert();
        delete.assert();
        put.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_deletes_all_of_type_only() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [
                    {"type":"A","name":"host","address":"1.2.3.4","ttl":300},
                    {"type":"A","name":"host","address":"5.6.7.8","ttl":300},
                    {"type":"TXT","name":"host","value":"keep-me","ttl":300},
                    {"type":"A","name":"other","address":"9.9.9.9","ttl":300}
                ],
                "total": 4,
            }),
        );

        let delete = server
            .mock("DELETE", "/dns/records/example.com")
            .match_body(Matcher::Json(json!([
                {"type":"A","name":"host","address":"1.2.3.4"},
                {"type":"A","name":"host","address":"5.6.7.8"}
            ])))
            .with_status(200)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_at_apex_uses_at_marker() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [
                    {"type":"TXT","name":"@","value":"old","ttl":300}
                ],
                "total": 1,
            }),
        );

        let delete = server
            .mock("DELETE", "/dns/records/example.com")
            .match_body(Matcher::Json(json!([
                {"type":"TXT","name":"@","value":"old"}
            ])))
            .with_status(200)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::TXT,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_is_noop_when_no_records_exist() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [
                    {"type":"TXT","name":"host","value":"keep","ttl":300}
                ],
                "total": 1,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn set_rrset_does_not_touch_other_types_at_same_name() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [
                    {"type":"TXT","name":"host","value":"keep-me","ttl":300},
                    {"type":"AAAA","name":"host","address":"::1","ttl":300}
                ],
                "total": 2,
            }),
        );

        let put = server
            .mock("PUT", "/dns/records/example.com")
            .match_body(Matcher::Json(json!({
                "items": [
                    {"type":"A","name":"host","address":"1.1.1.1","ttl":300}
                ]
            })))
            .with_status(200)
            .create();

        let provider = setup_provider(server.url().as_str());
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
        list.assert();
        put.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
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
    async fn add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [
                    {"type":"TXT","name":"_acme","value":"existing","ttl":60}
                ],
                "total": 1,
            }),
        );

        let put = server
            .mock("PUT", "/dns/records/example.com")
            .match_body(Matcher::Json(json!({
                "items": [
                    {"type":"TXT","name":"_acme","value":"new-token","ttl":60}
                ]
            })))
            .with_status(200)
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
        list.assert();
        put.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("host.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [
                    {"type":"TXT","name":"_acme","value":"keep-me","ttl":60},
                    {"type":"TXT","name":"_acme","value":"drop-me","ttl":60}
                ],
                "total": 2,
            }),
        );

        let delete = server
            .mock("DELETE", "/dns/records/example.com")
            .match_body(Matcher::Json(json!([
                {"type":"TXT","name":"_acme","value":"drop-me"}
            ])))
            .with_status(200)
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
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_absent_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [
                    {"type":"TXT","name":"_acme","value":"keep-me","ttl":60}
                ],
                "total": 1,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("not-there".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn set_rrset_rejects_mismatched_record_type() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not-an-A".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn add_to_rrset_rejects_mismatched_record_type() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not-an-A".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn remove_from_rrset_rejects_mismatched_record_type() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::TXT("not-an-A".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn set_rrset_replaces_two_tlsa_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [
                    {
                        "type":"TLSA","name":"mail","port":"_25","protocol":"_tcp",
                        "usage":3,"selector":1,"matching":1,"associationData":"aa","ttl":300
                    },
                    {
                        "type":"TLSA","name":"mail","port":"_25","protocol":"_tcp",
                        "usage":2,"selector":1,"matching":1,"associationData":"bb","ttl":300
                    }
                ],
                "total": 2,
            }),
        );

        let delete = server
            .mock("DELETE", "/dns/records/example.com")
            .match_body(Matcher::Json(json!([
                {
                    "type":"TLSA","name":"mail","port":"_25","protocol":"_tcp",
                    "usage":3,"selector":1,"matching":1,"associationData":"aa"
                },
                {
                    "type":"TLSA","name":"mail","port":"_25","protocol":"_tcp",
                    "usage":2,"selector":1,"matching":1,"associationData":"bb"
                }
            ])))
            .with_status(200)
            .create();

        let put = server
            .mock("PUT", "/dns/records/example.com")
            .match_body(Matcher::Json(json!({
                "items": [
                    {
                        "type":"TLSA","name":"mail","port":"_25","protocol":"_tcp",
                        "usage":3,"selector":1,"matching":1,"associationData":"cc","ttl":300
                    },
                    {
                        "type":"TLSA","name":"mail","port":"_25","protocol":"_tcp",
                        "usage":2,"selector":1,"matching":1,"associationData":"dd","ttl":300
                    }
                ]
            })))
            .with_status(200)
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
        list.assert();
        delete.assert();
        put.assert();
    }

    #[tokio::test]
    async fn set_rrset_sends_underscore_prefixed_tlsa_port() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [],
                "total": 0,
            }),
        );

        let put = server
            .mock("PUT", "/dns/records/example.com")
            .match_body(Matcher::Json(json!({
                "items": [
                    {
                        "type":"TLSA","name":"mail","port":"_995","protocol":"_tcp",
                        "usage":3,"selector":1,"matching":1,"associationData":"aabb","ttl":300
                    }
                ]
            })))
            .with_status(200)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_995._tcp.mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xaa, 0xbb],
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        put.assert();
    }

    #[tokio::test]
    async fn list_rrset_matches_tlsa_with_string_port() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [
                    {
                        "type":"TLSA","name":"mail","port":"_995","protocol":"_tcp",
                        "usage":3,"selector":1,"matching":1,"associationData":"aabb","ttl":300
                    },
                    {
                        "type":"TLSA","name":"mail","port":"_25","protocol":"_tcp",
                        "usage":3,"selector":1,"matching":1,"associationData":"ccdd","ttl":300
                    }
                ],
                "total": 2,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset(
                "_995._tcp.mail.example.com",
                DnsRecordType::TLSA,
                "example.com",
            )
            .await
            .expect("list_rrset failed");

        list.assert();
        assert_eq!(
            result,
            vec![DnsRecord::TLSA(TLSARecord {
                cert_usage: TlsaCertUsage::DaneEe,
                selector: TlsaSelector::Spki,
                matching: TlsaMatching::Sha256,
                cert_data: vec![0xaa, 0xbb],
            })]
        );
    }

    #[tokio::test]
    async fn set_rrset_rejects_invalid_tlsa_port_label() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_0._tcp.mail.example.com",
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
        assert!(matches!(result, Err(Error::Parse(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn list_rrset_filters_by_name_and_type() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [
                    {"type":"A","name":"host","address":"1.1.1.1","ttl":300},
                    {"type":"A","name":"host","address":"2.2.2.2","ttl":300},
                    {"type":"A","name":"other","address":"9.9.9.9","ttl":300},
                    {"type":"AAAA","name":"host","address":"::1","ttl":300}
                ],
                "total": 4,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");
        list.assert();

        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
    }

    #[tokio::test]
    async fn list_rrset_reconstructs_srv_record() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "example.com",
            json!({
                "items": [
                    {
                        "type":"SRV","name":"@","service":"_sip","protocol":"_tcp",
                        "priority":10,"weight":60,"port":5060,
                        "target":"sip.example.com","ttl":300
                    }
                ],
                "total": 1,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("_sip._tcp.example.com", DnsRecordType::SRV, "example.com")
            .await
            .expect("list_rrset failed");
        list.assert();
        assert_eq!(
            result,
            vec![DnsRecord::SRV(SRVRecord {
                priority: 10,
                weight: 60,
                port: 5060,
                target: "sip.example.com".into(),
            })]
        );
    }
}
