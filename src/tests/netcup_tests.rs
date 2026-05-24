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
        CAARecord, DnsRecord, DnsRecordType, Error, MXRecord, TLSARecord, TlsaCertUsage,
        TlsaMatching, TlsaSelector, providers::netcup::NetcupProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::{Value, json};
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> NetcupProvider {
        NetcupProvider::new("12345", "key", "password", Some(Duration::from_secs(1)))
            .with_endpoint(endpoint)
    }

    fn ok_body(data: Value) -> String {
        json!({
            "status": "success",
            "statuscode": 2000,
            "shortmessage": "ok",
            "longmessage": "",
            "responsedata": data,
        })
        .to_string()
    }

    fn mock_login(server: &mut ServerGuard, session_id: &str) -> Mock {
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "login",
                "param": {
                    "customernumber": "12345",
                    "apikey": "key",
                    "apipassword": "password"
                }
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ok_body(json!({"apisessionid": session_id})))
            .create()
    }

    fn mock_info(server: &mut ServerGuard, domain: &str, records: Value) -> Mock {
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "infoDnsRecords",
                "param": {"domainname": domain}
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ok_body(json!({"dnsrecords": records})))
            .create()
    }

    fn mock_update(server: &mut ServerGuard, body: Value) -> Mock {
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(body))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ok_body(json!({})))
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let login = mock_login(&mut server, "sess-set-1");
        let info = mock_info(&mut server, "example.com", json!([]));
        let update = mock_update(
            &mut server,
            json!({
                "action": "updateDnsRecords",
                "param": {
                    "domainname": "example.com",
                    "dnsrecordset": {
                        "dnsrecords": [
                            {"hostname": "host", "type": "A", "destination": "1.1.1.1"},
                            {"hostname": "host", "type": "A", "destination": "2.2.2.2"}
                        ]
                    }
                }
            }),
        );

        let provider = setup_provider(server.url());
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
        login.assert();
        info.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let login = mock_login(&mut server, "sess-set-2");
        let info = mock_info(
            &mut server,
            "example.com",
            json!([{
                "id": "1",
                "hostname": "test",
                "type": "A",
                "destination": "1.1.1.1"
            }]),
        );
        let no_update = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "updateDnsRecords"
            })))
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
        login.assert();
        info.assert();
        no_update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_keeps_matching() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_login(&mut server, "sess-set-3");
        let _info = mock_info(
            &mut server,
            "example.com",
            json!([
                {"id": "keep", "hostname": "host", "type": "A", "destination": "1.1.1.1"},
                {"id": "stale", "hostname": "host", "type": "A", "destination": "9.9.9.9"}
            ]),
        );
        let update = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "updateDnsRecords",
                "param": {
                    "dnsrecordset": {
                        "dnsrecords": [
                            {"hostname": "host", "type": "A", "destination": "8.8.8.8"},
                            {"id": "stale", "hostname": "host", "type": "A", "destination": "9.9.9.9", "deleterecord": true}
                        ]
                    }
                }
            })))
            .with_status(200)
            .with_body(ok_body(json!({})))
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
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_all_of_that_type() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_login(&mut server, "sess-set-4");
        let _info = mock_info(
            &mut server,
            "example.com",
            json!([
                {"id": "x", "hostname": "gone", "type": "A", "destination": "1.2.3.4"},
                {"id": "y", "hostname": "gone", "type": "A", "destination": "5.6.7.8"},
                {"id": "z", "hostname": "gone", "type": "TXT", "destination": "keep-me"},
                {"id": "w", "hostname": "other", "type": "A", "destination": "9.9.9.9"}
            ]),
        );
        let update = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "updateDnsRecords",
                "param": {
                    "dnsrecordset": {
                        "dnsrecords": [
                            {"id": "x", "hostname": "gone", "type": "A", "destination": "1.2.3.4", "deleterecord": true},
                            {"id": "y", "hostname": "gone", "type": "A", "destination": "5.6.7.8", "deleterecord": true}
                        ]
                    }
                }
            })))
            .with_status(200)
            .with_body(ok_body(json!({})))
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
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_login(&mut server, "sess-iso");
        let _info = mock_info(
            &mut server,
            "example.com",
            json!([
                {"id": "txt-1", "hostname": "shared", "type": "TXT", "destination": "do-not-delete-me"}
            ]),
        );
        let update = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "updateDnsRecords",
                "param": {
                    "dnsrecordset": {
                        "dnsrecords": [
                            {"hostname": "shared", "type": "A", "destination": "1.2.3.4"}
                        ]
                    }
                }
            })))
            .with_status(200)
            .with_body(ok_body(json!({})))
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "shared.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_type_validation_rejects_mismatched_records() {
        let provider = setup_provider("http://127.0.0.1:1".to_string());
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
    async fn test_add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_login(&mut server, "sess-add-1");
        let _info = mock_info(
            &mut server,
            "example.com",
            json!([
                {"id": "old", "hostname": "_acme", "type": "TXT", "destination": "existing"}
            ]),
        );
        let update = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "updateDnsRecords",
                "param": {
                    "dnsrecordset": {
                        "dnsrecords": [
                            {"hostname": "_acme", "type": "TXT", "destination": "new-token"}
                        ]
                    }
                }
            })))
            .with_status(200)
            .with_body(ok_body(json!({})))
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
        update.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_full_noop_when_everything_present() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_login(&mut server, "sess-add-2");
        let _info = mock_info(
            &mut server,
            "example.com",
            json!([
                {"id": "1", "hostname": "test", "type": "A", "destination": "1.1.1.1"},
                {"id": "2", "hostname": "test", "type": "A", "destination": "8.8.8.8"}
            ]),
        );
        let no_update = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "updateDnsRecords"
            })))
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
        no_update.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_input_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        let no_call = server.mock("POST", "/").expect(0).create();

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
        no_call.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_login(&mut server, "sess-rem-1");
        let _info = mock_info(
            &mut server,
            "example.com",
            json!([
                {"id": "keep", "hostname": "_acme", "type": "TXT", "destination": "keep-me"},
                {"id": "drop", "hostname": "_acme", "type": "TXT", "destination": "drop-me"}
            ]),
        );
        let update = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "updateDnsRecords",
                "param": {
                    "dnsrecordset": {
                        "dnsrecords": [
                            {"id": "drop", "hostname": "_acme", "type": "TXT", "destination": "drop-me", "deleterecord": true}
                        ]
                    }
                }
            })))
            .with_status(200)
            .with_body(ok_body(json!({})))
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
        update.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_noop_when_values_absent() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_login(&mut server, "sess-rem-2");
        let _info = mock_info(
            &mut server,
            "example.com",
            json!([
                {"id": "1", "hostname": "test", "type": "A", "destination": "1.1.1.1"}
            ]),
        );
        let no_update = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "updateDnsRecords"
            })))
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
        no_update.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_input_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        let no_call = server.mock("POST", "/").expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        no_call.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_replaces_two_tlsa_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_login(&mut server, "sess-tlsa");
        let _info = mock_info(
            &mut server,
            "example.com",
            json!([
                {"id": "old-ee", "hostname": "_25._tcp.mail", "type": "TLSA",
                 "destination": "3 1 1 aa"},
                {"id": "old-ta", "hostname": "_25._tcp.mail", "type": "TLSA",
                 "destination": "2 1 1 bb"}
            ]),
        );
        let update = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "updateDnsRecords",
                "param": {
                    "dnsrecordset": {
                        "dnsrecords": [
                            {"hostname": "_25._tcp.mail", "type": "TLSA", "destination": "3 1 1 cc"},
                            {"hostname": "_25._tcp.mail", "type": "TLSA", "destination": "2 1 1 dd"},
                            {"id": "old-ee", "hostname": "_25._tcp.mail", "type": "TLSA", "destination": "3 1 1 aa", "deleterecord": true},
                            {"id": "old-ta", "hostname": "_25._tcp.mail", "type": "TLSA", "destination": "2 1 1 bb", "deleterecord": true}
                        ]
                    }
                }
            })))
            .with_status(200)
            .with_body(ok_body(json!({})))
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
        update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_with_priority_matches_canonical_form() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_login(&mut server, "sess-mx-set");
        let _info = mock_info(
            &mut server,
            "example.com",
            json!([
                {"id": "1", "hostname": "@", "type": "MX",
                 "priority": "10", "destination": "mail.example.com."}
            ]),
        );
        let no_update = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "updateDnsRecords"
            })))
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                300,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        no_update.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_apex_uses_at_sign_hostname() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_login(&mut server, "sess-apex");
        let _info = mock_info(&mut server, "example.com", json!([]));
        let update = mock_update(
            &mut server,
            json!({
                "action": "updateDnsRecords",
                "param": {
                    "dnsrecordset": {
                        "dnsrecords": [
                            {"hostname": "@", "type": "A", "destination": "1.2.3.4"}
                        ]
                    }
                }
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        update.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_filters_by_hostname_and_type() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_login(&mut server, "sess-list");
        let _info = mock_info(
            &mut server,
            "example.com",
            json!([
                {"id": "1", "hostname": "host", "type": "A", "destination": "1.1.1.1"},
                {"id": "2", "hostname": "host", "type": "A", "destination": "2.2.2.2"},
                {"id": "3", "hostname": "host", "type": "TXT", "destination": "ignore-txt"},
                {"id": "4", "hostname": "other", "type": "A", "destination": "9.9.9.9"}
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await;

        let records = result.expect("list_rrset returned err");
        assert_eq!(records.len(), 2, "got {records:?}");
        assert!(records.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(records.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
    }

    #[tokio::test]
    async fn test_list_rrset_decodes_mx_with_trailing_dot_stripped() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_login(&mut server, "sess-list-mx");
        let _info = mock_info(
            &mut server,
            "example.com",
            json!([
                {"id": "1", "hostname": "@", "type": "MX",
                 "priority": "10", "destination": "mail.example.com."}
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await;

        let records = result.expect("list_rrset returned err");
        assert_eq!(
            records,
            vec![DnsRecord::MX(MXRecord {
                exchange: "mail.example.com".to_string(),
                priority: 10,
            })]
        );
    }

    #[tokio::test]
    async fn test_list_rrset_decodes_caa() {
        let mut server = mockito::Server::new_async().await;
        let _login = mock_login(&mut server, "sess-list-caa");
        let _info = mock_info(
            &mut server,
            "example.com",
            json!([
                {"id": "1", "hostname": "@", "type": "CAA",
                 "destination": "0 issue \"letsencrypt.org\""}
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("example.com", DnsRecordType::CAA, "example.com")
            .await;

        let records = result.expect("list_rrset returned err");
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
    async fn test_add_to_rrset_type_validation() {
        let provider = setup_provider("http://127.0.0.1:1".to_string());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_type_validation() {
        let provider = setup_provider("http://127.0.0.1:1".to_string());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }
}
