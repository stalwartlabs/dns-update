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
        CAARecord, DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord,
        providers::easydns::EasyDnsProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use std::time::Duration;

    fn provider(endpoint: String) -> EasyDnsProvider {
        EasyDnsProvider::new("token", "key", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn mock_list(server: &mut ServerGuard, body: &str) -> Mock {
        server
            .mock("GET", "/zones/records/all/example.com?format=json")
            .match_header("authorization", "Basic dG9rZW46a2V5")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, r#"{"data":[]}"#);

        let put_1 = server
            .mock("PUT", "/zones/records/add/example.com/A?format=json")
            .match_body(Matcher::PartialJsonString(
                r#"{"domain":"example.com","host":"www","type":"A","rdata":"1.1.1.1","ttl":"300","prio":"0"}"#
                    .to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"data":{"id":"a"}}"#)
            .create();
        let put_2 = server
            .mock("PUT", "/zones/records/add/example.com/A?format=json")
            .match_body(Matcher::PartialJsonString(
                r#"{"domain":"example.com","host":"www","type":"A","rdata":"2.2.2.2","ttl":"300","prio":"0"}"#
                    .to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"data":{"id":"b"}}"#)
            .expect(1)
            .create();

        let provider = provider(server.url());
        let result = provider
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
            .await;

        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
        put_1.assert();
        put_2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            r#"{"data":[{"id":"r1","host":"www","type":"A","rdata":"1.1.1.1","ttl":"300","prio":"0"}]}"#,
        );

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_keeps_matching() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            r#"{"data":[
                {"id":"keep","host":"www","type":"A","rdata":"1.1.1.1","ttl":"300","prio":"0"},
                {"id":"stale","host":"www","type":"A","rdata":"9.9.9.9","ttl":"300","prio":"0"}
            ]}"#,
        );
        let delete_stale = server
            .mock("DELETE", "/zones/records/example.com/stale?format=json")
            .with_status(200)
            .with_body("{}")
            .create();
        let put_new = server
            .mock("PUT", "/zones/records/add/example.com/A?format=json")
            .match_body(Matcher::PartialJsonString(
                r#"{"host":"www","type":"A","rdata":"8.8.8.8"}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"data":{"id":"new"}}"#)
            .create();

        let provider = provider(server.url());
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

        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
        delete_stale.assert();
        put_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_records_deletes_all_of_type() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            r#"{"data":[
                {"id":"a1","host":"www","type":"A","rdata":"1.1.1.1","ttl":"300","prio":"0"},
                {"id":"a2","host":"www","type":"A","rdata":"2.2.2.2","ttl":"300","prio":"0"},
                {"id":"txt1","host":"www","type":"TXT","rdata":"keep-me","ttl":"300","prio":"0"}
            ]}"#,
        );
        let delete_a1 = server
            .mock("DELETE", "/zones/records/example.com/a1?format=json")
            .with_status(200)
            .with_body("{}")
            .create();
        let delete_a2 = server
            .mock("DELETE", "/zones/records/example.com/a2?format=json")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
        delete_a1.assert();
        delete_a2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            r#"{"data":[
                {"id":"a1","host":"www","type":"A","rdata":"1.1.1.1","ttl":"300","prio":"0"},
                {"id":"txt1","host":"www","type":"TXT","rdata":"hands-off","ttl":"300","prio":"0"}
            ]}"#,
        );
        let put_new = server
            .mock("PUT", "/zones/records/add/example.com/A?format=json")
            .match_body(Matcher::PartialJsonString(
                r#"{"host":"www","type":"A","rdata":"2.2.2.2"}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"data":{"id":"new"}}"#)
            .create();

        let provider = provider(server.url());
        let result = provider
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
            .await;

        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
        put_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
        let _ = server;
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            r#"{"data":[
                {"id":"r1","host":"_acme","type":"TXT","rdata":"existing","ttl":"60","prio":"0"}
            ]}"#,
        );
        let put_new = server
            .mock("PUT", "/zones/records/add/example.com/TXT?format=json")
            .match_body(Matcher::PartialJsonString(
                r#"{"host":"_acme","type":"TXT","rdata":"new-token"}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"data":{"id":"new"}}"#)
            .create();

        let provider = provider(server.url());
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
        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
        list.assert();
        put_new.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = provider(server.url());
        let result = provider
            .remove_from_rrset("www.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            r#"{"data":[
                {"id":"keep","host":"_acme","type":"TXT","rdata":"keep-me","ttl":"60","prio":"0"},
                {"id":"drop","host":"_acme","type":"TXT","rdata":"drop-me","ttl":"60","prio":"0"}
            ]}"#,
        );
        let delete = server
            .mock("DELETE", "/zones/records/example.com/drop?format=json")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = provider(server.url());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop-me".to_string())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_absent_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            r#"{"data":[
                {"id":"keep","host":"_acme","type":"TXT","rdata":"keep-me","ttl":"60","prio":"0"}
            ]}"#,
        );

        let provider = provider(server.url());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("not-here".to_string())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_two_mx_with_different_priorities() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, r#"{"data":[]}"#);
        let put_10 = server
            .mock("PUT", "/zones/records/add/example.com/MX?format=json")
            .match_body(Matcher::PartialJsonString(
                r#"{"host":"@","type":"MX","rdata":"mail1.example.com.","prio":"10"}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"data":{"id":"m1"}}"#)
            .create();
        let put_20 = server
            .mock("PUT", "/zones/records/add/example.com/MX?format=json")
            .match_body(Matcher::PartialJsonString(
                r#"{"host":"@","type":"MX","rdata":"mail2.example.com.","prio":"20"}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"data":{"id":"m2"}}"#)
            .create();

        let provider = provider(server.url());
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
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
        put_10.assert();
        put_20.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_uses_prio_and_rdata_format() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, r#"{"data":[]}"#);
        let put = server
            .mock("PUT", "/zones/records/add/example.com/SRV?format=json")
            .match_body(Matcher::PartialJsonString(
                r#"{"host":"_sip._tcp","type":"SRV","rdata":"5 5060 sipserver.example.com.","prio":"10"}"#
                    .to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"data":{"id":"s1"}}"#)
            .create();

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                3600,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 5060,
                    target: "sipserver.example.com.".to_string(),
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_bind_style_rdata() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, r#"{"data":[]}"#);
        let put = server
            .mock("PUT", "/zones/records/add/example.com/CAA?format=json")
            .match_body(Matcher::PartialJsonString(
                r#"{"host":"@","type":"CAA","rdata":"0 issue \"letsencrypt.org\""}"#.to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"data":{"id":"c1"}}"#)
            .create();

        let provider = provider(server.url());
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
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![DnsRecord::TLSA(crate::TLSARecord {
                    cert_usage: crate::TlsaCertUsage::DaneEe,
                    selector: crate::TlsaSelector::Spki,
                    matching: crate::TlsaMatching::Sha256,
                    cert_data: vec![0xaa],
                })],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
        let _ = server;
    }

    #[tokio::test]
    async fn test_list_rrset_filters_by_name_and_type() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            r#"{"data":[
                {"id":"1","host":"www","type":"A","rdata":"1.1.1.1","ttl":"300","prio":"0"},
                {"id":"2","host":"www","type":"A","rdata":"2.2.2.2","ttl":"300","prio":"0"},
                {"id":"3","host":"www","type":"TXT","rdata":"ignore","ttl":"300","prio":"0"},
                {"id":"4","host":"other","type":"A","rdata":"9.9.9.9","ttl":"300","prio":"0"}
            ]}"#,
        );

        let provider = provider(server.url());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();
        list.assert();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
    }

    #[tokio::test]
    async fn test_list_rrset_mx_parses_priority() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            r#"{"data":[
                {"id":"1","host":"@","type":"MX","rdata":"mail.example.com.","ttl":"300","prio":"10"}
            ]}"#,
        );

        let provider = provider(server.url());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .unwrap();
        list.assert();
        assert_eq!(
            result,
            vec![DnsRecord::MX(MXRecord {
                exchange: "mail.example.com.".to_string(),
                priority: 10,
            })]
        );
    }

    #[tokio::test]
    async fn test_set_rrset_idempotent_second_call_noop() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            r#"{"data":[
                {"id":"r1","host":"www","type":"A","rdata":"1.1.1.1","ttl":"300","prio":"0"},
                {"id":"r2","host":"www","type":"A","rdata":"2.2.2.2","ttl":"300","prio":"0"}
            ]}"#,
        );

        let provider = provider(server.url());
        let result = provider
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
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        list.assert();
    }
}
