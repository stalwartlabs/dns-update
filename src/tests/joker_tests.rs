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
        DnsRecord, DnsRecordType, Error, MXRecord,
        providers::joker::{JokerAuth, JokerProvider},
    };
    use mockito::Matcher;
    use std::time::Duration;

    fn provider(endpoint: String) -> JokerProvider {
        JokerProvider::new(
            JokerAuth::api_key("api-key-1"),
            Some(Duration::from_secs(1)),
        )
        .unwrap()
        .with_endpoint(endpoint)
    }

    fn login_mock(server: &mut mockito::ServerGuard, sid: &str) -> mockito::Mock {
        server
            .mock("POST", "/login")
            .match_body(Matcher::UrlEncoded("api-key".into(), "api-key-1".into()))
            .with_status(200)
            .with_body(format!(
                "Status-Code: 0\nStatus-Text: OK\nAuth-Sid: {sid}\n\n"
            ))
            .create()
    }

    fn get_zone_mock(
        server: &mut mockito::ServerGuard,
        sid: &str,
        domain: &str,
        zone_body: &str,
    ) -> mockito::Mock {
        server
            .mock("POST", "/dns-zone-get")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("auth-sid".into(), sid.into()),
                Matcher::UrlEncoded("domain".into(), domain.into()),
            ]))
            .with_status(200)
            .with_body(format!("Status-Code: 0\nStatus-Text: OK\n\n{zone_body}"))
            .create()
    }

    fn put_zone_mock_with_zone(
        server: &mut mockito::ServerGuard,
        sid: &str,
        domain: &str,
        expected_zone: &str,
    ) -> mockito::Mock {
        server
            .mock("POST", "/dns-zone-put")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("auth-sid".into(), sid.into()),
                Matcher::UrlEncoded("domain".into(), domain.into()),
                Matcher::UrlEncoded("zone".into(), expected_zone.into()),
            ]))
            .with_status(200)
            .with_body("Status-Code: 0\nStatus-Text: OK\n\n")
            .create()
    }

    #[tokio::test]
    async fn set_rrset_replaces_records_preserving_other_types() {
        let mut server = mockito::Server::new_async().await;
        let login = login_mock(&mut server, "sid");
        let get = get_zone_mock(
            &mut server,
            "sid",
            "example.com",
            "@ NS 0 ns.joker.com. 86400\nwww A 0 1.1.1.1 300\nwww AAAA 0 2001:db8::1 300\nwww TXT 0 \"keep\" 300\n",
        );
        let put = put_zone_mock_with_zone(
            &mut server,
            "sid",
            "example.com",
            "@ NS 0 ns.joker.com. 86400\nwww AAAA 0 2001:db8::1 300\nwww TXT 0 \"keep\" 300\nwww A 0 2.2.2.2 300\nwww A 0 3.3.3.3 300",
        );

        let p = provider(server.url());
        let res = p
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                    DnsRecord::A("3.3.3.3".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(res.is_ok(), "{res:?}");
        login.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_deletes_only_matching_type() {
        let mut server = mockito::Server::new_async().await;
        let login = login_mock(&mut server, "sid");
        let get = get_zone_mock(
            &mut server,
            "sid",
            "example.com",
            "www A 0 1.1.1.1 300\nwww TXT 0 \"keep\" 300\n",
        );
        let put =
            put_zone_mock_with_zone(&mut server, "sid", "example.com", "www TXT 0 \"keep\" 300");

        let p = provider(server.url());
        let res = p
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(res.is_ok(), "{res:?}");
        login.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_already_absent_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let login = login_mock(&mut server, "sid");
        let get = get_zone_mock(
            &mut server,
            "sid",
            "example.com",
            "www TXT 0 \"keep\" 300\n",
        );

        let p = provider(server.url());
        let res = p
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(res.is_ok(), "{res:?}");
        login.assert();
        get.assert();
    }

    #[tokio::test]
    async fn set_rrset_rejects_tlsa() {
        let server = mockito::Server::new_async().await;
        let p = provider(server.url());
        let res = p
            .set_rrset(
                "_443._tcp.example.com",
                DnsRecordType::TLSA,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(
            matches!(res, Err(Error::Unsupported(ref msg)) if msg.contains("TLSA")),
            "{res:?}"
        );
        let _ = server;
    }

    #[tokio::test]
    async fn set_rrset_rejects_type_mismatch() {
        let server = mockito::Server::new_async().await;
        let p = provider(server.url());
        let res = p
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(res, Err(Error::Api(ref msg)) if msg.contains("mismatch")),
            "{res:?}"
        );
        let _ = server;
    }

    #[tokio::test]
    async fn add_to_rrset_empty_short_circuits() {
        let server = mockito::Server::new_async().await;
        let p = provider(server.url());
        let res = p
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(res.is_ok(), "{res:?}");
        let _ = server;
    }

    #[tokio::test]
    async fn add_to_rrset_skips_already_present() {
        let mut server = mockito::Server::new_async().await;
        let login = login_mock(&mut server, "sid");
        let get = get_zone_mock(
            &mut server,
            "sid",
            "example.com",
            "www A 0 1.1.1.1 300\nwww A 0 2.2.2.2 300\n",
        );

        let p = provider(server.url());
        let res = p
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(res.is_ok(), "{res:?}");
        login.assert();
        get.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_appends_only_missing() {
        let mut server = mockito::Server::new_async().await;
        let login = login_mock(&mut server, "sid");
        let get = get_zone_mock(&mut server, "sid", "example.com", "www A 0 1.1.1.1 300\n");
        let put = put_zone_mock_with_zone(
            &mut server,
            "sid",
            "example.com",
            "www A 0 1.1.1.1 300\nwww A 0 2.2.2.2 300",
        );

        let p = provider(server.url());
        let res = p
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
        assert!(res.is_ok(), "{res:?}");
        login.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_short_circuits() {
        let server = mockito::Server::new_async().await;
        let p = provider(server.url());
        let res = p
            .remove_from_rrset("www.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(res.is_ok(), "{res:?}");
        let _ = server;
    }

    #[tokio::test]
    async fn remove_from_rrset_filters_matching() {
        let mut server = mockito::Server::new_async().await;
        let login = login_mock(&mut server, "sid");
        let get = get_zone_mock(
            &mut server,
            "sid",
            "example.com",
            "www A 0 1.1.1.1 300\nwww A 0 2.2.2.2 300\nwww TXT 0 \"keep\" 300\n",
        );
        let put = put_zone_mock_with_zone(
            &mut server,
            "sid",
            "example.com",
            "www A 0 2.2.2.2 300\nwww TXT 0 \"keep\" 300",
        );

        let p = provider(server.url());
        let res = p
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(res.is_ok(), "{res:?}");
        login.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_absent_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let login = login_mock(&mut server, "sid");
        let get = get_zone_mock(&mut server, "sid", "example.com", "www A 0 1.1.1.1 300\n");

        let p = provider(server.url());
        let res = p
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(res.is_ok(), "{res:?}");
        login.assert();
        get.assert();
    }

    #[tokio::test]
    async fn list_rrset_parses_zone() {
        let mut server = mockito::Server::new_async().await;
        let login = login_mock(&mut server, "sid");
        let get = get_zone_mock(
            &mut server,
            "sid",
            "example.com",
            "www A 0 1.1.1.1 300\nwww A 0 2.2.2.2 300\nwww TXT 0 \"hello\" 300\n",
        );

        let p = provider(server.url());
        let listed = p
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();
        assert_eq!(
            listed,
            vec![
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                DnsRecord::A("2.2.2.2".parse().unwrap()),
            ]
        );
        login.assert();
        get.assert();
    }

    #[tokio::test]
    async fn list_rrset_rejects_tlsa() {
        let server = mockito::Server::new_async().await;
        let p = provider(server.url());
        let res = p
            .list_rrset("_443._tcp.example.com", DnsRecordType::TLSA, "example.com")
            .await;
        assert!(
            matches!(res, Err(Error::Unsupported(ref msg)) if msg.contains("TLSA")),
            "{res:?}"
        );
        let _ = server;
    }

    #[tokio::test]
    async fn list_rrset_parses_mx() {
        let mut server = mockito::Server::new_async().await;
        let login = login_mock(&mut server, "sid");
        let get = get_zone_mock(
            &mut server,
            "sid",
            "example.com",
            "@ MX 10 mail.example.com. 300\n@ MX 20 backup.example.com. 300\n",
        );

        let p = provider(server.url());
        let listed = p
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .unwrap();
        assert_eq!(
            listed,
            vec![
                DnsRecord::MX(MXRecord {
                    priority: 10,
                    exchange: "mail.example.com".to_string()
                }),
                DnsRecord::MX(MXRecord {
                    priority: 20,
                    exchange: "backup.example.com".to_string()
                }),
            ]
        );
        login.assert();
        get.assert();
    }

    #[tokio::test]
    async fn set_rrset_clamps_low_ttl_to_minimum() {
        let mut server = mockito::Server::new_async().await;
        let login = login_mock(&mut server, "sid");
        let get = get_zone_mock(&mut server, "sid", "example.com", "");
        let put = put_zone_mock_with_zone(&mut server, "sid", "example.com", "www A 0 1.1.1.1 300");

        let p = provider(server.url());
        let res = p
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                60,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(res.is_ok(), "{res:?}");
        login.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn set_rrset_long_txt_is_chunked() {
        let mut server = mockito::Server::new_async().await;
        let login = login_mock(&mut server, "sid");
        let get = get_zone_mock(&mut server, "sid", "example.com", "");

        let long: String = "a".repeat(300);
        let expected_chunked = format!(
            "_acme TXT 0 \"{}\" \"{}\" 300",
            "a".repeat(255),
            "a".repeat(45),
        );
        let put = put_zone_mock_with_zone(&mut server, "sid", "example.com", &expected_chunked);

        let p = provider(server.url());
        let res = p
            .set_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(long)],
                "example.com",
            )
            .await;
        assert!(res.is_ok(), "{res:?}");
        login.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn set_rrset_preserves_comments_and_dyndns_directive() {
        let mut server = mockito::Server::new_async().await;
        let login = login_mock(&mut server, "sid");
        let get = get_zone_mock(
            &mut server,
            "sid",
            "example.com",
            "# managed zone\n$dyndns=yes:user:pass\nwww A 0 1.1.1.1 300\n",
        );
        let put = put_zone_mock_with_zone(
            &mut server,
            "sid",
            "example.com",
            "# managed zone\n$dyndns=yes:user:pass\nwww A 0 9.9.9.9 300",
        );

        let p = provider(server.url());
        let res = p
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(res.is_ok(), "{res:?}");
        login.assert();
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn session_expiry_triggers_relogin() {
        let mut server = mockito::Server::new_async().await;

        let first_login = server
            .mock("POST", "/login")
            .match_body(Matcher::UrlEncoded("api-key".into(), "api-key-1".into()))
            .with_status(200)
            .with_body("Status-Code: 0\nStatus-Text: OK\nAuth-Sid: stale-sid\n\n")
            .expect(1)
            .create();

        let stale_get = server
            .mock("POST", "/dns-zone-get")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("auth-sid".into(), "stale-sid".into()),
                Matcher::UrlEncoded("domain".into(), "example.com".into()),
            ]))
            .with_status(200)
            .with_body("Status-Code: 2300\nStatus-Text: authorization required\n\n")
            .expect(1)
            .create();

        let second_login = server
            .mock("POST", "/login")
            .match_body(Matcher::UrlEncoded("api-key".into(), "api-key-1".into()))
            .with_status(200)
            .with_body("Status-Code: 0\nStatus-Text: OK\nAuth-Sid: fresh-sid\n\n")
            .expect(1)
            .create();

        let fresh_get = server
            .mock("POST", "/dns-zone-get")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("auth-sid".into(), "fresh-sid".into()),
                Matcher::UrlEncoded("domain".into(), "example.com".into()),
            ]))
            .with_status(200)
            .with_body("Status-Code: 0\nStatus-Text: OK\n\n")
            .expect(1)
            .create();

        let put = put_zone_mock_with_zone(
            &mut server,
            "fresh-sid",
            "example.com",
            "www A 0 1.1.1.1 300",
        );

        let p = provider(server.url());
        let res = p
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(res.is_ok(), "{res:?}");
        first_login.assert();
        stale_get.assert();
        second_login.assert();
        fresh_get.assert();
        put.assert();
    }
}
