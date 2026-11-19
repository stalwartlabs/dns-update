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
        TlsaMatching, TlsaSelector, providers::world4you::World4YouProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const PACKAGE_ID: &str = "12345";
    const SESSION_COOKIE: &str = "W4YSESSID=session123";
    const LOGIN_PAGE: &str = r#"<html><body><form id="loginForm"><input type="hidden" name="_csrf_token" value="csrf123"></form></body></html>"#;
    const PACKAGES_PAGE: &str = r#"<html><body><script id="paketListData" type="application/json">{"items":[{"id":12345,"fqdn":"example.com","description":"Hosting"}]}</script></body></html>"#;

    fn setup_provider(endpoint: &str) -> World4YouProvider {
        World4YouProvider::new("user", "pass", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    fn dns_page(records: serde_json::Value) -> String {
        let records = serde_json::to_string(&records)
            .unwrap()
            .replace('"', "&quot;");

        format!(
            r#"<html><head></head><body>
<meta id="currentDns" data-records="{records}">
<form name="AddDnsRecordForm" method="post">
<input type="hidden" name="AddDnsRecordForm[uniqueFormIdDP]" value="add-dp">
<input type="hidden" name="AddDnsRecordForm[_token]" value="add-token">
</form>
<form name="DeleteDnsRecordForm" method="post">
<input type="hidden" name="DeleteDnsRecordForm[uniqueFormIdDP]" value="delete-dp">
<input type="hidden" name="DeleteDnsRecordForm[_token]" value="delete-token">
</form>
</body></html>"#
        )
    }

    fn mock_login(server: &mut ServerGuard) -> (Mock, Mock) {
        let login_page = server
            .mock("GET", "/login")
            .with_status(200)
            .with_header(
                "set-cookie",
                format!("{SESSION_COOKIE}; path=/; secure; httponly; samesite=lax").as_str(),
            )
            .with_body(LOGIN_PAGE)
            .create();

        let login = server
            .mock("POST", "/login")
            .match_header("cookie", SESSION_COOKIE)
            .match_header("x-requested-with", "XMLHttpRequest")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("_username".into(), "user".into()),
                Matcher::UrlEncoded("_password".into(), "pass".into()),
                Matcher::UrlEncoded("_csrf_token".into(), "csrf123".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":true,"message":null}"#)
            .create();

        (login_page, login)
    }

    fn mock_packages(server: &mut ServerGuard, body: &str) -> Mock {
        server
            .mock("GET", "/")
            .match_header("cookie", SESSION_COOKIE)
            .expect_at_least(1)
            .with_status(200)
            .with_body(body)
            .create()
    }

    fn mock_auth(server: &mut ServerGuard) -> (Mock, Mock, Mock) {
        let (login_page, login) = mock_login(server);
        let packages = mock_packages(server, PACKAGES_PAGE);

        (login_page, login, packages)
    }

    fn mock_dns_page(server: &mut ServerGuard, records: serde_json::Value) -> Mock {
        server
            .mock("GET", format!("/{PACKAGE_ID}/dns").as_str())
            .match_header("cookie", SESSION_COOKIE)
            .expect_at_least(1)
            .with_status(200)
            .with_body(dns_page(records))
            .create()
    }

    fn mock_add(
        server: &mut ServerGuard,
        subdomain: &str,
        record_type: &str,
        priority: Option<u16>,
        value: &str,
    ) -> Mock {
        let mut matchers = vec![
            Matcher::UrlEncoded("AddDnsRecordForm[name]".into(), subdomain.into()),
            Matcher::UrlEncoded("AddDnsRecordForm[dnsType][type]".into(), record_type.into()),
            Matcher::UrlEncoded("AddDnsRecordForm[value]".into(), value.into()),
            Matcher::UrlEncoded("AddDnsRecordForm[uniqueFormIdDP]".into(), "add-dp".into()),
            Matcher::UrlEncoded("AddDnsRecordForm[_token]".into(), "add-token".into()),
        ];

        if let Some(priority) = priority {
            matchers.push(Matcher::UrlEncoded(
                "AddDnsRecordForm[dnsType][prio]".into(),
                priority.to_string(),
            ));
        }

        server
            .mock("POST", format!("/{PACKAGE_ID}/dns").as_str())
            .match_header("cookie", SESSION_COOKIE)
            .match_header("x-requested-with", "XMLHttpRequest")
            .match_body(Matcher::AllOf(matchers))
            .with_status(302)
            .with_header("location", format!("/{PACKAGE_ID}/dns").as_str())
            .create()
    }

    fn mock_delete(server: &mut ServerGuard, record_id: &str) -> Mock {
        server
            .mock("POST", format!("/{PACKAGE_ID}/dns/record/delete").as_str())
            .match_header("cookie", SESSION_COOKIE)
            .match_header("x-requested-with", "XMLHttpRequest")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("DeleteDnsRecordForm[id]".into(), record_id.into()),
                Matcher::UrlEncoded(
                    "DeleteDnsRecordForm[uniqueFormIdDP]".into(),
                    "delete-dp".into(),
                ),
                Matcher::UrlEncoded("DeleteDnsRecordForm[_token]".into(), "delete-token".into()),
            ]))
            .with_status(302)
            .with_header("location", format!("/{PACKAGE_ID}/dns").as_str())
            .create()
    }

    #[tokio::test]
    async fn test_list_rrset_parses_supported_types() {
        let mut server = mockito::Server::new_async().await;
        let (login_page, login, packages) = mock_auth(&mut server);
        let dns = mock_dns_page(
            &mut server,
            json!([
                {"id":"rec-a","name":"test.example.com","type":"A","value":"192.0.2.1","prio":""},
                {"id":"rec-aaaa","name":"test.example.com","type":"AAAA","value":"2001:db8::1","prio":""},
                {"id":"rec-cname","name":"test.example.com","type":"CNAME","value":"target.example.com.","prio":""},
                {"id":"rec-mx","name":"test.example.com","type":"MX","value":"mail.example.com","prio":"10"},
                {"id":"rec-txt","name":"test.example.com","type":"TXT","value":"hello world","prio":""},
                {"id":"rec-srv","name":"test.example.com","type":"SRV","value":"20 443 sip.example.com","prio":"10"},
                {"id":"rec-tlsa","name":"test.example.com","type":"TLSA","value":"3 1 1 deadbeef","prio":""},
                {"id":"rec-caa","name":"test.example.com","type":"CAA","value":"0 issue \"letsencrypt.org\"","prio":""},
                {"id":"rec-other","name":"other.example.com","type":"A","value":"192.0.2.9","prio":""},
            ]),
        );

        let provider = setup_provider(&server.url());
        let cases = [
            (DnsRecordType::A, DnsRecord::A("192.0.2.1".parse().unwrap())),
            (
                DnsRecordType::AAAA,
                DnsRecord::AAAA("2001:db8::1".parse().unwrap()),
            ),
            (
                DnsRecordType::CNAME,
                DnsRecord::CNAME("target.example.com".to_string()),
            ),
            (
                DnsRecordType::MX,
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                }),
            ),
            (
                DnsRecordType::TXT,
                DnsRecord::TXT("hello world".to_string()),
            ),
            (
                DnsRecordType::SRV,
                DnsRecord::SRV(SRVRecord {
                    target: "sip.example.com".to_string(),
                    priority: 10,
                    weight: 20,
                    port: 443,
                }),
            ),
            (
                DnsRecordType::TLSA,
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xde, 0xad, 0xbe, 0xef],
                }),
            ),
            (
                DnsRecordType::CAA,
                DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".to_string()),
                    options: vec![],
                }),
            ),
        ];

        for (record_type, expected) in cases {
            let records = provider
                .list_rrset("test.example.com", record_type, "example.com")
                .await
                .unwrap_or_else(|err| panic!("list {record_type:?} failed: {err}"));
            assert_eq!(records, vec![expected], "record type {record_type:?}");
        }

        login_page.assert();
        login.assert();
        packages.assert();
        dns.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_empty_when_missing() {
        let mut server = mockito::Server::new_async().await;
        let (_, _, _) = mock_auth(&mut server);
        mock_dns_page(&mut server, json!([]));

        let provider = setup_provider(&server.url());
        let records = provider
            .list_rrset("test.example.com", DnsRecordType::TXT, "example.com")
            .await
            .unwrap();

        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn test_set_rrset_adds_missing_and_deletes_extra() {
        let mut server = mockito::Server::new_async().await;
        let (_, _, _) = mock_auth(&mut server);
        mock_dns_page(
            &mut server,
            json!([
                {"id":"rec-old","name":"_acme-challenge.example.com","type":"TXT","value":"old-token","prio":""},
                {"id":"rec-keep","name":"_acme-challenge.example.com","type":"TXT","value":"keep-token","prio":""},
                {"id":"rec-a","name":"_acme-challenge.example.com","type":"A","value":"192.0.2.1","prio":""},
            ]),
        );
        let delete = mock_delete(&mut server, "rec-old");
        let add = mock_add(&mut server, "_acme-challenge", "TXT", None, "new-token");

        let provider = setup_provider(&server.url());
        let result = provider
            .set_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                300,
                vec![
                    DnsRecord::TXT("keep-token".to_string()),
                    DnsRecord::TXT("new-token".to_string()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        delete.assert();
        add.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_everything() {
        let mut server = mockito::Server::new_async().await;
        let (_, _, _) = mock_auth(&mut server);
        mock_dns_page(
            &mut server,
            json!([
                {"id":"rec-1","name":"_acme-challenge.example.com","type":"TXT","value":"token-1","prio":""},
                {"id":"rec-2","name":"_acme-challenge.example.com","type":"TXT","value":"token-2","prio":""},
            ]),
        );
        let delete_1 = mock_delete(&mut server, "rec-1");
        let delete_2 = mock_delete(&mut server, "rec-2");

        let provider = setup_provider(&server.url());
        let result = provider
            .set_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        delete_1.assert();
        delete_2.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let (_, _, _) = mock_auth(&mut server);
        mock_dns_page(
            &mut server,
            json!([
                {"id":"rec-keep","name":"_acme-challenge.example.com","type":"TXT","value":"keep-token","prio":""},
            ]),
        );
        let add = mock_add(&mut server, "_acme-challenge", "TXT", None, "new-token");

        let provider = setup_provider(&server.url());
        let result = provider
            .add_to_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                300,
                vec![
                    DnsRecord::TXT("keep-token".to_string()),
                    DnsRecord::TXT("new-token".to_string()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        add.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_is_noop_when_all_present() {
        let mut server = mockito::Server::new_async().await;
        let (_, _, _) = mock_auth(&mut server);
        mock_dns_page(
            &mut server,
            json!([
                {"id":"rec-keep","name":"_acme-challenge.example.com","type":"TXT","value":"keep-token","prio":""},
            ]),
        );

        let provider = setup_provider(&server.url());
        let result = provider
            .add_to_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("keep-token".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_requested_values() {
        let mut server = mockito::Server::new_async().await;
        let (_, _, _) = mock_auth(&mut server);
        mock_dns_page(
            &mut server,
            json!([
                {"id":"rec-old","name":"_acme-challenge.example.com","type":"TXT","value":"old-token","prio":""},
                {"id":"rec-keep","name":"_acme-challenge.example.com","type":"TXT","value":"keep-token","prio":""},
            ]),
        );
        let delete = mock_delete(&mut server, "rec-old");

        let provider = setup_provider(&server.url());
        let result = provider
            .remove_from_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("old-token".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_is_noop_when_absent() {
        let mut server = mockito::Server::new_async().await;
        let (_, _, _) = mock_auth(&mut server);
        mock_dns_page(
            &mut server,
            json!([
                {"id":"rec-keep","name":"_acme-challenge.example.com","type":"TXT","value":"keep-token","prio":""},
            ]),
        );

        let provider = setup_provider(&server.url());
        let result = provider
            .remove_from_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("missing-token".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_mx_add_sends_priority_separately() {
        let mut server = mockito::Server::new_async().await;
        let (_, _, _) = mock_auth(&mut server);
        mock_dns_page(&mut server, json!([]));
        let add = mock_add(&mut server, "test", "MX", Some(10), "mail.example.com");

        let provider = setup_provider(&server.url());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::MX,
                300,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com.".to_string(),
                    priority: 10,
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        add.assert();
    }

    #[tokio::test]
    async fn test_apex_record_uses_empty_relative_name() {
        let mut server = mockito::Server::new_async().await;
        let (_, _, _) = mock_auth(&mut server);
        mock_dns_page(&mut server, json!([]));
        let add = mock_add(&mut server, "", "A", None, "192.0.2.1");

        let provider = setup_provider(&server.url());
        let result = provider
            .add_to_rrset(
                "example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        add.assert();
    }

    #[tokio::test]
    async fn test_resolves_package_from_origin_first() {
        let mut server = mockito::Server::new_async().await;
        let (_, _) = mock_login(&mut server);
        mock_packages(
            &mut server,
            r#"<html><body><script id="paketListData" type="application/json">{"items":[{"id":111,"fqdn":"example.com"},{"id":222,"fqdn":"sub.example.com"}]}</script></body></html>"#,
        );
        let dns = server
            .mock("GET", "/111/dns")
            .match_header("cookie", SESSION_COOKIE)
            .with_status(200)
            .with_body(dns_page(json!([
                {"id":"rec-1","name":"test.sub.example.com","type":"TXT","value":"token","prio":""},
            ])))
            .create();

        let provider = setup_provider(&server.url());
        let records = provider
            .list_rrset("test.sub.example.com", DnsRecordType::TXT, "example.com")
            .await
            .unwrap();

        assert_eq!(records, vec![DnsRecord::TXT("token".to_string())]);
        dns.assert();
    }

    #[tokio::test]
    async fn test_falls_back_to_longest_package_when_origin_is_unknown() {
        let mut server = mockito::Server::new_async().await;
        let (_, _) = mock_login(&mut server);
        mock_packages(
            &mut server,
            r#"<html><body><script id="paketListData" type="application/json">{"items":[{"id":111,"fqdn":"example.com"},{"id":222,"fqdn":"sub.example.com"}]}</script></body></html>"#,
        );
        let dns = server
            .mock("GET", "/222/dns")
            .match_header("cookie", SESSION_COOKIE)
            .with_status(200)
            .with_body(dns_page(json!([
                {"id":"rec-1","name":"test.sub.example.com","type":"TXT","value":"token","prio":""},
            ])))
            .create();

        let provider = setup_provider(&server.url());
        let records = provider
            .list_rrset("test.sub.example.com", DnsRecordType::TXT, "other.org")
            .await
            .unwrap();

        assert_eq!(records, vec![DnsRecord::TXT("token".to_string())]);
        dns.assert();
    }

    #[tokio::test]
    async fn test_record_type_mismatch_is_rejected_before_any_request() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(&server.url());

        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("token".to_string())],
                "example.com",
            )
            .await;

        match result {
            Err(Error::Api(message)) => assert!(message.contains("RRSet record type mismatch")),
            other => panic!("expected a record type mismatch error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_ns_records_are_unsupported() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(&server.url());

        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::NS,
                300,
                vec![DnsRecord::NS("ns1.example.com".to_string())],
                "example.com",
            )
            .await;

        match result {
            Err(Error::Unsupported(message)) => assert!(message.contains("NS")),
            other => panic!("expected an unsupported error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_form_error_is_returned() {
        let mut server = mockito::Server::new_async().await;
        let (_, _, _) = mock_auth(&mut server);
        mock_dns_page(&mut server, json!([]));
        server
            .mock("POST", format!("/{PACKAGE_ID}/dns").as_str())
            .match_header("cookie", SESSION_COOKIE)
            .with_status(200)
            .with_body(r#"<html><body><div class="form-error-message">Record already exists</div></body></html>"#)
            .create();

        let provider = setup_provider(&server.url());
        let result = provider
            .add_to_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("token".to_string())],
                "example.com",
            )
            .await;

        match result {
            Err(Error::Api(message)) => assert!(message.contains("Record already exists")),
            other => panic!("expected an API error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_login_failure_is_reported() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/login")
            .with_status(200)
            .with_header("set-cookie", format!("{SESSION_COOKIE}; path=/").as_str())
            .with_body(LOGIN_PAGE)
            .create();
        server
            .mock("POST", "/login")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":false,"message":"Invalid credentials"}"#)
            .create();

        let provider = setup_provider(&server.url());
        let result = provider
            .list_rrset("test.example.com", DnsRecordType::TXT, "example.com")
            .await;

        match result {
            Err(Error::Api(message)) => assert!(message.contains("Invalid credentials")),
            other => panic!("expected an API error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_get_page_follows_same_origin_redirect() {
        let mut server = mockito::Server::new_async().await;
        let (_, _) = mock_login(&mut server);
        let redirect = server
            .mock("GET", "/")
            .match_header("cookie", SESSION_COOKIE)
            .with_status(302)
            .with_header("location", "/en/")
            .create();
        let packages = server
            .mock("GET", "/en/")
            .match_header("cookie", SESSION_COOKIE)
            .expect_at_least(1)
            .with_status(200)
            .with_body(PACKAGES_PAGE)
            .create();
        let dns = mock_dns_page(&mut server, json!([]));

        let provider = setup_provider(&server.url());
        let records = provider
            .list_rrset("test.example.com", DnsRecordType::TXT, "example.com")
            .await
            .unwrap();

        assert!(records.is_empty());
        redirect.assert();
        packages.assert();
        dns.assert();
    }

    #[tokio::test]
    async fn test_get_page_rejects_cross_origin_redirect() {
        let mut server = mockito::Server::new_async().await;
        let (_, _) = mock_login(&mut server);
        server
            .mock("GET", "/")
            .match_header("cookie", SESSION_COOKIE)
            .with_status(302)
            .with_header("location", "https://example.invalid/en/")
            .create();

        let provider = setup_provider(&server.url());
        let result = provider
            .list_rrset("test.example.com", DnsRecordType::TXT, "example.com")
            .await;

        match result {
            Err(Error::Api(message)) => assert!(message.contains("unsupported location")),
            other => panic!("expected an API error, got {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore = "Requires WORLD4YOU_USERNAME, WORLD4YOU_PASSWORD and WORLD4YOU_ORIGIN"]
    async fn integration_test() {
        let username = std::env::var("WORLD4YOU_USERNAME").unwrap_or_default();
        let password = std::env::var("WORLD4YOU_PASSWORD").unwrap_or_default();
        let origin = std::env::var("WORLD4YOU_ORIGIN").unwrap_or_default();
        assert!(!username.is_empty(), "Set WORLD4YOU_USERNAME");
        assert!(!password.is_empty(), "Set WORLD4YOU_PASSWORD");
        assert!(
            !origin.is_empty(),
            "Set WORLD4YOU_ORIGIN (e.g. example.com)"
        );

        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let name = format!("_dns-update-{run_id}.{origin}");
        let token = format!("dns-update-test-{run_id}");
        let record = DnsRecord::TXT(token.clone());
        let provider = World4YouProvider::new(username, password, Some(Duration::from_secs(30)));

        provider
            .set_rrset(
                name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![record.clone()],
                origin.as_str(),
            )
            .await
            .unwrap();
        assert!(
            provider
                .list_rrset(name.as_str(), DnsRecordType::TXT, origin.as_str())
                .await
                .unwrap()
                .contains(&record)
        );

        provider
            .remove_from_rrset(
                name.as_str(),
                DnsRecordType::TXT,
                vec![record.clone()],
                origin.as_str(),
            )
            .await
            .unwrap();
        assert!(
            !provider
                .list_rrset(name.as_str(), DnsRecordType::TXT, origin.as_str())
                .await
                .unwrap()
                .contains(&record)
        );

        provider
            .set_rrset(
                name.as_str(),
                DnsRecordType::TXT,
                300,
                vec![],
                origin.as_str(),
            )
            .await
            .unwrap();
    }
}
