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
    use crate::{DnsRecord, DnsRecordType, Error, MXRecord, providers::nifcloud::NifcloudProvider};
    use mockito::{Matcher, Mock, ServerGuard};
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> NifcloudProvider {
        NifcloudProvider::new("access", "secret", Some(Duration::from_secs(2)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    const OK_RESPONSE: &str = r#"<?xml version="1.0"?>
<ChangeResourceRecordSetsResponse>
    <ChangeInfo>
        <Id>/change/CHANGE1</Id>
        <Status>PENDING</Status>
    </ChangeInfo>
</ChangeResourceRecordSetsResponse>"#;

    fn mock_list_empty(server: &mut ServerGuard) -> Mock {
        server
            .mock("GET", "/2012-12-12N2013-12-16/hostedzone/example.com/rrset")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/xml")
            .with_body(
                r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
    <ResourceRecordSets></ResourceRecordSets>
    <IsTruncated>false</IsTruncated>
    <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>"#,
            )
            .create()
    }

    fn mock_list_with(server: &mut ServerGuard, body: &str) -> Mock {
        server
            .mock("GET", "/2012-12-12N2013-12-16/hostedzone/example.com/rrset")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/xml")
            .with_body(body)
            .create()
    }

    fn mock_change<F>(server: &mut ServerGuard, matcher: F) -> Mock
    where
        F: Into<Matcher>,
    {
        server
            .mock(
                "POST",
                "/2012-12-12N2013-12-16/hostedzone/example.com/rrset",
            )
            .match_header(
                "x-nifty-authorization",
                Matcher::Regex("^NIFTY3-HTTPS .*Algorithm=HmacSHA256,.*$".into()),
            )
            .match_header("date", Matcher::Any)
            .match_body(matcher.into())
            .with_status(200)
            .with_header("content-type", "application/xml")
            .with_body(OK_RESPONSE)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_empty() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_list_empty(&mut server);
        let change = mock_change(
            &mut server,
            Matcher::AllOf(vec![
                Matcher::Regex("<Action>CREATE</Action>".into()),
                Matcher::Regex("<Type>A</Type>".into()),
                Matcher::Regex("<Value>1.1.1.1</Value>".into()),
                Matcher::Regex("<Value>2.2.2.2</Value>".into()),
                Matcher::Regex("<TTL>300</TTL>".into()),
            ]),
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
        list.assert();
        change.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_list_with(
            &mut server,
            r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
    <ResourceRecordSets>
        <ResourceRecordSet>
            <Name>host.example.com</Name>
            <Type>A</Type>
            <TTL>300</TTL>
            <ResourceRecords>
                <ResourceRecord><Value>1.1.1.1</Value></ResourceRecord>
            </ResourceRecords>
        </ResourceRecordSet>
    </ResourceRecordSets>
    <IsTruncated>false</IsTruncated>
    <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>"#,
        );

        let provider = setup_provider(server.url());
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
    async fn test_set_rrset_replaces_old_with_atomic_batch() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_list_with(
            &mut server,
            r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
    <ResourceRecordSets>
        <ResourceRecordSet>
            <Name>host.example.com</Name>
            <Type>A</Type>
            <TTL>60</TTL>
            <ResourceRecords>
                <ResourceRecord><Value>9.9.9.9</Value></ResourceRecord>
            </ResourceRecords>
        </ResourceRecordSet>
    </ResourceRecordSets>
    <IsTruncated>false</IsTruncated>
    <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>"#,
        );

        let change = mock_change(
            &mut server,
            Matcher::AllOf(vec![
                Matcher::Regex("<Action>DELETE</Action>".into()),
                Matcher::Regex("<Value>9.9.9.9</Value>".into()),
                Matcher::Regex("<Action>CREATE</Action>".into()),
                Matcher::Regex("<Value>1.2.3.4</Value>".into()),
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        change.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_the_rrset() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_list_with(
            &mut server,
            r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
    <ResourceRecordSets>
        <ResourceRecordSet>
            <Name>host.example.com</Name>
            <Type>A</Type>
            <TTL>60</TTL>
            <ResourceRecords>
                <ResourceRecord><Value>9.9.9.9</Value></ResourceRecord>
            </ResourceRecords>
        </ResourceRecordSet>
    </ResourceRecordSets>
    <IsTruncated>false</IsTruncated>
    <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>"#,
        );

        let change = mock_change(
            &mut server,
            Matcher::AllOf(vec![
                Matcher::Regex("<Action>DELETE</Action>".into()),
                Matcher::Regex("<Type>A</Type>".into()),
                Matcher::Regex("<Value>9.9.9.9</Value>".into()),
            ]),
        );

        let provider = setup_provider(server.url());
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
        change.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_on_absent_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_empty(&mut server);

        let provider = setup_provider(server.url());
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
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_list_with(
            &mut server,
            r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
    <ResourceRecordSets>
        <ResourceRecordSet>
            <Name>host.example.com</Name>
            <Type>AAAA</Type>
            <TTL>60</TTL>
            <ResourceRecords>
                <ResourceRecord><Value>::1</Value></ResourceRecord>
            </ResourceRecords>
        </ResourceRecordSet>
    </ResourceRecordSets>
    <IsTruncated>false</IsTruncated>
    <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>"#,
        );

        let change = mock_change(
            &mut server,
            Matcher::AllOf(vec![
                Matcher::Regex("<Action>CREATE</Action>".into()),
                Matcher::Regex("<Type>A</Type>".into()),
                Matcher::Regex("<Value>1.1.1.1</Value>".into()),
            ]),
        );

        let provider = setup_provider(server.url());
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
        change.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_appends_new_values_atomically() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_list_with(
            &mut server,
            r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
    <ResourceRecordSets>
        <ResourceRecordSet>
            <Name>host.example.com</Name>
            <Type>A</Type>
            <TTL>60</TTL>
            <ResourceRecords>
                <ResourceRecord><Value>1.1.1.1</Value></ResourceRecord>
            </ResourceRecords>
        </ResourceRecordSet>
    </ResourceRecordSets>
    <IsTruncated>false</IsTruncated>
    <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>"#,
        );

        let change = mock_change(
            &mut server,
            Matcher::AllOf(vec![
                Matcher::Regex("<Action>DELETE</Action>".into()),
                Matcher::Regex("<Value>1.1.1.1</Value>".into()),
                Matcher::Regex("<Action>CREATE</Action>".into()),
                Matcher::Regex("<Value>2.2.2.2</Value>".into()),
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("2.2.2.2".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        list.assert();
        change.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_creates_when_absent() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_list_empty(&mut server);
        let change = mock_change(
            &mut server,
            Matcher::AllOf(vec![
                Matcher::Regex("<Action>CREATE</Action>".into()),
                Matcher::Regex("<Value>1.1.1.1</Value>".into()),
                Matcher::Regex("<TTL>300</TTL>".into()),
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        list.assert();
        change.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_duplicates() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_list_with(
            &mut server,
            r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
    <ResourceRecordSets>
        <ResourceRecordSet>
            <Name>host.example.com</Name>
            <Type>A</Type>
            <TTL>60</TTL>
            <ResourceRecords>
                <ResourceRecord><Value>1.1.1.1</Value></ResourceRecord>
            </ResourceRecords>
        </ResourceRecordSet>
    </ResourceRecordSets>
    <IsTruncated>false</IsTruncated>
    <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>"#,
        );

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_short_circuit() {
        let server = mockito::Server::new_async().await;

        let provider = setup_provider(server.url());
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
        let _ = server;
    }

    #[tokio::test]
    async fn test_remove_from_rrset_filters_existing() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_list_with(
            &mut server,
            r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
    <ResourceRecordSets>
        <ResourceRecordSet>
            <Name>host.example.com</Name>
            <Type>A</Type>
            <TTL>60</TTL>
            <ResourceRecords>
                <ResourceRecord><Value>1.1.1.1</Value></ResourceRecord>
                <ResourceRecord><Value>2.2.2.2</Value></ResourceRecord>
            </ResourceRecords>
        </ResourceRecordSet>
    </ResourceRecordSets>
    <IsTruncated>false</IsTruncated>
    <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>"#,
        );

        let change = mock_change(
            &mut server,
            Matcher::AllOf(vec![
                Matcher::Regex("<Action>DELETE</Action>".into()),
                Matcher::Regex("<Value>1.1.1.1</Value>".into()),
                Matcher::Regex("<Value>2.2.2.2</Value>".into()),
                Matcher::Regex("<Action>CREATE</Action>".into()),
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
        change.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_last_value() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_list_with(
            &mut server,
            r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
    <ResourceRecordSets>
        <ResourceRecordSet>
            <Name>host.example.com</Name>
            <Type>A</Type>
            <TTL>60</TTL>
            <ResourceRecords>
                <ResourceRecord><Value>1.1.1.1</Value></ResourceRecord>
            </ResourceRecords>
        </ResourceRecordSet>
    </ResourceRecordSets>
    <IsTruncated>false</IsTruncated>
    <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>"#,
        );

        let change = server
            .mock(
                "POST",
                "/2012-12-12N2013-12-16/hostedzone/example.com/rrset",
            )
            .match_body(Matcher::AllOf(vec![
                Matcher::Regex("<Action>DELETE</Action>".into()),
                Matcher::Regex("<Value>1.1.1.1</Value>".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/xml")
            .with_body(OK_RESPONSE)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
        change.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_skips_absent_values() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_list_with(
            &mut server,
            r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
    <ResourceRecordSets>
        <ResourceRecordSet>
            <Name>host.example.com</Name>
            <Type>A</Type>
            <TTL>60</TTL>
            <ResourceRecords>
                <ResourceRecord><Value>1.1.1.1</Value></ResourceRecord>
            </ResourceRecords>
        </ResourceRecordSet>
    </ResourceRecordSets>
    <IsTruncated>false</IsTruncated>
    <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>"#,
        );

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_short_circuit() {
        let server = mockito::Server::new_async().await;

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset("host.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        let _ = server;
    }

    #[tokio::test]
    async fn test_list_rrset_returns_parsed_records() {
        let mut server = mockito::Server::new_async().await;

        let list = mock_list_with(
            &mut server,
            r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse>
    <ResourceRecordSets>
        <ResourceRecordSet>
            <Name>mail.example.com</Name>
            <Type>MX</Type>
            <TTL>60</TTL>
            <ResourceRecords>
                <ResourceRecord><Value>10 mx1.example.com</Value></ResourceRecord>
                <ResourceRecord><Value>20 mx2.example.com</Value></ResourceRecord>
            </ResourceRecords>
        </ResourceRecordSet>
    </ResourceRecordSets>
    <IsTruncated>false</IsTruncated>
    <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>"#,
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("mail.example.com", DnsRecordType::MX, "example.com")
            .await
            .unwrap();
        assert_eq!(
            result,
            vec![
                DnsRecord::MX(MXRecord {
                    priority: 10,
                    exchange: "mx1.example.com".to_string()
                }),
                DnsRecord::MX(MXRecord {
                    priority: 20,
                    exchange: "mx2.example.com".to_string()
                }),
            ]
        );
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_srv() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "srv.example.com",
                DnsRecordType::SRV,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("SRV")),
            "expected SRV rejection, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_caa() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::CAA,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("CAA")),
            "expected CAA rejection, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_tlsa() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::TLSA,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("TLSA")),
            "expected TLSA rejection, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_type_validation_rejects_mismatch() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("x".into())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("mismatch")),
            "expected type mismatch error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_auth_error_propagates() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list_empty(&mut server);

        let create = server
            .mock(
                "POST",
                "/2012-12-12N2013-12-16/hostedzone/example.com/rrset",
            )
            .with_status(401)
            .with_header("content-type", "application/xml")
            .with_body(
                r#"<ErrorResponse><Error><Code>AuthFailure</Code><Message>bad</Message></Error></ErrorResponse>"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                60,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
        list.assert();
        create.assert();
    }

    #[tokio::test]
    #[ignore = "requires NIFCLOUD_ACCESS_KEY_ID, NIFCLOUD_SECRET_ACCESS_KEY, NIFCLOUD_DOMAIN env vars"]
    async fn test_live_nifcloud_roundtrip() {
        let access_key = std::env::var("NIFCLOUD_ACCESS_KEY_ID").expect("NIFCLOUD_ACCESS_KEY_ID");
        let secret_key =
            std::env::var("NIFCLOUD_SECRET_ACCESS_KEY").expect("NIFCLOUD_SECRET_ACCESS_KEY");
        let domain = std::env::var("NIFCLOUD_DOMAIN").expect("NIFCLOUD_DOMAIN");
        let provider =
            NifcloudProvider::new(access_key, secret_key, Some(Duration::from_secs(30))).unwrap();
        provider
            .set_rrset(
                format!("dns-update-test.{domain}"),
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("hello".into())],
                &domain,
            )
            .await
            .unwrap();
        provider
            .set_rrset(
                format!("dns-update-test.{domain}"),
                DnsRecordType::TXT,
                60,
                vec![],
                &domain,
            )
            .await
            .unwrap();
    }
}
