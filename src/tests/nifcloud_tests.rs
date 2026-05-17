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
        DnsRecord, DnsRecordType, Error, providers::nifcloud::NifcloudProvider,
    };
    use mockito::Matcher;
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

    #[tokio::test]
    async fn test_create_txt_success() {
        let mut server = mockito::Server::new_async().await;

        let create = server
            .mock(
                "POST",
                "/2012-12-12N2013-12-16/hostedzone/example.com/rrset",
            )
            .match_header("x-nifty-authorization", Matcher::Regex("^NIFTY3-HTTPS .*".into()))
            .match_header("date", Matcher::Any)
            .match_body(Matcher::AllOf(vec![
                Matcher::Regex("<Action>CREATE</Action>".into()),
                Matcher::Regex("<Type>TXT</Type>".into()),
                Matcher::Regex("<TTL>60</TTL>".into()),
                Matcher::Regex("<Value>\"hello\"</Value>".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/xml")
            .with_body(OK_RESPONSE)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("hello".into()),
                60,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        create.assert();
    }

    #[tokio::test]
    async fn test_update_replaces_record() {
        let mut server = mockito::Server::new_async().await;

        let delete = server
            .mock(
                "POST",
                "/2012-12-12N2013-12-16/hostedzone/example.com/rrset",
            )
            .match_body(Matcher::Regex("<Action>DELETE</Action>".into()))
            .with_status(200)
            .with_header("content-type", "application/xml")
            .with_body(OK_RESPONSE)
            .create();

        let create = server
            .mock(
                "POST",
                "/2012-12-12N2013-12-16/hostedzone/example.com/rrset",
            )
            .match_body(Matcher::Regex("<Action>CREATE</Action>".into()))
            .with_status(200)
            .with_header("content-type", "application/xml")
            .with_body(OK_RESPONSE)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "host.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                120,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "update returned: {result:?}");
        delete.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_delete_record() {
        let mut server = mockito::Server::new_async().await;

        let delete = server
            .mock(
                "POST",
                "/2012-12-12N2013-12-16/hostedzone/example.com/rrset",
            )
            .match_body(Matcher::AllOf(vec![
                Matcher::Regex("<Action>DELETE</Action>".into()),
                Matcher::Regex("<Type>TXT</Type>".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/xml")
            .with_body(OK_RESPONSE)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete(
                "_acme-challenge.example.com",
                "example.com",
                DnsRecordType::TXT,
            )
            .await;
        assert!(result.is_ok(), "delete returned: {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn test_auth_error_propagates() {
        let mut server = mockito::Server::new_async().await;

        let create = server
            .mock(
                "POST",
                "/2012-12-12N2013-12-16/hostedzone/example.com/rrset",
            )
            .with_status(401)
            .with_header("content-type", "application/xml")
            .with_body(r#"<ErrorResponse><Error><Code>AuthFailure</Code><Message>bad</Message></Error></ErrorResponse>"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "host.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                60,
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
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
            .create(
                format!("dns-update-test.{domain}"),
                DnsRecord::TXT("hello".into()),
                60,
                &domain,
            )
            .await
            .unwrap();
        provider
            .delete(
                format!("dns-update-test.{domain}"),
                &domain,
                DnsRecordType::TXT,
            )
            .await
            .unwrap();
    }
}
