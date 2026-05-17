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
        DnsRecord, DnsRecordType, DnsUpdater, Error,
        providers::namesilo::NameSiloProvider,
    };
    use mockito::Matcher;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> NameSiloProvider {
        NameSiloProvider::new("apikey", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn ok_reply(code: &str, detail: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><namesilo><request><operation>op</operation><ip>0.0.0.0</ip></request><reply><code>{code}</code><detail>{detail}</detail></reply></namesilo>"#
        )
    }

    fn list_reply(records: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><namesilo><request><operation>dnsListRecords</operation><ip>0.0.0.0</ip></request><reply><code>300</code><detail>success</detail>{records}</reply></namesilo>"#
        )
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/dnsAddRecord")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("version".into(), "1".into()),
                Matcher::UrlEncoded("type".into(), "xml".into()),
                Matcher::UrlEncoded("key".into(), "apikey".into()),
                Matcher::UrlEncoded("domain".into(), "example.com".into()),
                Matcher::UrlEncoded("rrtype".into(), "A".into()),
                Matcher::UrlEncoded("rrhost".into(), "www".into()),
                Matcher::UrlEncoded("rrvalue".into(), "1.2.3.4".into()),
                Matcher::UrlEncoded("rrttl".into(), "600".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/xml")
            .with_body(ok_reply("300", "success"))
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_looks_up_record_id_then_updates() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/dnsListRecords")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(list_reply(
                r#"<resource_record><record_id>abc123</record_id><type>A</type><host>www.example.com</host><value>1.1.1.1</value><ttl>600</ttl><distance>0</distance></resource_record>"#,
            ))
            .create();

        let update = server
            .mock("GET", "/dnsUpdateRecord")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("rrid".into(), "abc123".into()),
                Matcher::UrlEncoded("rrhost".into(), "www".into()),
                Matcher::UrlEncoded("rrvalue".into(), "8.8.8.8".into()),
                Matcher::UrlEncoded("rrttl".into(), "600".into()),
            ]))
            .with_status(200)
            .with_body(ok_reply("300", "success"))
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "www.example.com",
                DnsRecord::A("8.8.8.8".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update returned: {result:?}");
        list.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_delete_looks_up_record_id_then_deletes() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/dnsListRecords")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(list_reply(
                r#"<resource_record><record_id>zzz</record_id><type>TXT</type><host>_acme-challenge.example.com</host><value>foo</value><ttl>3600</ttl><distance>0</distance></resource_record>"#,
            ))
            .create();

        let delete = server
            .mock("GET", "/dnsDeleteRecord")
            .match_query(Matcher::UrlEncoded("rrid".into(), "zzz".into()))
            .with_status(200)
            .with_body(ok_reply("300", "success"))
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
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_namesilo_api_error_returned() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/dnsAddRecord")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(ok_reply("280", "Invalid"))
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
        mock.assert();
    }

    #[tokio::test]
    async fn test_http_unauthorized_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("GET", "/dnsAddRecord")
            .match_query(Matcher::Any)
            .with_status(401)
            .with_body("")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
        unauthorized.assert();
    }

    #[tokio::test]
    #[ignore = "Requires NAMESILO_API_KEY, NAMESILO_ORIGIN, NAMESILO_FQDN"]
    async fn integration_test() {
        let key = std::env::var("NAMESILO_API_KEY").unwrap_or_default();
        let origin = std::env::var("NAMESILO_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("NAMESILO_FQDN").unwrap_or_default();

        assert!(!key.is_empty(), "Set NAMESILO_API_KEY to run this test");
        assert!(!origin.is_empty(), "Set NAMESILO_ORIGIN to run this test");
        assert!(!fqdn.is_empty(), "Set NAMESILO_FQDN to run this test");

        let updater = DnsUpdater::new_namesilo(key, Some(Duration::from_secs(30))).unwrap();

        let create_result = updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 3600, &origin)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");

        let update_result = updater
            .update(&fqdn, DnsRecord::A([8, 8, 8, 8].into()), 3600, &origin)
            .await;
        assert!(update_result.is_ok(), "update failed: {update_result:?}");

        let delete_result = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
