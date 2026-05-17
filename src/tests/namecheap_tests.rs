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
        providers::namecheap::NamecheapProvider,
    };
    use mockito::Matcher;
    use std::time::Duration;

    fn provider(endpoint: String) -> NamecheapProvider {
        NamecheapProvider::new(
            "user",
            "key",
            "1.2.3.4",
            None::<&str>,
            Some(Duration::from_secs(1)),
        )
        .unwrap()
        .with_endpoint(format!("{endpoint}/xml.response"))
    }

    const GET_HOSTS_OK: &str = r#"<?xml version="1.0"?>
<ApiResponse Status="OK">
  <Errors/>
  <CommandResponse>
    <DomainDNSGetHostsResult Domain="example.com">
      <host HostId="1" Name="www" Type="A" Address="1.1.1.1" MXPref="10" TTL="300"/>
    </DomainDNSGetHostsResult>
  </CommandResponse>
</ApiResponse>"#;

    const SET_HOSTS_OK: &str = r#"<?xml version="1.0"?>
<ApiResponse Status="OK">
  <Errors/>
  <CommandResponse>
    <DomainDNSSetHostsResult Domain="example.com" IsSuccess="true"/>
  </CommandResponse>
</ApiResponse>"#;

    #[tokio::test]
    async fn test_create_reads_then_writes_hosts() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/xml.response")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("ApiUser".into(), "user".into()),
                Matcher::UrlEncoded("ApiKey".into(), "key".into()),
                Matcher::UrlEncoded("UserName".into(), "user".into()),
                Matcher::UrlEncoded("ClientIp".into(), "1.2.3.4".into()),
                Matcher::UrlEncoded("SLD".into(), "example".into()),
                Matcher::UrlEncoded("TLD".into(), "com".into()),
                Matcher::UrlEncoded("Command".into(), "namecheap.domains.dns.getHosts".into()),
            ]))
            .with_status(200)
            .with_body(GET_HOSTS_OK)
            .create();

        let set = server
            .mock("POST", "/xml.response")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded(
                    "Command".into(),
                    "namecheap.domains.dns.setHosts".into(),
                ),
                Matcher::UrlEncoded("HostName1".into(), "www".into()),
                Matcher::UrlEncoded("RecordType1".into(), "A".into()),
                Matcher::UrlEncoded("Address1".into(), "1.1.1.1".into()),
                Matcher::UrlEncoded("HostName2".into(), "_acme".into()),
                Matcher::UrlEncoded("RecordType2".into(), "TXT".into()),
                Matcher::UrlEncoded("Address2".into(), "value".into()),
            ]))
            .with_status(200)
            .with_body(SET_HOSTS_OK)
            .create();

        let provider = provider(server.url());
        let result = provider
            .create(
                "_acme.example.com",
                DnsRecord::TXT("value".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned {result:?}");
        get.assert();
        set.assert();
    }

    #[tokio::test]
    async fn test_delete_drops_matching_host() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/xml.response")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(GET_HOSTS_OK)
            .create();

        let set = server
            .mock("POST", "/xml.response")
            .match_body(Matcher::AllOf(vec![Matcher::UrlEncoded(
                "Command".into(),
                "namecheap.domains.dns.setHosts".into(),
            )]))
            .with_status(200)
            .with_body(SET_HOSTS_OK)
            .create();

        let provider = provider(server.url());
        let result = provider
            .delete("www.example.com", "example.com", DnsRecordType::A)
            .await;
        assert!(result.is_ok(), "delete returned {result:?}");
        get.assert();
        set.assert();
    }

    #[tokio::test]
    async fn test_api_error_propagates() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", Matcher::Any)
            .with_status(200)
            .with_body(
                r#"<?xml version="1.0"?>
<ApiResponse Status="ERROR">
  <Errors><Error Number="1010102">bad API key</Error></Errors>
</ApiResponse>"#,
            )
            .create();

        let provider = provider(server.url());
        let result = provider
            .create(
                "_acme.example.com",
                DnsRecord::TXT("v".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
        get.assert();
    }

    #[tokio::test]
    #[ignore = "Requires NAMECHEAP_API_USER, NAMECHEAP_API_KEY, NAMECHEAP_CLIENT_IP, NAMECHEAP_ORIGIN, NAMECHEAP_FQDN"]
    async fn integration_test() {
        let user = std::env::var("NAMECHEAP_API_USER").unwrap_or_default();
        let key = std::env::var("NAMECHEAP_API_KEY").unwrap_or_default();
        let ip = std::env::var("NAMECHEAP_CLIENT_IP").unwrap_or_default();
        let origin = std::env::var("NAMECHEAP_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("NAMECHEAP_FQDN").unwrap_or_default();
        assert!(
            !user.is_empty()
                && !key.is_empty()
                && !ip.is_empty()
                && !origin.is_empty()
                && !fqdn.is_empty()
        );

        let updater = DnsUpdater::new_namecheap(
            user,
            key,
            ip,
            None::<&str>,
            Some(Duration::from_secs(30)),
        )
        .unwrap();
        updater
            .create(&fqdn, DnsRecord::TXT("v".to_string()), 300, &origin)
            .await
            .unwrap();
        updater
            .delete(&fqdn, &origin, DnsRecordType::TXT)
            .await
            .unwrap();
    }
}
