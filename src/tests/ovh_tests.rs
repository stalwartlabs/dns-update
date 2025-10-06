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
        providers::ovh::{OvhEndpoint, OvhProvider, OvhRecordFormat},
        DnsRecord, DnsRecordType, DnsUpdater, Error,
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider() -> OvhProvider {
        OvhProvider::new(
            "test_app_key",
            "test_app_secret",
            "test_consumer_key",
            OvhEndpoint::OvhEu,
            Some(Duration::from_secs(1)),
        )
        .unwrap()
    }

    #[test]
    fn test_ovh_endpoint_parsing() {
        assert!(matches!(
            "ovh-eu".parse::<OvhEndpoint>().unwrap(),
            OvhEndpoint::OvhEu
        ));
        assert!(matches!(
            "ovh-ca".parse::<OvhEndpoint>().unwrap(),
            OvhEndpoint::OvhCa
        ));
        assert!(matches!(
            "kimsufi-eu".parse::<OvhEndpoint>().unwrap(),
            OvhEndpoint::KimsufiEu
        ));
        assert!(matches!(
            "kimsufi-ca".parse::<OvhEndpoint>().unwrap(),
            OvhEndpoint::KimsufiCa
        ));
        assert!(matches!(
            "soyoustart-eu".parse::<OvhEndpoint>().unwrap(),
            OvhEndpoint::SoyoustartEu
        ));
        assert!(matches!(
            "soyoustart-ca".parse::<OvhEndpoint>().unwrap(),
            OvhEndpoint::SoyoustartCa
        ));

        assert!("invalid-endpoint".parse::<OvhEndpoint>().is_err());
    }

    #[test]
    fn test_ovh_provider_creation() {
        let provider = OvhProvider::new(
            "test_app_key",
            "test_app_secret",
            "test_consumer_key",
            OvhEndpoint::OvhEu,
            Some(Duration::from_secs(30)),
        );

        assert!(provider.is_ok());
    }

    #[test]
    fn test_dns_updater_ovh_creation() {
        let updater = DnsUpdater::new_ovh(
            "test_app_key",
            "test_app_secret",
            "test_consumer_key",
            OvhEndpoint::OvhEu,
            Some(Duration::from_secs(30)),
        );

        assert!(updater.is_ok());

        match updater.unwrap() {
            DnsUpdater::Ovh(_) => (),
            _ => panic!("Expected OVH provider"),
        }
    }

    #[test]
    fn test_ovh_record_format_from_dns_record() {
        let record = DnsRecord::A {
            content: "1.1.1.1".parse().unwrap(),
        };
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "A");
        assert_eq!(ovh_record.target, "1.1.1.1");

        let record = DnsRecord::AAAA {
            content: "2001:db8::1".parse().unwrap(),
        };
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "AAAA");
        assert_eq!(ovh_record.target, "2001:db8::1");

        let record = DnsRecord::CNAME {
            content: "alias.example.com".to_string(),
        };
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "CNAME");
        assert_eq!(ovh_record.target, "alias.example.com");

        let record = DnsRecord::MX {
            priority: 10,
            content: "mail.example.com".to_string(),
        };
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "MX");
        assert_eq!(ovh_record.target, "10 mail.example.com");

        let record = DnsRecord::TXT {
            content: "v=spf1 include:_spf.example.com ~all".to_string(),
        };
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "TXT");
        assert_eq!(ovh_record.target, "v=spf1 include:_spf.example.com ~all");

        let record = DnsRecord::SRV {
            priority: 10,
            weight: 20,
            port: 443,
            content: "sip.example.com".to_string(),
        };
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "SRV");
        assert_eq!(ovh_record.target, "10 20 443 sip.example.com");

        let record = DnsRecord::NS {
            content: "ns1.example.com".to_string(),
        };
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "NS");
        assert_eq!(ovh_record.target, "ns1.example.com");
    }

    #[tokio::test]
    async fn test_create_record_success() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/domain/zone/example.com")
            .with_status(200)
            .match_header("x-ovh-application", "test_app_key")
            .match_header("x-ovh-consumer", "test_consumer_key")
            .with_body(r#"{"name": "example.com"}"#)
            .create();

        let create_mock = server
            .mock("POST", "/domain/zone/example.com/record")
            .with_status(200)
            .match_header("x-ovh-application", "test_app_key")
            .match_header("x-ovh-consumer", "test_consumer_key")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "fieldType": "A",
                "subDomain": "test",
                "target": "1.1.1.1",
                "ttl": 3600
            })))
            .with_body(r#"{"id": 123456789}"#)
            .create();

        let refresh_mock = server
            .mock("POST", "/domain/zone/example.com/refresh")
            .with_status(200)
            .match_header("x-ovh-application", "test_app_key")
            .match_header("x-ovh-consumer", "test_consumer_key")
            .with_body("")
            .create();

        let result = setup_provider()
            .with_endpoint(server.url())
            .create(
                "test.example.com",
                DnsRecord::A {
                    content: "1.1.1.1".parse().unwrap(),
                },
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        zone_mock.assert();
        create_mock.assert();
        refresh_mock.assert();
    }

    #[tokio::test]
    async fn test_update_record_success() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/domain/zone/example.com")
            .with_status(200)
            .match_header("x-ovh-application", "test_app_key")
            .match_header("x-ovh-consumer", "test_consumer_key")
            .with_body(r#"{"name": "example.com"}"#)
            .create();

        let lookup_mock = server
            .mock(
                "GET",
                "/domain/zone/example.com/record?fieldType=A&subDomain=test",
            )
            .with_status(200)
            .match_header("x-ovh-application", "test_app_key")
            .match_header("x-ovh-consumer", "test_consumer_key")
            .with_body(r#"[123456789]"#)
            .create();

        let update_mock = server
            .mock("PUT", "/domain/zone/example.com/record/123456789")
            .with_status(200)
            .match_header("x-ovh-application", "test_app_key")
            .match_header("x-ovh-consumer", "test_consumer_key")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "target": "2.2.2.2",
                "ttl": 3600
            })))
            .with_body("")
            .create();

        let refresh_mock = server
            .mock("POST", "/domain/zone/example.com/refresh")
            .with_status(200)
            .match_header("x-ovh-application", "test_app_key")
            .match_header("x-ovh-consumer", "test_consumer_key")
            .with_body("")
            .create();

        let result = setup_provider()
            .with_endpoint(server.url())
            .update(
                "test.example.com",
                DnsRecord::A {
                    content: "2.2.2.2".parse().unwrap(),
                },
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        zone_mock.assert();
        lookup_mock.assert();
        update_mock.assert();
        refresh_mock.assert();
    }

    #[tokio::test]
    async fn test_delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/domain/zone/example.com")
            .with_status(200)
            .match_header("x-ovh-application", "test_app_key")
            .match_header("x-ovh-consumer", "test_consumer_key")
            .with_body(r#"{"name": "example.com"}"#)
            .create();

        let lookup_mock = server
            .mock(
                "GET",
                "/domain/zone/example.com/record?fieldType=TXT&subDomain=test",
            )
            .with_status(200)
            .match_header("x-ovh-application", "test_app_key")
            .match_header("x-ovh-consumer", "test_consumer_key")
            .with_body(r#"[123456789]"#)
            .create();

        let delete_mock = server
            .mock("DELETE", "/domain/zone/example.com/record/123456789")
            .with_status(200)
            .match_header("x-ovh-application", "test_app_key")
            .match_header("x-ovh-consumer", "test_consumer_key")
            .with_body("")
            .create();

        let refresh_mock = server
            .mock("POST", "/domain/zone/example.com/refresh")
            .with_status(200)
            .match_header("x-ovh-application", "test_app_key")
            .match_header("x-ovh-consumer", "test_consumer_key")
            .with_body("")
            .create();

        let result = setup_provider()
            .with_endpoint(server.url())
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok());
        zone_mock.assert();
        lookup_mock.assert();
        delete_mock.assert();
        refresh_mock.assert();
    }

    #[tokio::test]
    async fn test_create_record_unauthorized() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/domain/zone/example.com")
            .with_status(401)
            .match_header("x-ovh-application", "test_app_key")
            .match_header("x-ovh-consumer", "test_consumer_key")
            .with_body(r#"{"message": "Invalid credentials"}"#)
            .create();

        let result = setup_provider()
            .with_endpoint(server.url())
            .create(
                "test.example.com",
                DnsRecord::A {
                    content: "1.1.1.1".parse().unwrap(),
                },
                3600,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(_))));
        zone_mock.assert();
    }

    #[tokio::test]
    async fn test_record_not_found() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/domain/zone/example.com")
            .with_status(200)
            .match_header("x-ovh-application", "test_app_key")
            .match_header("x-ovh-consumer", "test_consumer_key")
            .with_body(r#"{"name": "example.com"}"#)
            .create();

        let lookup_mock = server
            .mock(
                "GET",
                "/domain/zone/example.com/record?fieldType=A&subDomain=nonexistent",
            )
            .with_status(200)
            .match_header("x-ovh-application", "test_app_key")
            .match_header("x-ovh-consumer", "test_consumer_key")
            .with_body(r#"[]"#)
            .create();

        let result = setup_provider()
            .with_endpoint(server.url())
            .update(
                "nonexistent.example.com",
                DnsRecord::A {
                    content: "1.1.1.1".parse().unwrap(),
                },
                3600,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::NotFound)));
        zone_mock.assert();
        lookup_mock.assert();
    }

    #[tokio::test]
    #[ignore = "Requires OVH API credentials and domain configuration"]
    async fn integration_test() {
        let app_key = std::env::var("OVH_APP_KEY").unwrap_or_default();
        let app_secret = std::env::var("OVH_APP_SECRET").unwrap_or_default();
        let consumer_key = std::env::var("OVH_CONSUMER_KEY").unwrap_or_default();
        let endpoint = std::env::var("OVH_ENDPOINT").unwrap_or_default();
        let origin = std::env::var("OVH_ORIGIN").unwrap_or_default();
        let domain = std::env::var("OVH_DOMAIN").unwrap_or_default();

        assert!(
            !app_key.is_empty(),
            "Please configure your OVH application key in the integration test"
        );
        assert!(
            !app_secret.is_empty(),
            "Please configure your OVH application secret in the integration test"
        );
        assert!(
            !consumer_key.is_empty(),
            "Please configure your OVH consumer key in the integration test"
        );
        assert!(
            !endpoint.is_empty(),
            "Please configure your endpoint in the integration test"
        );
        assert!(
            !origin.is_empty(),
            "Please configure your domain in the integration test"
        );
        assert!(
            !domain.is_empty(),
            "Please configure your test subdomain in the integration test"
        );

        let updater = DnsUpdater::new_ovh(
            app_key,
            app_secret,
            consumer_key,
            endpoint.parse().unwrap(),
            Some(Duration::from_secs(30)),
        )
        .unwrap();

        let creation_result = updater
            .create(
                &domain,
                DnsRecord::A {
                    content: "1.1.1.1".parse().unwrap(),
                },
                3600,
                &origin,
            )
            .await;

        assert!(creation_result.is_ok());

        let update_result = updater
            .update(
                &domain,
                DnsRecord::A {
                    content: "2.2.2.2".parse().unwrap(),
                },
                3600,
                &origin,
            )
            .await;

        assert!(update_result.is_ok());

        let deletion_result = updater.delete(domain, origin, DnsRecordType::A).await;

        assert!(deletion_result.is_ok());
    }
}
