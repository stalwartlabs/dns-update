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
        DnsRecord, DnsRecordType, DnsUpdater,
        providers::bluecatv2::{BluecatV2Config, BluecatV2Provider},
    };
    use std::time::Duration;

    fn config() -> BluecatV2Config {
        BluecatV2Config {
            server_url: "http://placeholder".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            config_name: "default".to_string(),
            view_name: "internal".to_string(),
            skip_deploy: true,
            request_timeout: Some(Duration::from_secs(1)),
        }
    }

    fn config_with_deploy() -> BluecatV2Config {
        let mut c = config();
        c.skip_deploy = false;
        c
    }

    fn setup(endpoint: &str) -> BluecatV2Provider {
        BluecatV2Provider::new(config())
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn setup_with_deploy(endpoint: &str) -> BluecatV2Provider {
        BluecatV2Provider::new(config_with_deploy())
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn mock_session(server: &mut mockito::ServerGuard) -> mockito::Mock {
        server
            .mock("POST", "/api/v2/sessions")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"basicAuthenticationCredentials":"AUTH"}"#)
            .create()
    }

    fn mock_zone(server: &mut mockito::ServerGuard) -> mockito::Mock {
        server
            .mock("GET", mockito::Matcher::Regex("/api/v2/zones\\?.*".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"count":1,"totalCount":1,"data":[{"id":42,"absoluteName":"example.com"}]}"#,
            )
            .create()
    }

    fn mock_deploy(server: &mut mockito::ServerGuard) -> mockito::Mock {
        server
            .mock("POST", "/api/v2/zones/42/deployments")
            .match_header("authorization", "Basic AUTH")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "type": "QuickDeployment",
            })))
            .with_status(200)
            .with_body(r#"{"id":1}"#)
            .create()
    }

    #[test]
    fn rejects_missing_credentials() {
        let mut cfg = config();
        cfg.username.clear();
        assert!(matches!(
            BluecatV2Provider::new(cfg),
            Err(crate::Error::Api(_))
        ));
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_bluecatv2(config());
        assert!(matches!(updater, Ok(DnsUpdater::BluecatV2(..))));
    }

    #[tokio::test]
    async fn set_rrset_replaces_records_and_deploys() {
        let mut server = mockito::Server::new_async().await;
        let session = mock_session(&mut server);
        let zone = mock_zone(&mut server);

        let list = server
            .mock(
                "GET",
                mockito::Matcher::Regex("/api/v2/zones/42/resourceRecords\\?.*".into()),
            )
            .with_status(200)
            .with_body(
                r#"{"count":2,"totalCount":2,"data":[
                    {"id":11,"absoluteName":"app.example.com","recordType":"A","addresses":["1.1.1.1"]},
                    {"id":12,"absoluteName":"app.example.com","recordType":"A","addresses":["9.9.9.9"]}
                ]}"#,
            )
            .create();

        let delete_extra = server
            .mock("DELETE", "/api/v2/resourceRecords/12")
            .with_status(204)
            .expect(1)
            .create();

        let create_new = server
            .mock("POST", "/api/v2/zones/42/resourceRecords")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "type": "GenericRecord",
                "name": "app",
                "recordType": "A",
                "addresses": ["2.2.2.2"],
            })))
            .with_status(201)
            .with_body(r#"{"id":21}"#)
            .expect(1)
            .create();

        let deploy = mock_deploy(&mut server);

        let provider = setup_with_deploy(server.url().as_str());
        let result = provider
            .set_rrset(
                "app.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        session.assert();
        zone.assert();
        list.assert();
        delete_extra.assert();
        create_new.assert();
        deploy.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_deletes_rrset_and_deploys() {
        let mut server = mockito::Server::new_async().await;
        let session = mock_session(&mut server);
        let zone = mock_zone(&mut server);

        let list = server
            .mock(
                "GET",
                mockito::Matcher::Regex("/api/v2/zones/42/resourceRecords\\?.*".into()),
            )
            .with_status(200)
            .with_body(
                r#"{"count":2,"totalCount":2,"data":[
                    {"id":11,"absoluteName":"app.example.com","recordType":"TXT","text":"a"},
                    {"id":12,"absoluteName":"app.example.com","recordType":"TXT","text":"b"}
                ]}"#,
            )
            .create();

        let delete_one = server
            .mock("DELETE", "/api/v2/resourceRecords/11")
            .with_status(204)
            .expect(1)
            .create();
        let delete_two = server
            .mock("DELETE", "/api/v2/resourceRecords/12")
            .with_status(204)
            .expect(1)
            .create();

        let no_post = server
            .mock("POST", "/api/v2/zones/42/resourceRecords")
            .expect(0)
            .create();

        let deploy = mock_deploy(&mut server);

        let provider = setup_with_deploy(server.url().as_str());
        let result = provider
            .set_rrset(
                "app.example.com",
                DnsRecordType::TXT,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        session.assert();
        zone.assert();
        list.assert();
        delete_one.assert();
        delete_two.assert();
        no_post.assert();
        deploy.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_no_existing_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let session = mock_session(&mut server);
        let zone = mock_zone(&mut server);

        let list = server
            .mock(
                "GET",
                mockito::Matcher::Regex("/api/v2/zones/42/resourceRecords\\?.*".into()),
            )
            .with_status(200)
            .with_body(r#"{"count":0,"totalCount":0,"data":[]}"#)
            .create();

        let no_delete = server
            .mock(
                "DELETE",
                mockito::Matcher::Regex("/api/v2/resourceRecords/.*".into()),
            )
            .expect(0)
            .create();
        let no_deploy = server
            .mock("POST", "/api/v2/zones/42/deployments")
            .expect(0)
            .create();

        let provider = setup_with_deploy(server.url().as_str());
        let result = provider
            .set_rrset(
                "app.example.com",
                DnsRecordType::TXT,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        session.assert();
        zone.assert();
        list.assert();
        no_delete.assert();
        no_deploy.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_skips_duplicates() {
        let mut server = mockito::Server::new_async().await;
        let session = mock_session(&mut server);
        let zone = mock_zone(&mut server);

        let list = server
            .mock(
                "GET",
                mockito::Matcher::Regex("/api/v2/zones/42/resourceRecords\\?.*".into()),
            )
            .with_status(200)
            .with_body(
                r#"{"count":1,"totalCount":1,"data":[
                    {"id":11,"absoluteName":"app.example.com","recordType":"A","addresses":["1.1.1.1"]}
                ]}"#,
            )
            .create();

        let create = server
            .mock("POST", "/api/v2/zones/42/resourceRecords")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "addresses": ["2.2.2.2"],
            })))
            .with_status(201)
            .with_body(r#"{"id":12}"#)
            .expect(1)
            .create();

        let dup_post_guard = server
            .mock("POST", "/api/v2/zones/42/resourceRecords")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "addresses": ["1.1.1.1"],
            })))
            .expect(0)
            .create();

        let deploy = mock_deploy(&mut server);

        let provider = setup_with_deploy(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "app.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset failed: {result:?}");
        session.assert();
        zone.assert();
        list.assert();
        create.assert();
        dup_post_guard.assert();
        deploy.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_empty_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let no_session = server.mock("POST", "/api/v2/sessions").expect(0).create();

        let provider = setup_with_deploy(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "app.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset failed: {result:?}");
        no_session.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_matches_only() {
        let mut server = mockito::Server::new_async().await;
        let session = mock_session(&mut server);
        let zone = mock_zone(&mut server);

        let list = server
            .mock(
                "GET",
                mockito::Matcher::Regex("/api/v2/zones/42/resourceRecords\\?.*".into()),
            )
            .with_status(200)
            .with_body(
                r#"{"count":2,"totalCount":2,"data":[
                    {"id":11,"absoluteName":"app.example.com","recordType":"A","addresses":["1.1.1.1"]},
                    {"id":12,"absoluteName":"app.example.com","recordType":"A","addresses":["2.2.2.2"]}
                ]}"#,
            )
            .create();

        let delete_match = server
            .mock("DELETE", "/api/v2/resourceRecords/11")
            .with_status(204)
            .expect(1)
            .create();
        let no_other_delete = server
            .mock("DELETE", "/api/v2/resourceRecords/12")
            .expect(0)
            .create();

        let deploy = mock_deploy(&mut server);

        let provider = setup_with_deploy(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "app.example.com",
                DnsRecordType::A,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("3.3.3.3".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
        session.assert();
        zone.assert();
        list.assert();
        delete_match.assert();
        no_other_delete.assert();
        deploy.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let no_session = server.mock("POST", "/api/v2/sessions").expect(0).create();

        let provider = setup_with_deploy(server.url().as_str());
        let result = provider
            .remove_from_rrset("app.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
        no_session.assert();
    }

    #[tokio::test]
    async fn set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let session = mock_session(&mut server);
        let zone = mock_zone(&mut server);

        let list_a = server
            .mock("GET", "/api/v2/zones/42/resourceRecords")
            .match_query(mockito::Matcher::UrlEncoded(
                "filter".into(),
                "absoluteName:eq('shared.example.com') and recordType:eq('A')".into(),
            ))
            .with_status(200)
            .with_body(r#"{"count":0,"totalCount":0,"data":[]}"#)
            .expect(1)
            .create();

        let txt_list_guard = server
            .mock("GET", "/api/v2/zones/42/resourceRecords")
            .match_query(mockito::Matcher::UrlEncoded(
                "filter".into(),
                "absoluteName:eq('shared.example.com') and recordType:eq('TXT')".into(),
            ))
            .expect(0)
            .create();
        let txt_delete_guard = server
            .mock(
                "DELETE",
                mockito::Matcher::Regex("/api/v2/resourceRecords/.*".into()),
            )
            .expect(0)
            .create();

        let create = server
            .mock("POST", "/api/v2/zones/42/resourceRecords")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "type": "GenericRecord",
                "recordType": "A",
                "addresses": ["1.1.1.1"],
            })))
            .with_status(201)
            .with_body(r#"{"id":99}"#)
            .expect(1)
            .create();

        let deploy = mock_deploy(&mut server);

        let provider = setup_with_deploy(server.url().as_str());
        let result = provider
            .set_rrset(
                "shared.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        session.assert();
        zone.assert();
        list_a.assert();
        txt_list_guard.assert();
        txt_delete_guard.assert();
        create.assert();
        deploy.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_parsed_records() {
        let mut server = mockito::Server::new_async().await;
        let session = mock_session(&mut server);
        let zone = mock_zone(&mut server);

        let list = server
            .mock(
                "GET",
                mockito::Matcher::Regex("/api/v2/zones/42/resourceRecords\\?.*".into()),
            )
            .with_status(200)
            .with_body(
                r#"{"count":2,"totalCount":2,"data":[
                    {"id":11,"absoluteName":"app.example.com","recordType":"A","addresses":["1.1.1.1"]},
                    {"id":12,"absoluteName":"app.example.com","recordType":"A","addresses":["2.2.2.2"]}
                ]}"#,
            )
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .list_rrset("app.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
        session.assert();
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn set_rrset_rejects_type_mismatch() {
        let server = mockito::Server::new_async().await;
        let provider = setup(server.url().as_str());
        let result = provider
            .set_rrset(
                "app.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not an A".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(crate::Error::Api(_))));
    }

    #[tokio::test]
    async fn set_rrset_idempotent_skips_when_match() {
        let mut server = mockito::Server::new_async().await;
        let session = mock_session(&mut server);
        let zone = mock_zone(&mut server);

        let list = server
            .mock(
                "GET",
                mockito::Matcher::Regex("/api/v2/zones/42/resourceRecords\\?.*".into()),
            )
            .with_status(200)
            .with_body(
                r#"{"count":1,"totalCount":1,"data":[
                    {"id":11,"absoluteName":"app.example.com","recordType":"A","addresses":["1.1.1.1"]}
                ]}"#,
            )
            .create();

        let no_post = server
            .mock("POST", "/api/v2/zones/42/resourceRecords")
            .expect(0)
            .create();
        let no_delete = server
            .mock(
                "DELETE",
                mockito::Matcher::Regex("/api/v2/resourceRecords/.*".into()),
            )
            .expect(0)
            .create();
        let no_deploy = server
            .mock("POST", "/api/v2/zones/42/deployments")
            .expect(0)
            .create();

        let provider = setup_with_deploy(server.url().as_str());
        let result = provider
            .set_rrset(
                "app.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        session.assert();
        zone.assert();
        list.assert();
        no_post.assert();
        no_delete.assert();
        no_deploy.assert();
    }
}
