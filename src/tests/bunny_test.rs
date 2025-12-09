#[cfg(test)]
mod tests {
    use crate::{providers::bunny::BunnyProvider, DnsRecord, DnsUpdater};
    use std::time::Duration;

    #[tokio::test]
    #[ignore = "Requires Bunny API keys and domain configuration"]
    async fn integration_test() {
        let api_key = std::env::var("BUNNY_API_KEY").unwrap_or_default();
        let domain = std::env::var("BUNNY_DOMAIN").unwrap_or_default();
        let origin = std::env::var("BUNNY_ORIGIN").unwrap_or_default();

        assert!(
            !api_key.is_empty(),
            "Please configure your Bunny application key in the integration test"
        );
        assert!(
            !domain.is_empty(),
            "Please configure your domain in the integration test"
        );
        assert!(
            !origin.is_empty(),
            "Please configure your origin in the integration test"
        );

        let updater = DnsUpdater::new_bunny(api_key, Some(Duration::from_secs(30))).unwrap();

        let create_result = updater
            .create(
                &domain,
                DnsRecord::A {
                    content: [1, 1, 1, 1].into(),
                },
                300,
                &origin,
            )
            .await;
        assert!(create_result.is_ok());

        let update_result = updater
            .update(
                &domain,
                DnsRecord::A {
                    content: [8, 8, 8, 8].into(),
                },
                300,
                &origin,
            )
            .await;
        assert!(update_result.is_ok());

        let delete_result = updater
            .delete(&domain, &origin, crate::DnsRecordType::A)
            .await;
        assert!(delete_result.is_ok());
    }

    #[test]
    fn provider_creation() {
        let provider = BunnyProvider::new("bunny-mock-api-key", Some(Duration::from_secs(1)));

        assert!(provider.is_ok());
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_bunny("bunny-mock-api-key", Some(Duration::from_secs(30)));

        assert!(
            matches!(updater, Ok(DnsUpdater::Bunny(..))),
            "Expected Bunny updater to provide a Bunny provider"
        );
    }
}
