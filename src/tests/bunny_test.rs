#[cfg(test)]
mod tests {
    use crate::{providers::bunny::BunnyProvider, DnsRecord, DnsUpdater};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider() -> BunnyProvider {
        BunnyProvider::new("bunny test api key", Some(Duration::from_secs(1))).unwrap()
    }

    #[tokio::test]
    // #[ignore = "Requires API keys and domain configuration"]
    async fn bunny_integration_test() {
        let updater = DnsUpdater::new_bunny(
            "9e5d80e4-1f25-4055-b1f0-512fe154a31067692e84-2f51-4b2d-9a95-38adb9e176a0",
            Some(Duration::from_secs(30)),
        )
        .unwrap();

        let create_result = updater
            .create(
                "testing",
                DnsRecord::A {
                    content: [1, 1, 1, 1].into(),
                },
                300,
                "angelo.fyi",
            )
            .await;
        assert!(create_result.is_ok());

        let update_result = updater
            .update(
                "testing",
                DnsRecord::A {
                    content: [8, 8, 8, 8].into(),
                },
                300,
                "angelo.fyi",
            )
            .await;
        assert!(update_result.is_ok());

        let delete_result = updater
            .delete("testing", "angelo.fyi", crate::DnsRecordType::A)
            .await;
        assert!(delete_result.is_ok());
    }

    #[test]
    fn test_bunny_provider_creation() {
        let provider = BunnyProvider::new("bunny test api key", Some(Duration::from_secs(1)));

        assert!(provider.is_ok());
    }

    #[test]
    fn test_dns_updater_bunny_creation() {
        let updater = DnsUpdater::new_bunny("bunny test api key", Some(Duration::from_secs(30)));

        assert!(updater.is_ok());

        match updater.unwrap() {
            DnsUpdater::Bunny(_) => (),
            _ => panic!("Expected Bunny provider"),
        }
    }
}
