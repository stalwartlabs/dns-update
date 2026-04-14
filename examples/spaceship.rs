use dns_update::{DnsRecord, DnsRecordType, DnsUpdater};
use std::{env, time::Duration};

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = env::var("SPACESHIP_API_KEY")
        .expect("SPACESHIP_API_KEY should be set with your Spaceship API key");
    let api_secret = env::var("SPACESHIP_API_SECRET")
        .expect("SPACESHIP_API_SECRET should be set with your Spaceship API secret");
    let origin = env::var("SPACESHIP_ORIGIN").unwrap_or_else(|_| "vmlux.com".to_string());
    let record_name =
        env::var("SPACESHIP_TEST_RECORD").unwrap_or_else(|_| "_dnsupdate-smoke".to_string());
    let fqdn = format!("{}.{}", record_name, origin);

    let client = DnsUpdater::new_spaceship(api_key, api_secret, Some(Duration::from_secs(30)))?;

    println!("Creating TXT record: {}", fqdn);
    client
        .create(&fqdn, DnsRecord::TXT("smoke-1".to_string()), 120, &origin)
        .await?;
    println!("Created");

    println!("Updating TXT record: {}", fqdn);
    client
        .update(&fqdn, DnsRecord::TXT("smoke-2".to_string()), 120, &origin)
        .await?;
    println!("Updated");

    println!("Deleting TXT record: {}", fqdn);
    client.delete(&fqdn, &origin, DnsRecordType::TXT).await?;
    println!("Deleted");

    Ok(())
}
