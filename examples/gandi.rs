use dns_update::{DnsRecord, DnsRecordType, DnsUpdater};
use std::env;
use std::time::Duration;

#[tokio::main]
pub async fn main() -> Result<(), std::env::VarError> {
    let token = env::var("GANDIV5_PERSONAL_ACCESS_TOKEN")
        .expect("Envvar GANDIV5_PERSONAL_ACCESS_TOKEN should be set with valid token");
    let domain =
        env::var("GANDIV5_DOMAIN").expect("Envvar GANDIV5_DOMAIN should be set with DNS domain");

    let client = DnsUpdater::new_gandi(token, Some(Duration::from_secs(120))).unwrap();

    // Create a new TXT record

    let client_result = client
        .create(
            format!("dns-update-example.{}", domain),
            DnsRecord::TXT("\"test dns-update record\"".to_string()),
            3600,
            &domain,
        )
        .await;

    println!("client create result={:?}", client_result);

    let client_del_result = client
        .delete("dns-update-example", &domain, DnsRecordType::TXT)
        .await;

    println!("client del result={:?}", client_del_result);

    Ok(())
}
