use dns_update::{DnsRecord, DnsRecordType, DnsUpdater};
use std::env;
use std::time::Duration;

#[tokio::main]
pub async fn main() -> Result<(), std::env::VarError> {
    let token = env::var("DESEC_TOKEN").expect("Envvar DESEC_TOKEN should be set with valid token");
    let domain =
        env::var("DESEC_DOMAIN").expect("Envvar DESEC_DOMAIN should be set with DNS domain");

    let client = DnsUpdater::new_desec(token, Some(Duration::from_secs(120))).unwrap();

    // Create a new TXT record

    let client_result = client
        .create(
            format!("_domainkey.{}", domain),
            DnsRecord::TXT {
                content: "\"v=DKIM1; k=rsa; h=sha256; p=test\"".to_string(),
            },
            3600,
            format!("{}", domain),
        )
        .await;

    println!("client create result={:?}", client_result);

    let client_del_result = client
        .delete("_domainkey", format!("{}", domain), DnsRecordType::TXT)
        .await;

    println!("client del result={:?}", client_del_result);

    Ok(())
}
