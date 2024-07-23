# dns-update

[![crates.io](https://img.shields.io/crates/v/dns-update)](https://crates.io/crates/dns-update)
[![build](https://github.com/stalwartlabs/dns-update/actions/workflows/rust.yml/badge.svg)](https://github.com/stalwartlabs/dns-update/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/dns-update)](https://docs.rs/dns-update)
[![crates.io](https://img.shields.io/crates/l/dns-update)](http://www.apache.org/licenses/LICENSE-2.0)

_dns-update_ is an **Dynamic DNS update library** for Rust that supports updating DNS records using the [RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136) protocol
and different cloud provider APIs such as [Cloudflare](https://www.cloudflare.com/). It was designed to be simple and easy to use, while providing a high level of flexibility
 and performance. 
 
## Limitations
 
- Currently the library is `async` only.
- Besides RFC 2136, it only supports Cloudflare's API. 

## PRs Welcome

PRs to add more providers are welcome. The goal is to support as many providers as Go's [lego](https://go-acme.github.io/lego/dns/) library.

## Usage Example

Using RFC2136 with TSIG:

```rust
        // Create a new RFC2136 client
        let client = Rfc2136Provider::new_tsig("tcp://127.0.0.1:53", "<KEY_NAME>", STANDARD.decode("<TSIG_KEY>").unwrap(), TsigAlgorithm::HmacSha512).unwrap();

        // Create a new TXT record
        client.create(
            "test._domainkey.example.org",
            DnsRecord::TXT {
                content: "v=DKIM1; k=rsa; h=sha256; p=test".to_string(),
            },
            300,
            "example.org",
        )
        .await
        .unwrap();

        // Delete the record
        client.delete("test._domainkey.example.org", "example.org").await.unwrap();
```

Using Cloudflare's API:

```rust
        // Create a new Cloudflare client
        let client =
            DnsUpdater::new_cloudflare("<API_TOKEN>", None::<String>, Some(Duration::from_secs(60)))
                .unwrap();

        // Create a new TXT record
        client.create(
            "test._domainkey.example.org",
            DnsRecord::TXT {
                content: "v=DKIM1; k=rsa; h=sha256; p=test".to_string(),
            },
            300,
            "example.org",
        )
        .await
        .unwrap();

        // Delete the record
        client.delete("test._domainkey.example.org", "example.org").await.unwrap();
```

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Copyright

Copyright (C) 2020-2024, Stalwart Labs Ltd.
