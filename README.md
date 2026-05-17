# dns-update

[![crates.io](https://img.shields.io/crates/v/dns-update)](https://crates.io/crates/dns-update)
[![build](https://github.com/stalwartlabs/dns-update/actions/workflows/rust.yml/badge.svg)](https://github.com/stalwartlabs/dns-update/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/dns-update)](https://docs.rs/dns-update)
[![crates.io](https://img.shields.io/crates/l/dns-update)](http://www.apache.org/licenses/LICENSE-2.0)

_dns-update_ is an **Dynamic DNS update library** for Rust that supports updating DNS records using the [RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136) protocol
and over 70 cloud, registrar, and self-hosted DNS provider APIs. It was designed to be simple and easy to use, while providing a high level of flexibility and performance.

## Supported providers

| Provider | Constructor | Notes |
|----------|-------------|-------|
| [RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136) | `new_rfc2136_tsig` | TSIG authentication |
| [Alibaba Cloud DNS](https://www.alibabacloud.com/product/dns) | `new_alidns` | ACS3-HMAC-SHA256 |
| [ArvanCloud](https://www.arvancloud.ir/) | `new_arvancloud` | |
| [AutoDNS](https://www.internetx.com/) | `new_autodns` | InterNetX |
| [Azure DNS](https://azure.microsoft.com/services/dns/) | `new_azuredns` | OAuth2 client credentials |
| [Baidu Cloud DNS](https://cloud.baidu.com/product/dns) | `new_baiducloud` | BCE-Auth-V1 |
| [Bindman](https://github.com/labbsr0x/bindman-dns-webhook) | `new_bindman` | BIND webhook |
| [BlueCat Address Manager v2](https://www.bluecatnetworks.com/) | `new_bluecatv2` | OAuth |
| [Bunny DNS](https://bunny.net/dns/) | `new_bunny` | |
| [Cloudflare](https://www.cloudflare.com/) | `new_cloudflare` | API token or X-Auth-* |
| [ClouDNS](https://www.cloudns.net/) | `new_cloudns` | |
| [Constellix](https://constellix.com/) | `new_constellix` | HMAC-SHA1 |
| [cPanel](https://cpanel.net/) | `new_cpanel` | UAPI, API token |
| [DDNSS.de](https://ddnss.de/) | `new_ddnss` | TXT only |
| [deSEC](https://desec.io/) | `new_desec` | |
| [DigitalOcean](https://www.digitalocean.com/products/networking/dns) | `new_digitalocean` | |
| [DNSimple](https://dnsimple.com/) | `new_dnsimple` | |
| [DNS Made Easy](https://dnsmadeeasy.com/) | `new_dnsmadeeasy` | HMAC-SHA1 |
| [Domeneshop](https://domene.shop/) | `new_domeneshop` | |
| [DreamHost](https://www.dreamhost.com/) | `new_dreamhost` | |
| [DuckDNS](https://www.duckdns.org/) | `new_duckdns` | TXT only |
| [Dynu](https://www.dynu.com/) | `new_dynu` | |
| [EasyDNS](https://www.easydns.com/) | `new_easydns` | |
| [Akamai Edge DNS](https://www.akamai.com/products/edge-dns) | `new_edgedns` | EG1-HMAC-SHA256 |
| [Exoscale](https://www.exoscale.com/) | `new_exoscale` | EXO2-HMAC-SHA256 |
| [FreeMyIP](https://freemyip.com/) | `new_freemyip` | TXT only |
| [Gandi v5](https://www.gandi.net/) | `new_gandiv5` | LiveDNS |
| [Gcore](https://gcore.com/dns) | `new_gcore` | |
| [GleSYS](https://glesys.com/) | `new_glesys` | |
| [GoDaddy](https://www.godaddy.com/) | `new_godaddy` | |
| [Google Cloud DNS](https://cloud.google.com/dns) | `new_google_cloud_dns` | Service account JWT |
| [Hetzner DNS](https://www.hetzner.com/dns-console) | `new_hetzner` | |
| [hosting.de](https://www.hosting.de/) | `new_hostingde` | |
| [Hostinger](https://www.hostinger.com/) | `new_hostinger` | |
| [Huawei Cloud DNS](https://www.huaweicloud.com/) | `new_huaweicloud` | SDK-HMAC-SHA256 |
| [Hurricane Electric](https://dns.he.net/) | `new_hurricane` | TXT only |
| [IBM Cloud (SoftLayer)](https://www.ibm.com/cloud/) | `new_ibmcloud` | Classic Infrastructure |
| [Infoblox NIOS](https://www.infoblox.com/) | `new_infoblox` | WAPI |
| [Infomaniak](https://www.infomaniak.com/) | `new_infomaniak` | |
| [INWX](https://www.inwx.com/) | `new_inwx` | JSON-RPC |
| [IONOS](https://www.ionos.com/) | `new_ionos` | |
| [IPv64](https://ipv64.net/) | `new_ipv64` | TXT only |
| [Joker](https://joker.com/) | `new_joker_api_key` / `new_joker_password` | DMAPI |
| [AWS Lightsail](https://aws.amazon.com/lightsail/) | `new_lightsail` | AWS Sigv4 |
| [Linode](https://www.linode.com/) | `new_linode` | |
| [LuaDNS](https://www.luadns.com/) | `new_luadns` | |
| [Mail-in-a-Box](https://mailinabox.email/) | `new_mailinabox` | |
| [Mythic Beasts](https://www.mythic-beasts.com/) | `new_mythicbeasts` | OAuth2 |
| [Namecheap](https://www.namecheap.com/) | `new_namecheap` | XML API |
| [Name.com](https://www.name.com/) | `new_namedotcom` | |
| [NameSilo](https://www.namesilo.com/) | `new_namesilo` | XML API |
| [netcup](https://www.netcup.com/) | `new_netcup` | JSON-RPC, session cache |
| [Netlify](https://www.netlify.com/) | `new_netlify` | |
| [Nifcloud](https://pfs.nifcloud.com/) | `new_nifcloud` | NIFTY3-HTTPS |
| [NS1](https://ns1.com/) | `new_ns1` | |
| [Oracle Cloud DNS](https://www.oracle.com/cloud/networking/dns/) | `new_oraclecloud` | RSA-SHA256 HTTP Signatures |
| [OVH](https://www.ovh.com/) | `new_ovh` | |
| [PowerDNS](https://www.powerdns.com/) | `new_pdns` | |
| [Plesk](https://www.plesk.com/) | `new_plesk` | REST API, X-API-Key |
| [Porkbun](https://porkbun.com/) | `new_porkbun` | |
| [AWS Route 53](https://aws.amazon.com/route53/) | `new_route53` | AWS Sigv4 |
| [ANS SafeDNS](https://www.ans.co.uk/) | `new_safedns` | |
| [Scaleway](https://www.scaleway.com/) | `new_scaleway` | |
| [Spaceship](https://www.spaceship.com/) | `new_spaceship` | |
| [Technitium DNS Server](https://technitium.com/dns/) | `new_technitium` | |
| [Tencent Cloud DNSPod](https://cloud.tencent.com/product/dns) | `new_tencentcloud` | TC3-HMAC-SHA256 |
| [TransIP](https://www.transip.eu/) | `new_transip` | RSA-SHA512 JWT |
| [UltraDNS](https://vercara.com/authoritative-dns) | `new_ultradns` | OAuth2 |
| [Vercel](https://vercel.com/) | `new_vercel` | |
| [Volcano Engine](https://www.volcengine.com/) | `new_volcengine` | HMAC-SHA256 |
| [Vultr](https://www.vultr.com/) | `new_vultr` | |
| [Websupport](https://www.websupport.sk/) | `new_websupport` | HMAC-SHA1 |
| [Yandex Cloud DNS](https://cloud.yandex.com/services/dns) | `new_yandexcloud` | PS256 JWT |

## Usage Example

Using RFC2136 with TSIG:

```rust,ignore
        // Create a new RFC2136 client
        let client = DnsUpdater::new_rfc2136_tsig("tcp://127.0.0.1:53", "<KEY_NAME>", STANDARD.decode("<TSIG_KEY>").unwrap(), TsigAlgorithm::HmacSha512).unwrap();

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

Using a cloud provider such as Cloudflare:

```rust,ignore
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

Copyright (C) 2020, Stalwart Labs LLC
