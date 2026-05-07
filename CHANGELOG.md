dns-update 0.2.8
================================
- Hetzner Cloud DNS provider support.

dns-update 0.2.7
================================
- OVH + Google Cloud DNS: Fixes FQDN handling for `MX` and `SRV` records.

dns-update 0.2.6
================================
- Route53: Fix serialization format (#44).

dns-update 0.2.5
================================
- BunnyDNS: Use subdomain as name of record instead of FQDN.
- RFC2136: Chunk TXT records.

dns-update 0.2.4
================================
- Google Cloud DNS: Chunk TXT records into 255-character strings when updating records.
- desec.io: Fixes + Verification

dns-update 0.2.3
================================
- Fix deSEC provider to include trailing dots on MX, SRV, CNAME and NS record values, as required by the API.
- Cloudflare: Check zone subdomains when finding zones (#39).

dns-update 0.2.2
================================
- Fix `CAA` record updates for Cloudflare provider.

dns-update 0.2.1
================================
- Fix deletion by record in RFC2136, Cloudflare and DigitalOcean providers
- Deprecation notice for `new_rfc2136_sig0` 

dns-update 0.2.0
================================
- Route53 provider support (contributed by @jimmystewpot) (#23)
- Google Cloud DNS provider support (contributed by @jimmystewpot) (#36)
- Bunny provider support (contributed by @angeloanan) (#24)
- Porkbun provider support (contributed by @jeffesquivels) (#31)
- DNSimple provider support (contributed by @NelsonVides) (#33)
- Spaceship provider support (contributed by @matserix) (#34)
- update `hickory_client` with feature flag for `ring` and `aws-lc-rs` (#29)

dns-update 0.1.6
================================
- deSec fixes.

dns-update 0.1.5
================================
- Add OVH provider.

dns-update 0.1.4
================================
- Add desec.io provider.
- Add retry function to http client
- Moved `strip_origin_from_name` form `digitalocean` to `lib`
- Fixed cargo test 

dns-update 0.1.3
================================
- Add DigitalOcean provider.

dns-update 0.1.2
================================
- Fixed parsing IPv6 addresses.

dns-update 0.1.1
================================
- Minor fixes.

dns-update 0.1.0
================================
- Initial release.
