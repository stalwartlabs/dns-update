# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](https://semver.org/).

## [0.5.10] - 2026-09-XX

### Changed
- Replaced `base64` with `encodify`.

## [0.5.9] - 2026-09-26

### Added
- PowerDNS authoritative API support.

### Changed
- Replaced `chrono` with `jiff`.

## [0.5.8] - 2026-09-11

### Fixed
- Scaleway: append a trailing dot to CNAME, NS, MX and SRV hostname targets.

## [0.5.7] - 2026-09-04

### Changed
- Update `quick-xml` to 0.42.

### Fixed
- Exoscale: fix HTTP 403 "Invalid request signature" on every API call by signing the request body.

## [0.5.6] - 2026-08-08

### Added
- Simply.com support.

### Fixed
- Plesk: identify the zone with the `domain` query parameter the REST API requires instead of a `site_id` field.
- NameSilo: clamp the TTL to the range the API accepts and strip the trailing dot from records.

## [0.5.5] - 2026-08-02

### Fixed
- INWX: resolve the managed DNS zone by walking up the origin labels instead of using the origin verbatim (#79).
- Spaceship: send the TLSA `port` as the underscore-prefixed string the API requires (`"_995"`) instead of a number, and match TLSA RRsets returned in that form (#81).
- NameSilo: drop the default `Content-Type: application/json` request header, which made the API ignore `type=xml` and answer with JSON.

## [0.5.4] - 2026-07-12

### Added
- OVH: add US OVH Endpoint.
- Hetzner: add TLSA support.

### Changed
- Include body snippet in deserialization failure messages.

### Fixed
- deSEC: resolve the managed DNS zone by walking up the origin labels instead of using the origin verbatim (#72).
- DNSMadeEasy: send `gtdLocation: "DEFAULT"` on record creation to fix HTTP 500 errors when publishing records.
- Hetzner: fix RRset write paths.
- ClouDNS: retry when the API signals rate limiting in the response body instead of via HTTP 429 (#78).

## [0.5.3] - 2026-06-19

### Fixed
- Namecheap: corrected the behavior of the set_hosts command when adding a TXT record.
- Mythic Beasts: resolve the managed DNS zone by walking up the origin labels instead of using the origin verbatim (#70).

## [0.5.2] - 2026-06-15

### Fixed
- Porkbun: fix `set_rrset` silently failing to publish a new single-record RRset (#67).
- Infomaniak: resolve the managed DNS zone by walking up the origin labels instead of using the origin verbatim (#66).
- Vultr: send long TXT values (DKIM keys >255 bytes) as a single quoted string instead of multiple quoted segments.

## [0.5.1] - 2026-06-06

### Changed
- HTTP: retry on 503 in addition to 429, back off when no `Retry-After` is present, and cap the retry delay at 60s.

### Fixed
- TransIP: append a trailing dot to CNAME, NS, MX and SRV hostname targets.
- deSEC: fix `set_rrset` returning "Not found" when creating a record that does not yet exist.
- INWX: accept record IDs returned as JSON strings.

## [0.5.0] - 2026-05-28

### Added
- New RRSet-oriented API: `set_rrset`, `add_to_rrset`, `remove_from_rrset`. See `PROMPT.md` for per-provider migration plan.
- TransIP: expose `global_key` parameter on `new_transip` so callers without an IP whitelist can mint global-scope tokens.
- HTTP: add `HttpClient::set_header` (insert) alongside the existing `with_header` (append).

### Changed
- Hetzner: chunk long TXT values (DKIM keys >255 bytes) into multiple quoted segments.
- Cloudflare: chunk long TXT values (DKIM keys >255 bytes) into multiple quoted segments so wire chunk boundaries are predictable for propagation checks.
- HTTP: preserve response body in `Error::Api` for all non-success status codes.

### Fixed
- Infomaniak fixes (#57).
- Namecheap (#58): fix duplicate `Content-Type` header that IIS rejected as invalid.
- TransIP fixes (#59): shorten nonce to fit the API's 6-32 character limit, accept PKCS#1 (`BEGIN RSA PRIVATE KEY`) PEMs in addition to PKCS#8.
- RFC 2136: fix RRSET when publishing multiple records at the same owner (e.g. two TLSA).
- Netcup: SRV records now send `priority` in the dedicated field and `weight port target` in `destination` (fixes 4013 "destination of SRV entry is in wrong format").

## [0.4.1] - 2026-05-20

### Changed
- Route53: chunk TXT records into 255-byte character-strings.
- DeSEC: use `PATCH` instead of `POST` for create.

## [0.4.0] - 2026-05-18

### Added
- 62 new DNS provider integrations: Akamai Edge DNS, Alibaba Cloud DNS, ArvanCloud, AutoDNS, AWS Lightsail, Azure DNS, Baidu Cloud DNS, BlueCat Address Manager v2, ClouDNS, Constellix, cPanel, DDNSS.de, DNS Made Easy, Domeneshop, DreamHost, DuckDNS, Dynu, EasyDNS, Exoscale, FreeMyIP, Gandi v5, Gcore, GleSYS, GoDaddy, Hetzner DNS, hosting.de, Hostinger, Huawei Cloud DNS, Hurricane Electric, IBM Cloud (SoftLayer), Infoblox NIOS, Infomaniak, INWX, IONOS, IPv64, Joker, Linode, LuaDNS, Mythic Beasts, Name.com, Namecheap, NameSilo, netcup, Netlify, Nifcloud, NS1, Oracle Cloud DNS, Plesk, SafeDNS, Scaleway, Tencent Cloud DNSPod, TransIP, UltraDNS, Vercel, Volcano Engine, Vultr, Websupport, Yandex Cloud DNS.

### Removed
- Legacy `X-Auth-*` Cloudflare authentication method.

## [0.3.1] - 2026-05-12

### Fixed
- RFC2136 TSIG: fix regression related to multiplexer.

## [0.3.0] - 2026-05-11

### Fixed
- OVH + Google Cloud DNS: fix FQDN handling for `MX` and `SRV` records.
- Route53: fix changeset error resolution.
- deSEC: use empty `subname` for apex records instead of `@`, which the API rejects.
- Cloudflare: wrap `TXT` record content in double quotes (RFC 1035) to suppress dashboard warnings.

## [0.2.6] - 2026-04-30

### Fixed
- Route53: fix serialization format (#44).

## [0.2.5] - 2026-04-28

### Changed
- BunnyDNS: use subdomain as name of record instead of FQDN.

### Fixed
- RFC2136: chunk TXT records.

## [0.2.4] - 2026-04-23

### Changed
- Google Cloud DNS: chunk TXT records into 255-character strings when updating records.

### Fixed
- desec.io: fixes and verification.

## [0.2.3] - 2026-04-22

### Fixed
- deSEC: include trailing dots on MX, SRV, CNAME and NS record values, as required by the API.
- Cloudflare: check zone subdomains when finding zones (#39).

## [0.2.2] - 2026-04-21

### Fixed
- `CAA` record updates for Cloudflare provider.

## [0.2.1] - 2026-04-19

### Fixed
- Deletion by record in RFC2136, Cloudflare and DigitalOcean providers.

### Deprecated
- `new_rfc2136_sig0`.

## [0.2.0] - 2026-04-17

### Added
- Route53 provider support (contributed by @jimmystewpot) (#23).
- Google Cloud DNS provider support (contributed by @jimmystewpot) (#36).
- Bunny provider support (contributed by @angeloanan) (#24).
- Porkbun provider support (contributed by @jeffesquivels) (#31).
- DNSimple provider support (contributed by @NelsonVides) (#33).
- Spaceship provider support (contributed by @matserix) (#34).

### Changed
- Update `hickory_client` with feature flag for `ring` and `aws-lc-rs` (#29).

## [0.1.6] - 2025-10-31

### Fixed
- deSec fixes.

## [0.1.5] - 2025-07-27

### Added
- OVH provider.

## [0.1.4] - 2025-07-27

### Added
- desec.io provider.
- Retry function to http client.

### Changed
- Moved `strip_origin_from_name` from `digitalocean` to `lib`.

### Fixed
- Cargo test.

## [0.1.3] - 2025-07-16

### Added
- DigitalOcean provider.

## [0.1.2] - 2024-04-18

### Fixed
- Parsing IPv6 addresses.

## [0.1.1] - 2024-04-17

### Fixed
- Minor fixes.

## [0.1.0] - 2024-04-16

### Added
- Initial release.
