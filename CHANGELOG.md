dns-update 0.5.5
================================
- INWX: resolve the managed DNS zone by walking up the origin labels instead of using the origin verbatim (#79).
- Spaceship: send the TLSA `port` as the underscore-prefixed string the API requires (`"_995"`) instead of a number, and match TLSA RRsets returned in that form (#81).

dns-update 0.5.4
================================
- Include body snippet in deserialization failure messages.
- deSEC: resolve the managed DNS zone by walking up the origin labels instead of using the origin verbatim (#72).
- DNSMadeEasy: send `gtdLocation: "DEFAULT"` on record creation to fix HTTP 500 errors when publishing records.
- Hetzner: add TLSA support and fix RRset write paths.
- ClouDNS: retry when the API signals rate limiting in the response body instead of via HTTP 429 (#78).
- OVH: add US OVH Endpoint.

dns-update 0.5.3
================================
- Namecheap: Corrected the behavior of the set_hosts command when adding a TXT record.
- Mythic Beasts: resolve the managed DNS zone by walking up the origin labels instead of using the origin verbatim (#70).

dns-update 0.5.2
================================
- Porkbun: fix `set_rrset` silently failing to publish a new single-record RRset (#67).
- Infomaniak: resolve the managed DNS zone by walking up the origin labels instead of using the origin verbatim (#66).
- Vultr: send long TXT values (DKIM keys >255 bytes) as a single quoted string instead of multiple quoted segments.

dns-update 0.5.1
================================
- TransIP: append a trailing dot to CNAME, NS, MX and SRV hostname targets.
- HTTP: retry on 503 in addition to 429, back off when no `Retry-After` is present, and cap the retry delay at 60s.
- deSEC: fix `set_rrset` returning "Not found" when creating a record that does not yet exist.
- INWX: accept record IDs returned as JSON strings.

dns-update 0.5.0
================================
- New RRSet-oriented API: `set_rrset`, `add_to_rrset`, `remove_from_rrset`. See `PROMPT.md` for per-provider migration plan.
- Infomaniak fixes (#57)
- Namecheap (#58): fix duplicate `Content-Type` header that IIS rejected as invalid.
- TransIP fixes (#59): shorten nonce to fit the API's 6-32 character limit, accept PKCS#1 (`BEGIN RSA PRIVATE KEY`) PEMs in addition to PKCS#8.
- TransIP: expose `global_key` parameter on `new_transip` so callers without an IP whitelist can mint global-scope tokens.
- RFC 2136: fix RRSET when publishing multiple records at the same owner (e.g. two TLSA).
- Netcup: SRV records now send `priority` in the dedicated field and `weight port target` in `destination` (fixes 4013 "destination of SRV entry is in wrong format").
- Hetzner: chunk long TXT values (DKIM keys >255 bytes) into multiple quoted segments.
- Cloudflare: chunk long TXT values (DKIM keys >255 bytes) into multiple quoted segments so wire chunk boundaries are predictable for propagation checks.
- HTTP: preserve response body in `Error::Api` for all non-success status codes.
- HTTP: add `HttpClient::set_header` (insert) alongside the existing `with_header` (append).

dns-update 0.4.1
================================
- Route53: chunk TXT records into 255-byte character-strings.
- DeSEC: Use `PATCH` instead of `POST` for create.

dns-update 0.4.0
================================
- Added 62 new DNS provider integrations:
   - Akamai Edge DNS
   - Alibaba Cloud DNS
   - ArvanCloud
   - AutoDNS
   - AWS Lightsail
   - Azure DNS
   - Baidu Cloud DNS
   - BlueCat Address Manager v2
   - ClouDNS
   - Constellix
   - cPanel
   - DDNSS.de
   - DNS Made Easy
   - Domeneshop
   - DreamHost
   - DuckDNS
   - Dynu
   - EasyDNS
   - Exoscale
   - FreeMyIP
   - Gandi v5
   - Gcore
   - GleSYS
   - GoDaddy
   - Hetzner DNS
   - hosting.de
   - Hostinger
   - Huawei Cloud DNS
   - Hurricane Electric
   - IBM Cloud (SoftLayer)
   - Infoblox NIOS
   - Infomaniak
   - INWX
   - IONOS
   - IPv64
   - Joker
   - Linode
   - LuaDNS
   - Mythic Beasts
   - Name.com
   - Namecheap
   - NameSilo
   - netcup
   - Netlify
   - Nifcloud
   - NS1
   - Oracle Cloud DNS
   - Plesk
   - SafeDNS
   - Scaleway
   - Tencent Cloud DNSPod
   - TransIP
   - UltraDNS
   - Vercel
   - Volcano Engine
   - Vultr
   - Websupport
   - Yandex Cloud DNS
- Removed legacy `X-Auth-*` Cloudflare authentication method.

dns-update 0.3.1
================================
- RFC2136 TSIG: Fix regression related to multiplexer.

dns-update 0.3.0
================================
- OVH + Google Cloud DNS: Fix FQDN handling for `MX` and `SRV` records.
- Route53: Fix changeset error resolution.
- deSEC: Use empty `subname` for apex records instead of `@`, which the API rejects.
- Cloudflare: Wrap `TXT` record content in double quotes (RFC 1035) to suppress dashboard warnings.

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
