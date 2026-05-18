# CLAUDE.md

Notes for Claude (and future contributors) working on `dns-update`.

## What this crate is

`dns-update` is an async Rust library for dynamic DNS updates. It exposes a
single enum `DnsUpdater` that fronts many backend providers behind a uniform
`create` / `update` / `delete` API for record types `A`, `AAAA`, `CNAME`, `NS`,
`MX`, `TXT`, `SRV`, `TLSA`, `CAA`. It targets RFC 2136 (with TSIG) and a
growing list of cloud / registrar DNS APIs. The stated goal in `README.md` is
to eventually cover as many providers as Go's
[lego](https://go-acme.github.io/lego/dns/) library.

## Layout

- `src/lib.rs`: public surface. Defines `Error`, `DnsRecord*`, `CAARecord`,
  `MXRecord`, `SRVRecord`, `TLSARecord`, `KeyValue`, `TsigAlgorithm`,
  `Algorithm`, `IntoFqdn`, and the `DnsUpdater` enum that dispatches to a
  provider.
- `src/update.rs`: the `impl DnsUpdater` factories (`new_*`) and the
  `create` / `update` / `delete` match arms that fan out to each provider.
- `src/providers/`: one file per provider. Each file is self-contained and
  exposes a `pub struct <Name>Provider` plus `pub(crate) async fn new`,
  `create`, `update`, `delete` methods called from `update.rs`.
- `src/tests/`: one `*_tests.rs` file per provider, registered in
  `src/tests/mod.rs`.
- `src/http.rs`: shared `HttpClientBuilder` / `HttpClient` over `reqwest`.
  Handles JSON bodies, retries on 429 with `retry-after`, maps statuses to
  `Error::Unauthorized` / `Error::NotFound` / `Error::BadRequest` /
  `Error::Api`.
- `src/utils.rs`: `strip_origin_from_name`, `txt_chunks*`, `IntoFqdn` impls,
  `Display` for record types, helpers like `CAARecord::decompose`. Reuse
  these.
- `src/crypto.rs`, `src/jwt.rs`: HMAC, SHA, RSA-via-`ring`/`aws-lc-rs`, and
  Google-style JWT helpers (used by route53, ovh, google_cloud_dns).
- `src/bind.rs`: BIND zone-file rendering. Not a provider.

## Adding a new provider (the recipe)

For a vanilla token-based REST provider, follow `digitalocean.rs` or
`desec.rs` as the template. Steps:

1. Create `src/providers/<name>.rs` defining:
   - `#[derive(Clone)] pub struct <Name>Provider { client: HttpClientBuilder, ... }`
   - `pub(crate) fn new(...) -> crate::Result<Self>` (or `-> Self` if no
     fallible setup). Inject auth headers via
     `HttpClientBuilder::default().with_header(...).with_timeout(timeout)`.
   - `pub(crate) async fn create / update / delete` with the same signatures
     used elsewhere:
     ```rust
     async fn create(&self, name: impl IntoFqdn<'_>, record: DnsRecord, ttl: u32, origin: impl IntoFqdn<'_>) -> crate::Result<()>
     async fn update(&self, name: impl IntoFqdn<'_>, record: DnsRecord, ttl: u32, origin: impl IntoFqdn<'_>) -> crate::Result<()>
     async fn delete(&self, name: impl IntoFqdn<'_>, origin: impl IntoFqdn<'_>, record_type: DnsRecordType) -> crate::Result<()>
     ```
   - A test-only `with_endpoint` setter (gated `#[cfg(test)]`) so mockito can
     point the provider at a local URL.
2. Register it in `src/providers/mod.rs` (`pub mod <name>;`).
3. Wire it into `src/lib.rs`: add a variant on `DnsUpdater` and import the
   provider type.
4. Wire it into `src/update.rs`:
   - Add a `new_<name>(...)` constructor.
   - Add match arms in `create` / `update` / `delete`.
5. Write `src/tests/<name>_tests.rs` and register the module in
   `src/tests/mod.rs`. Use `mockito::Server::new_async()` for unit tests; the
   existing `cloudflare_tests.rs` is the canonical example. Also include a
   `#[ignore = "..."]` integration test that hits the real API behind env
   vars, again like cloudflare.

### Conventions

- **No comments in source code.** Identifiers carry the *what*; rationale
  belongs in commit / PR messages.
- **Never use em dashes (`—`).** Use `:`, `;`, parens, comma, or sentence
  breaks.
- **Naming**: subdomain vs name vs fqdn distinction matters. Use
  `name.into_name()` and `origin.into_name()` from `IntoFqdn`. To get the
  bare subdomain relative to a zone use
  `utils::strip_origin_from_name(name, origin, Some(""))` (or `None` for the
  `@` default).
- **Zone discovery**: when the API exposes zones by name, walk up the
  origin one label at a time until a zone matches (see Cloudflare's
  `obtain_zone_id`). For providers that always require an explicit zone,
  trust the caller's `origin`.
- **Record-ID resolution**: providers that need an ID for update / delete
  usually do a list-records lookup filtered by name + type. Reuse the
  Cloudflare and DigitalOcean patterns. For update specifically, resolve
  the record ID before issuing PATCH / PUT (see issue #52 / commit 707b82c).
- **TXT quoting / chunking**: some APIs want raw text, others want quoted
  with `\"`-escaping, others want chunks of <=255 bytes. Reuse
  `utils::txt_chunks_to_text` / `utils::txt_chunks`. Be deliberate about
  which form you send; check the provider's docs and look at lego's
  `presentRecord` for a hint.
- **CAA**: convert via `CAARecord::decompose()` to `(flags, tag, value)`.
  Many APIs accept that flat form; others want the BIND-style string given
  by `CAARecord::Display`.
- **TLSA**: `TLSARecord::Display` produces `"<usage> <selector> <matching>
  <hex>"`. Many providers can take that directly. Some don't support TLSA at
  all: return `Error::Api("TLSA records are not supported by ...")` (see
  `digitalocean.rs`'s `TryFrom<DnsRecord> for RecordData`).
- **Errors**: don't invent new error variants for one provider; use the
  existing `Error::{Api, Unauthorized, NotFound, BadRequest, Parse,
  Serialize, Client, Response, Protocol}`. API-level failure messages go
  into `Error::Api(_)`.
- **No new dependencies** unless you've checked with the maintainer. Most
  things we need (HTTP, JSON, urlencoded form bodies, base64, hex, HMAC,
  SHA, RSA, XML) are already in `Cargo.toml`. `quick-xml` is available for
  XML APIs (used by Route53).
- **Crypto**: use `ring` (feature `ring`) or `aws-lc-rs` (default). The
  cfg pattern is shown at the top of `src/jwt.rs`. Providers requiring
  crypto must gate themselves on `#[cfg(any(feature = "ring", feature =
  "aws-lc-rs"))]` the way `OvhProvider` does.

### What the public API looks like for the user

```rust
let updater = DnsUpdater::new_cloudflare(token, None::<&str>, Some(Duration::from_secs(30)))?;
updater.create("test._domainkey.example.org", DnsRecord::TXT("v=DKIM1; ...".into()), 300, "example.org").await?;
updater.update(..., DnsRecord::A(addr), ttl, origin).await?;
updater.delete(name, origin, DnsRecordType::TXT).await?;
```

## Helpers reference (reuse, do not reinvent)

Before writing anything in a new provider, check this list. If the same shape
exists here, use it.

### `src/http.rs`

The default HTTP layer. `HttpClientBuilder` is `Clone`able; build one in
`Provider::new` with the right auth headers and timeout, store it on the
provider struct, and call `.get(url) / .post(url) / .put(url) / .patch(url)
/ .delete(url)` to get an `HttpClient` per request.

- `HttpClientBuilder::default()`: starts with `Content-Type: application/json`.
- `.with_header(name: &'static str, value: impl AsRef<str>)`: chainable, repeatable.
- `.with_timeout(Option<Duration>)`: chainable.
- `HttpClient::with_header(...)`: per-request override.
- `HttpClient::with_body(B: Serialize)`: JSON-serialize the body. Returns `crate::Result<HttpClient>`.
- `HttpClient::with_raw_body(String)`: pre-rendered body (XML, form-encoded, etc).
- `HttpClient::send_raw() -> crate::Result<String>`: discards JSON parsing.
- `HttpClient::send<T: DeserializeOwned>() -> crate::Result<T>`.
- `HttpClient::send_with_retry<T>(max_retries: u32)`: retries on `429` honoring
  `Retry-After`, otherwise identical to `send`. Use this by default.

Status mapping (do not re-implement): `204` -> empty `{}` JSON, `2xx` -> body,
`400` -> `Error::Api("BadRequest ...")`, `401` -> `Error::Unauthorized`,
`404` -> `Error::NotFound`, other -> `Error::Api(...)`.

If you need form-encoded bodies use `serde_urlencoded::to_string(...)` and
`HttpClient::with_raw_body(...)` together (override the content-type header
on the builder or per-request via `.with_header`). If you need XML bodies use
`quick_xml::se::to_string(...)` plus `with_raw_body`.

### `src/utils.rs`

- `strip_origin_from_name(name, origin, return_if_equal: Option<&str>) -> String`:
  returns the bare subdomain. If `name == origin`, returns `return_if_equal`
  or `"@"` when `None`. Trailing dots are stripped.
- `txt_chunks_to_text(out: &mut String, text: &str, separator: &str)`:
  produces `"chunk1" "chunk2"` 255-byte-wise quoted+escaped TXT content.
- `txt_chunks(content: String) -> Vec<String>`: raw 255-byte chunks, no
  quoting.

Already-impl'd `Display` impls (use `format!("{}", record)` instead of
hand-rolling):

- `DnsRecord` (dispatches per variant).
- `DnsRecordType` -> `"A"`, `"AAAA"`, `"CNAME"`, ... Use `DnsRecordType::as_str()`
  for `&'static str` (avoids allocation in URL building).
- `MXRecord` -> `"<priority> <exchange>"`.
- `SRVRecord` -> `"<priority> <weight> <port> <target>"`.
- `TLSARecord` -> `"<usage> <selector> <matching> <hexcertdata>"`.
- `CAARecord` -> BIND-style `0 issue "letsencrypt.org"` (with options
  appended as `;key=value`).
- `KeyValue` -> `"key=value"` (or just `"key"` if value is empty).
- `Error` (implements `std::error::Error`).

Conversions:

- `DnsRecord::as_type() -> DnsRecordType`.
- `DnsRecord::priority() -> Option<u16>` (only MX / SRV; defined in
  `src/providers/mod.rs`).
- `CAARecord::decompose() -> (u8 flags, String tag, String value)`: the most
  common form APIs want for CAA. Prefer this over the `Display` impl when
  the API expects separate fields.
- `u8::from(TlsaCertUsage / TlsaSelector / TlsaMatching)`: numeric wire form.
- `IntoFqdn::into_fqdn(self) -> Cow<str>`: adds trailing `.`.
- `IntoFqdn::into_name(self) -> Cow<str>`: strips trailing `.`. Impls cover
  `&str`, `&String`, `String`.

### `src/crypto.rs`

Feature-gated to use `aws-lc-rs` (default) or `ring`:

- `sha1_digest(&[u8]) -> Vec<u8>`.
- `sha256_digest(&[u8]) -> Vec<u8>`.
- `hmac_sha256(key, data) -> Vec<u8>`.

If you need HMAC-SHA1 (websupport, dnsmadeeasy, constellix), add an
`hmac_sha1` helper here (single function); do not duplicate the cfg dance
across providers.

### `src/jwt.rs`

For providers that use OAuth2 JWT-bearer grants (Google, and any provider
that signs a JWT with a service-account private key to swap for an access
token, e.g. yandexcloud):

- `ServiceAccount { client_email, private_key, token_uri }` (`Deserialize`).
- `create_jwt(&ServiceAccount, scopes: &str) -> Result<String, ...>`: RS256
  signed JWT.
- `exchange_jwt_for_token(token_uri, jwt) -> Result<String, ...>`: standard
  `urn:ietf:params:oauth:grant-type:jwt-bearer` exchange. Returns the
  `access_token`.

If you need a non-Google JWT (different claims structure, e.g. yandexcloud
PS256 with custom `aud`), generalize this file rather than copying. Plain
RSA signing primitives are exposed by `ring` / `aws-lc-rs` directly.

### Provider patterns to copy verbatim

- **AWS-Sigv4 family** (any provider whose docs say "HMAC-SHA256",
  canonical request, signed headers, scoped derivation): `route53.rs`'s
  `send_signed_request` + `get_signature_key` is the template. Swap the
  `algorithm` constant, the service name, the canonical-headers list, and
  any region scoping format. Aliyun ACS3-HMAC-SHA256, Tencent
  TC3-HMAC-SHA256, Huawei SDK-HMAC-SHA256, Baidu BCE, and Volcengine all
  fit.
- **Bearer + zone-walk by suffix** (provider gives a zone-by-name endpoint,
  the user supplies a subdomain or apex): `cloudflare.rs`'s
  `obtain_zone_id` loop.
- **List + find by name+type for update/delete**: `cloudflare.rs`'s
  `obtain_record_id` and `digitalocean.rs`'s `obtain_record_id` are the
  two patterns (one walks all records with a name filter, one filters
  server-side). Pick whichever the API supports.
- **OAuth2 client_credentials -> Bearer** (azuredns, ibmcloud): write a
  tiny `ensure_token` method on the provider; cache the token + expiry in
  `Arc<Mutex<Option<(String, Instant)>>>` exactly like
  `google_cloud_dns.rs` does. Don't paginate / sign / retry yourself; just
  POST the form body via `HttpClient::with_raw_body(...)`.

### `src/bind.rs`

`BindSerializer::serialize(&[NamedDnsRecord]) -> String` renders zone-file
text. Not needed for cloud providers, but if you implement one that
accepts a BIND zone-file as input, reuse this rather than building strings
inline.

### What `Cargo.toml` already gives you

Anything in this list is fair game; pulling in a new crate is not. Each
crate is feature-flagged where relevant.

- `tokio` (`rt`, `net`, plus `full` in dev).
- `hickory-net`, `hickory-proto` (DNS protocol).
- `reqwest` (with `http2`, `gzip`, `deflate`, `json`).
- `serde`, `serde_json`, `serde_urlencoded`.
- `quick-xml` (XML serde for Route53; also use for SOAP-ish APIs).
- `base64`, `hex`.
- `chrono` (with `std`, `clock`, `now`) for date formatting and timestamps.
- `ring` / `aws-lc-rs` (feature-gated): SHA1/SHA256/SHA512, HMAC, RSA, ECDSA.
- `rustls` (feature-gated): TLS plumbing if you need a custom config.
- Dev-only: `mockito` (preferred for new tests), `httpmock`.

If you find yourself wanting `chrono::DateTime<Utc>::now()` for HTTP signing,
look at how Route53 already does it before writing your own helper.

## Testing

- Run all tests: `cargo test`. Tests that hit live APIs are gated behind
  `#[ignore = "..."]` and require env vars; CI runs only the mocked tests.
- The default crate feature is `aws-lc-rs`. To exercise the alternative
  crypto stack: `cargo test --no-default-features --features ring`.
- The `test_provider` feature unlocks `InMemoryProvider` and `PebbleProvider`
  for downstream consumers writing their own tests.

## Misc

- `examples/` has small `main.rs` programs that exercise the public API.
- License: dual Apache-2.0 / MIT. New files keep the existing header.
