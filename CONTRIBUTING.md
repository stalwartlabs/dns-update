# Contributing to dns-update

Thanks for your interest in improving dns-update. This page gets you from a fresh clone to a pull request.

## Getting set up

You need a stable Rust toolchain, installed with [rustup](https://rustup.rs/). Then:

```sh
git clone https://github.com/stalwartlabs/dns-update.git
cd dns-update
cargo build
cargo test
```

`cargo test` runs the mocked unit tests for every provider; it needs no network access or credentials. The crate builds with `aws-lc-rs` by default. To check the `ring` backend as well:

```sh
cargo test --no-default-features --features ring
```

Each provider also has a live test marked `#[ignore]` that talks to the real API. It reads its credentials from environment variables named in the `#[ignore = "..."]` reason. Run one with:

```sh
cargo test <test_name> -- --ignored
```

Before opening a pull request, make sure these pass:

```sh
cargo fmt --check
cargo clippy --all-targets
cargo test
```

## Where things live

- `src/lib.rs`: the public types (`DnsUpdater`, `DnsRecord`, `DnsRecordType`, `Error`, ...).
- `src/update.rs`: the `DnsUpdater::new_*` constructors and the `set_rrset`, `add_to_rrset`, `remove_from_rrset` and `list_rrset` methods that dispatch to each provider. Their doc comments define the expected semantics.
- `src/providers/`: one file per provider.
- `src/tests/`: one `<provider>_tests.rs` file per provider, registered in `src/tests/mod.rs`.
- `src/http.rs`: the shared HTTP client (auth headers, JSON bodies, retries on 429 and 503, status code mapping).
- `src/utils.rs`: shared helpers for names, TXT chunking, CAA and TLSA. Check here before writing your own.

## Adding a provider

1. Copy the shape of a simple token-based provider such as `src/providers/digitalocean.rs` or `src/providers/desec.rs` into `src/providers/<name>.rs`, and register it in `src/providers/mod.rs`.
2. Add a variant to `DnsUpdater` in `src/lib.rs`, a `new_<name>` constructor in `src/update.rs`, and a match arm in each of the four RRSet methods there.
3. Write `src/tests/<name>_tests.rs` with [mockito](https://docs.rs/mockito) tests (see `src/tests/cloudflare_tests.rs`), plus one `#[ignore]` live test.
4. Add a row to the provider table in `README.md`.

Record types a provider cannot handle return `Error::Unsupported`; API failures return `Error::Api`. Please reuse the existing error variants and dependencies, and ask in an issue before adding a new dependency.

## Pull requests

- Keep each pull request focused on one change.
- Add a line to `CHANGELOG.md` under the `[Unreleased]` entry.
- Include tests for the behaviour you add or fix.
- Do not leave comments in source code; explain the reasoning in the pull request description instead.
- Commits must not carry AI co-author trailers.
- If you can, test against the real provider and mention it in the pull request.

Questions are welcome in [GitHub issues](https://github.com/stalwartlabs/dns-update/issues).
