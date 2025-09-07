## Examples of how to use dns-update

This directory contains a number of examples showcasing various capabilities of
the `dns-update` crate.

All examples can be executed with:

```
cargo run --example $name
```

Some examples may require some environment variables like the `desec` example.

```bash
DESEC_DOMAIN=your-domain \
DESEC_TOKEN=your-desec-token \
cargo run --example desec
```