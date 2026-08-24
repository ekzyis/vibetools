# sha256

SHA-256 (FIPS 180-4), hand-written from scratch — no dependencies. Used on its
own and by other vibetools (e.g. `base58`).

## API

```rust
sha256::sha256(data: &[u8]) -> [u8; 32]
sha256::double_sha256(data: &[u8]) -> [u8; 32]   // SHA-256(SHA-256(data))
```

## Test

```sh
cargo test -p sha256
```

Tested against the FIPS 180-4 known-answer vectors (`""`, `"abc"`, and the
56-byte two-block example).

No binary target yet; add a `[[bin]]` to `Cargo.toml` if this tool grows a CLI.
