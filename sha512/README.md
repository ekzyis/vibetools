# sha512

SHA-512 (FIPS 180-4) and HMAC-SHA-512 (RFC 2104), hand-written from scratch —
no dependencies. The pair BIP-32 child key derivation is built on, so `bip32`
depends on this.

Same shape as the `sha256` vibetool, but with 64-bit words, 80 rounds,
different rotation amounts, and a 128-byte block with a 128-bit length field.

## API

```rust
sha512::sha512(data: &[u8]) -> [u8; 64]
sha512::hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64]
sha512::BLOCK_LEN  // 128, the block size HMAC pads keys to
```

## Test

```sh
cargo test -p sha512
```

Tested against the FIPS 180-4 examples (`""`, `"abc"`, and the 112-byte
two-block case) and RFC 4231 HMAC test cases 1, 2 and 6 — the last one has a
key longer than a block, so it exercises hashing the key down first.

No binary target yet; add a `[[bin]]` to `Cargo.toml` if this tool grows a CLI.
