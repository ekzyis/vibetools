# ripemd160

RIPEMD-160, hand-written from scratch, plus Bitcoin's `HASH160`. Depends on the
`sha256` vibetool for `HASH160`.

Unlike SHA-2, RIPEMD-160 runs *two* independent lines of 80 steps over each
block — different constants, word order and rotations in each — and combines
both results at the end. Words are little-endian throughout.

`HASH160` is `RIPEMD160(SHA256(x))`, the 20-byte digest Bitcoin uses to shorten
public keys (P2PKH, P2WPKH) and scripts (P2SH).

## API

```rust
ripemd160::ripemd160(data: &[u8]) -> [u8; 20]
ripemd160::hash160(data: &[u8]) -> [u8; 20]   // RIPEMD160(SHA256(data))
```

## Test

```sh
cargo test -p ripemd160
```

Tested against the RIPEMD-160 specification's own table of test values,
including the one-million-`a` case, and against BIP-49's `HASH160(pubkey)`
vector.

No binary target yet; add a `[[bin]]` to `Cargo.toml` if this tool grows a CLI.
