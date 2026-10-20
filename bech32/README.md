# bech32

Bech32 (BIP-173) and Bech32m (BIP-350), with segwit address encoding,
hand-written from scratch — no dependencies.

A bech32 string is `<hrp>1<data><checksum>`: a human-readable prefix such as
`bc`, the separator `1`, then the payload and a 6-character checksum, in a
32-character alphabet that leaves out `1`, `b`, `i` and `o`.

The checksum is a BCH code over GF(32), strong enough to point at *which*
characters are wrong rather than only that something is. Bech32m differs only in
the constant XORed into the checksum, which is what makes a witness v0 address
and a v1 (taproot) address impossible to confuse: v0 uses Bech32, v1 and up use
Bech32m.

## API

```rust
bech32::encode(hrp: &str, data: &[u8], variant: Variant) -> Result<String, String>
bech32::decode(string: &str) -> Result<(String, Vec<u8>, Variant), String>
bech32::encode_segwit_address(hrp: &str, version: u8, program: &[u8]) -> Result<String, String>
bech32::decode_segwit_address(address: &str) -> Result<(String, u8, Vec<u8>), String>
bech32::convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Result<Vec<u8>, String>
bech32::Variant::{Bech32, Bech32m}
bech32::Variant::for_witness_version(version: u8) -> Variant
```

`data` is 5-bit values, not bytes; `convert_bits` regroups between the two.

## Test

```sh
cargo test -p bech32
```

Tested against the BIP-173 and BIP-350 test vectors: the valid and invalid
bech32/bech32m strings, and the valid and invalid segwit addresses — including
every Bech32/Bech32m mix-up case.

No binary target yet; add a `[[bin]]` to `Cargo.toml` if this tool grows a CLI.
