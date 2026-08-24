# base58

Base58 and Base58Check, hand-written from scratch. Depends on the `sha256`
vibetool for the checksum hash. Used on its own and by other vibetools (e.g.
`bip32`).

Base58 uses Bitcoin's alphabet (no `0`, `O`, `I`, `l`). Base58Check appends a
4-byte double-SHA-256 checksum so typos in a copied string are caught.

## API

```rust
base58::encode(&[u8]) -> String
base58::decode(&str)  -> Result<Vec<u8>, String>
base58::encode_check(&[u8]) -> String                 // adds checksum
base58::decode_check(&str)  -> Result<Vec<u8>, String> // verifies checksum
```

## Test

```sh
cargo test -p base58
```

No binary target yet; add a `[[bin]]` to `Cargo.toml` if this tool grows a CLI.
