# bip32

BIP-32 hierarchical deterministic keys: the serialization format, and the child
key derivation that turns one key into a tree of them. One binary target,
`bip32-decode`, which decodes an extended key into its components; the
derivation is used as a library by the `descriptor` vibetool.

Reuses the `base58`, `sha512` (HMAC), `ripemd160` (fingerprints) and
`secp256k1` (public keys, point addition) vibetools.

## Usage

```sh
cargo run -p bip32 --bin bip32-decode -- <xpub|xprv>   # key as an argument
echo <xpub|xprv> | cargo run -p bip32 --bin bip32-decode  # or piped on stdin
```

Example:

```
$ bip32-decode xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
version            0x0488ade4
depth              0
parent fingerprint 00000000
child number       0x00000000
chain code         873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
key data           00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
```

The output is exactly the literal BIP-32 serialized fields: key data is the raw
33-byte field (`0x00 || ser256(k)` for a private key, `serP(K)` for a public
key), and child number the raw `ser32(i)`.

Exit codes: `0` success, `1` parse/checksum error, `2` no input.

## Test

```sh
cargo test -p bip32
```

Checked against the BIP-32 "Test Vectors": test vectors 1 to 4 are walked
chain by chain, deriving each child from the private parent *and*, where the
index is not hardened, from the public parent, comparing both serializations at
every step. Test vector 5's keys are all rejected.

## API

```rust
bip32::ExtendedKey::parse(&str) -> Result<ExtendedKey, String>
bip32::ExtendedKey::serialize(&self) -> String
bip32::ExtendedKey::derive_child(&self, index: u32) -> Result<ExtendedKey, String>
bip32::ExtendedKey::derive_path(&self, path: &[u32]) -> Result<ExtendedKey, String>
bip32::ExtendedKey::{to_public, public_key, private_key, fingerprint, network, kind, prefix}
bip32::HARDENED  // 0x8000_0000; add it to an index to harden it
```

## Serialization format

An extended key is Base58Check over 78 bytes: version (4), depth (1), parent
fingerprint (4), child number (4), chain code (32), key data (33). A child
index ≥ 2³¹ is hardened and shown as `i'`.

Besides BIP-32's own `xpub`/`xprv` and `tpub`/`tprv`, the SLIP-132 version bytes
(`ypub`, `zpub`, `upub`, `vpub`, `Ypub`, `Zpub`, …) are recognized, since that
is how wallets export accounts. The script type they imply is advice for a
wallet, not part of the key, so it is not tracked.

## Scope

Parsing, serializing and deriving public and private children. Deriving a
hardened child needs the private key, as BIP-32 intends. `parse` rejects the
serializations BIP-32 calls invalid: unknown version bytes, key data that does
not match the version, keys off the curve or out of range, and a master key
claiming to have a parent.

No signing, and no seed-to-master-key step (that is BIP-39's and BIP-32's
`HMAC-SHA512("Bitcoin seed", seed)`, not implemented here).
