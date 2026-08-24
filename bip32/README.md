# bip32

BIP-32 key tools. Currently one target, `bip32-decode`, which decodes a BIP-32
extended key (`xpub`/`xprv`, plus testnet `tpub`/`tprv`) into its components.
Reuses the `sha256` and `base58` vibetools (via `base58`); the field parsing is
hand-written here.

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

Decoding is checked against BIP-32 "Test Vectors" (test vector 1, chain m).

## Serialization format

An extended key is Base58Check over 78 bytes: version (4), depth (1), parent
fingerprint (4), child number (4), chain code (32), key data (33). A child
index ≥ 2³¹ is hardened and shown as `i'`.

## Scope

A decoder only: it decodes and verifies the checksum. It does no elliptic-curve
math — no key derivation, no checking that a public key is a valid secp256k1
point.
