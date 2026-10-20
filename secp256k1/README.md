# secp256k1

The elliptic curve Bitcoin keys live on, hand-written from scratch — no
dependencies. Used by `bip32` (child key derivation) and `descriptor` (the
taproot tweak).

The curve is `y² = x³ + 7` over the field of integers modulo
`p = 2²⁵⁶ - 2³² - 977`, and the generator `G` has prime order `n`. Two layers:

* `Fe` — arithmetic modulo `p`, for coordinates. Four 64-bit limbs, always
  fully reduced. Multiplication takes a 512-bit schoolbook product and folds it
  back down using the shape of `p`: since `2²⁵⁶ ≡ 2³² + 977 (mod p)`, the high
  half is multiplied by that small constant and added to the low half, instead
  of doing a real division. Inversion and square roots are exponentiations
  (`a^(p-2)` and `a^((p+1)/4)`, the latter because `p ≡ 3 mod 4`).
* `Point` — the group of curve points, for keys. Affine coordinates, so every
  addition does a field inversion. Slower than the projective coordinates a
  production library uses, but it is the group law as the textbook states it.

Scalars (private keys, tweaks) stay as 32 big-endian bytes; `scalar` has the
range check and the addition modulo `n` that key derivation needs.

## API

```rust
secp256k1::Point::generator() -> Point
secp256k1::Point::from_secret(secret: &[u8; 32]) -> Option<Point>   // secret * G
secp256k1::Point::from_compressed(bytes: &[u8; 33]) -> Option<Point>
secp256k1::Point::lift_x(x_only: &[u8; 32]) -> Option<Point>        // BIP-340
secp256k1::Point::{add, double, multiply, negate, to_compressed, x_only, is_on_curve}
secp256k1::Fe::{from_be_bytes, to_be_bytes, add, sub, neg, mul, square, invert, sqrt}
secp256k1::scalar::{ORDER, is_in_range, add_mod_order}
```

## Test

```sh
cargo test -p secp256k1
```

The field is checked against independently computed products, inverses and
roots; the group law against the published small multiples of `G` (`1G`..`5G`),
and `n·G = ∞`. The strongest test is indirect: `cargo test -p bip32` derives the
BIP-32 test vector chains through this code, both private and public paths.

## Scope

Public-key arithmetic only: no signing, no verification. Written for clarity,
*not* against side-channel attacks — the scalar multiplication is a plain
double-and-add whose timing depends on the scalar. Fine for deriving addresses,
not for handling a secret you must protect.

No binary target yet; add a `[[bin]]` to `Cargo.toml` if this tool grows a CLI.
