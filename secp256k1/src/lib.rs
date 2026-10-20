//! secp256k1 — the elliptic curve Bitcoin keys live on — from scratch.
//!
//! The curve is `y² = x³ + 7` over the field of integers modulo
//! `p = 2²⁵⁶ - 2³² - 977`, and the generator `G` has prime order `n`. Two
//! layers make that up:
//!
//! * [`Fe`], arithmetic modulo `p`, for coordinates;
//! * [`Point`], the group of curve points, for keys.
//!
//! Scalars (private keys, tweaks) stay as 32 big-endian bytes; see [`scalar`]
//! for the range check and the addition modulo `n` that key derivation needs.
//!
//! This is written for clarity, not for safety against side-channel attacks:
//! the scalar multiplication is a plain double-and-add whose timing depends on
//! the scalar. Fine for deriving public keys and addresses, which is all the
//! vibetools do with it; not fine for signing with a secret you must protect.

mod field;
mod point;
pub mod scalar;

pub use field::Fe;
pub use point::Point;
