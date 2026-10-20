//! BIP-32 hierarchical deterministic keys: parsing, serializing and child key
//! derivation.
//!
//! The binary targets in this crate use this library; so does the `descriptor`
//! vibetool, which walks the derivation paths inside a wallet descriptor.

pub mod extended_key;

pub use extended_key::{ExtendedKey, KeyKind, Network, HARDENED};
