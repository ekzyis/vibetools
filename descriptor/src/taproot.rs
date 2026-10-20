//! The key-path taproot output key (BIP-341).
//!
//! A `tr(KEY)` descriptor does not pay to `KEY` itself. It pays to
//! `Q = P + t·G`, where `P` is `KEY` with its y coordinate forced even and `t`
//! is a hash of `P`. Committing to the key this way means the output key is
//! still a normal-looking public key, while making it provable that there is no
//! hidden script branch: `t` depends on `P`, so nobody can claim `Q` was built
//! from some other key plus a script tree.

use secp256k1::{scalar, Point};
use sha256::sha256;

/// BIP-340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || data)`.
///
/// Prefixing with the 64-byte tag hash puts every use of SHA-256 in Bitcoin's
/// taproot design in its own domain, so a digest meant as a tweak can never be
/// read as, say, a signature challenge.
fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag.as_bytes());
    let mut message = Vec::with_capacity(64 + data.len());
    message.extend_from_slice(&tag_hash);
    message.extend_from_slice(&tag_hash);
    message.extend_from_slice(data);
    sha256(&message)
}

/// The x-only output key for a `tr()` descriptor with no script tree.
pub fn output_key(internal_key: &[u8; 33]) -> Result<[u8; 32], String> {
    let point = Point::from_compressed(internal_key)
        .ok_or_else(|| "internal key is not a point on the curve".to_string())?;
    let x_only = point.x_only().ok_or("internal key is the identity")?;

    // The internal key is x-only, so the tweak is computed over the point with
    // even y whatever the parity of the key we were handed.
    let internal_point = Point::lift_x(&x_only).ok_or("internal key has no even-y point")?;
    // With no script tree the tweak commits to the key alone.
    let tweak = tagged_hash("TapTweak", &x_only);
    if !scalar::is_in_range(&tweak) {
        return Err("taproot tweak is out of range for this key".to_string());
    }

    let output_point = Point::generator().multiply(&tweak) + internal_point;
    output_point
        .x_only()
        .ok_or_else(|| "tweaked key is the identity".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// BIP-86 test vectors: internal key to output key, for the first three
    /// addresses of the reference account.
    #[test]
    fn bip86_internal_to_output_key() {
        let cases = [
            (
                "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
                "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
            ),
            (
                "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
                "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
            ),
            (
                "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
                "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
            ),
        ];
        for (internal, expected) in cases {
            let mut compressed = [0u8; 33];
            compressed[0] = 0x02;
            compressed[1..].copy_from_slice(&unhex(internal));
            assert_eq!(
                hex(&output_key(&compressed).unwrap()),
                expected,
                "{internal}"
            );
        }
    }

    /// The tag hash is prepended twice, which is what makes the digest differ
    /// from a plain SHA-256 of the same data.
    #[test]
    fn tagged_hash_differs_from_plain_hash() {
        assert_ne!(tagged_hash("TapTweak", b"abc"), sha256(b"abc"));
    }
}
