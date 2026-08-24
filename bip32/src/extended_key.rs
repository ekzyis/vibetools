//! BIP-32 extended key parsing.
//!
//! A serialized extended key is Base58Check over exactly 78 bytes:
//!
//! ```text
//!   offset  size  field
//!   0       4     version
//!   4       1     depth
//!   5       4     parent fingerprint
//!   9       4     child number (index)
//!   13      32    chain code
//!   45      33    key data
//! ```
//!
//! Key data is a compressed SEC1 point (0x02/0x03 prefix) for a public key, or
//! 0x00 followed by the 32-byte scalar for a private key.

use base58::decode_check;

/// The raw fields of a BIP-32 serialized extended key.
pub struct ExtendedKey {
    pub version: u32,
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],
    pub key_data: [u8; 33],
}

impl ExtendedKey {
    pub fn parse(s: &str) -> Result<ExtendedKey, String> {
        let data = decode_check(s.trim())?;
        if data.len() != 78 {
            return Err(format!("expected 78-byte payload, got {} bytes", data.len()));
        }

        Ok(ExtendedKey {
            version: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            depth: data[4],
            parent_fingerprint: data[5..9].try_into().unwrap(),
            child_number: u32::from_be_bytes([data[9], data[10], data[11], data[12]]),
            chain_code: data[13..45].try_into().unwrap(),
            key_data: data[45..78].try_into().unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-32 "Test Vectors", Test vector 1, chain m.
    const XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    #[test]
    fn parses_master_xprv() {
        let k = ExtendedKey::parse(XPRV).unwrap();
        assert_eq!(k.version, 0x0488ADE4);
        assert_eq!(k.depth, 0);
        assert_eq!(k.parent_fingerprint, [0, 0, 0, 0]);
        assert_eq!(k.child_number, 0);
        assert_eq!(k.key_data[0], 0x00);
    }

    #[test]
    fn parses_master_xpub() {
        let k = ExtendedKey::parse(XPUB).unwrap();
        assert_eq!(k.version, 0x0488B21E);
        assert!(k.key_data[0] == 0x02 || k.key_data[0] == 0x03);
        // Public and private halves of the same node share a chain code.
        assert_eq!(k.chain_code, ExtendedKey::parse(XPRV).unwrap().chain_code);
    }

    #[test]
    fn rejects_non_extended_key() {
        assert!(ExtendedKey::parse("not-a-key").is_err());
    }
}
