//! Turning a scriptPubKey into the address people copy and paste.
//!
//! An address is just a compact way to write one of a few standard
//! scriptPubKeys: the legacy forms are Base58Check over a version byte and a
//! 20-byte hash, and the segwit forms are bech32 (v0) or bech32m (v1+) over the
//! witness version and program.

use bech32::encode_segwit_address;
use bip32::Network;

/// What an address can point at.
pub enum Payload {
    /// A 20-byte public key hash (P2PKH).
    KeyHash([u8; 20]),
    /// A 20-byte script hash (P2SH).
    ScriptHash([u8; 20]),
    /// A witness version and program (P2WPKH, P2WSH, P2TR).
    Witness { version: u8, program: Vec<u8> },
}

/// The Base58Check version byte for P2PKH addresses: `1...` and `m.../n...`.
fn key_hash_version(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0x00,
        Network::Testnet => 0x6f,
    }
}

/// The Base58Check version byte for P2SH addresses: `3...` and `2...`.
fn script_hash_version(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0x05,
        Network::Testnet => 0xc4,
    }
}

/// The bech32 human-readable part for segwit addresses.
fn witness_prefix(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "bc",
        Network::Testnet => "tb",
    }
}

pub fn encode(payload: &Payload, network: Network) -> Result<String, String> {
    match payload {
        Payload::KeyHash(hash) => Ok(base58_address(key_hash_version(network), hash)),
        Payload::ScriptHash(hash) => Ok(base58_address(script_hash_version(network), hash)),
        Payload::Witness { version, program } => {
            encode_segwit_address(witness_prefix(network), *version, program)
        }
    }
}

fn base58_address(version: u8, hash: &[u8; 20]) -> String {
    let mut payload = Vec::with_capacity(21);
    payload.push(version);
    payload.extend_from_slice(hash);
    base58::encode_check(&payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn unhex20(hex: &str) -> [u8; 20] {
        unhex(hex).try_into().unwrap()
    }

    /// The worked example from Bitcoin's "Technical background of version 1
    /// Bitcoin addresses": an uncompressed key, its HASH160, and the address.
    #[test]
    fn legacy_key_hash_address() {
        let key = unhex(
            "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b235\
             22cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6",
        );
        let hash = ripemd160::hash160(&key);
        assert_eq!(hash, unhex20("010966776006953d5567439e5e39f86a0d273bee"));
        assert_eq!(
            encode(&Payload::KeyHash(hash), Network::Mainnet).unwrap(),
            "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
        );
    }

    /// BIP-49's test vector ends at this P2SH-P2WPKH address on testnet.
    #[test]
    fn bip49_script_hash_address() {
        let hash = unhex20("336caa13e08b96080a32b5d818d59b4ab3b36742");
        assert_eq!(
            encode(&Payload::ScriptHash(hash), Network::Testnet).unwrap(),
            "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"
        );
    }

    #[test]
    fn witness_addresses_pick_the_right_variant() {
        // Witness v0 is bech32 ("bc1q"), v1 and up are bech32m ("bc1p").
        let v0 = encode(
            &Payload::Witness {
                version: 0,
                program: vec![0u8; 20],
            },
            Network::Mainnet,
        )
        .unwrap();
        let v1 = encode(
            &Payload::Witness {
                version: 1,
                program: vec![0u8; 32],
            },
            Network::Mainnet,
        )
        .unwrap();
        assert!(v0.starts_with("bc1q"), "{v0}");
        assert!(v1.starts_with("bc1p"), "{v1}");
    }
}
