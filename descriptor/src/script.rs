//! The pieces of Bitcoin script a descriptor can produce.
//!
//! Only the handful of opcodes the supported descriptors need are here; this is
//! not a script interpreter, just enough of the serialization to build a
//! scriptPubKey (or a redeem/witness script) and hash it.

const OP_0: u8 = 0x00;
const OP_DUP: u8 = 0x76;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_HASH160: u8 = 0xa9;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKMULTISIG: u8 = 0xae;
/// `OP_1` is 0x51, and `OP_N` follows at 0x50 + N up to `OP_16`.
const OP_1: u8 = 0x51;

/// Push `data` onto the stack. Descriptor scripts only ever push keys (33 or 65
/// bytes) and hashes (20 or 32), all of which fit the one-byte length form.
fn push(script: &mut Vec<u8>, data: &[u8]) {
    assert!(
        data.len() <= 75,
        "push of {} bytes needs OP_PUSHDATA",
        data.len()
    );
    script.push(data.len() as u8);
    script.extend_from_slice(data);
}

/// Push a small non-negative number the way script encodes one: the dedicated
/// `OP_0`..`OP_16` opcodes where they exist, otherwise a one-byte data push.
fn push_number(script: &mut Vec<u8>, n: u8) {
    match n {
        0 => script.push(OP_0),
        1..=16 => script.push(OP_1 - 1 + n),
        _ => push(script, &[n]),
    }
}

/// `<key> OP_CHECKSIG` — pay to a bare public key.
pub fn p2pk(key: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(key.len() + 2);
    push(&mut script, key);
    script.push(OP_CHECKSIG);
    script
}

/// `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG` — pay to a key hash.
pub fn p2pkh(key_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = vec![OP_DUP, OP_HASH160];
    push(&mut script, key_hash);
    script.push(OP_EQUALVERIFY);
    script.push(OP_CHECKSIG);
    script
}

/// `OP_HASH160 <hash> OP_EQUAL` — pay to a script hash.
pub fn p2sh(script_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = vec![OP_HASH160];
    push(&mut script, script_hash);
    script.push(OP_EQUAL);
    script
}

/// `OP_<version> <program>` — a segwit output.
pub fn witness_program(version: u8, program: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(program.len() + 2);
    push_number(&mut script, version);
    push(&mut script, program);
    script
}

/// `OP_<k> <key>... OP_<n> OP_CHECKMULTISIG` — the k-of-n multisig script,
/// with the keys in the order given, as `multi()` wants them.
pub fn multisig(threshold: u8, keys: &[Vec<u8>]) -> Vec<u8> {
    let mut script = Vec::new();
    push_number(&mut script, threshold);
    for key in keys {
        push(&mut script, key);
    }
    push_number(&mut script, keys.len() as u8);
    script.push(OP_CHECKMULTISIG);
    script
}

/// The same script with the keys in lexicographic order, as `sortedmulti()`
/// wants them (BIP-67).
///
/// Sorting is what lets a set of cosigners agree on one script without also
/// agreeing on an order to list their keys in. It happens on the *derived*
/// keys, so each address index has its own order.
pub fn sorted_multisig(threshold: u8, keys: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = keys.to_vec();
    sorted.sort();
    multisig(threshold, &sorted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{encode, Payload};
    use bip32::Network;
    use ripemd160::hash160;

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// BIP-67 "Test vectors": the key lists, the 2-of-n scripts their sorted
    /// order produces, and the P2SH addresses. Vector 3's keys are not points
    /// on the curve, which is the point — the order is a plain byte ordering.
    #[test]
    fn bip67_sorted_multisig_vectors() {
        let vectors: [(&[&str], &str, &str); 4] = [
            (
                &[
                    "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
                    "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f",
                ],
                "522102fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f2102ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f852ae",
                "39bgKC7RFbpoCRbtD5KEdkYKtNyhpsNa3Z",
            ),
            (
                &[
                    "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
                    "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
                    "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404",
                ],
                "522102632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed021027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e772102e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b40453ae",
                "3CKHTjBKxCARLzwABMu9yD85kvtm7WnMfH",
            ),
            (
                &[
                    "030000000000000000000000000000000000004141414141414141414141414141",
                    "020000000000000000000000000000000000004141414141414141414141414141",
                    "020000000000000000000000000000000000004141414141414141414141414140",
                    "030000000000000000000000000000000000004141414141414141414141414140",
                ],
                "522102000000000000000000000000000000000000414141414141414141414141414021020000000000000000000000000000000000004141414141414141414141414141210300000000000000000000000000000000000041414141414141414141414141402103000000000000000000000000000000000000414141414141414141414141414154ae",
                "32V85igBri9zcfBRVupVvwK18NFtS37FuD",
            ),
            (
                &[
                    "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
                    "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
                    "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18",
                ],
                "5221021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc1821022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da2103e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e953ae",
                "3Q4sF6tv9wsdqu2NtARzNCpQgwifm2rAba",
            ),
        ];

        for (keys, expected_script, expected_address) in vectors {
            let keys: Vec<Vec<u8>> = keys.iter().map(|key| unhex(key)).collect();
            let script = sorted_multisig(2, &keys);
            assert_eq!(
                hex(&script),
                expected_script,
                "script for {expected_address}"
            );
            assert_eq!(
                encode(&Payload::ScriptHash(hash160(&script)), Network::Mainnet).unwrap(),
                expected_address
            );
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn standard_script_shapes() {
        assert_eq!(
            hex(&p2pkh(&[0x11; 20])),
            "76a914111111111111111111111111111111111111111188ac"
        );
        assert_eq!(
            hex(&p2sh(&[0x22; 20])),
            "a914222222222222222222222222222222222222222287"
        );
        assert_eq!(
            hex(&witness_program(0, &[0x33; 20])),
            format!("0014{}", hex(&[0x33; 20]))
        );
        assert_eq!(
            hex(&witness_program(1, &[0x44; 32])),
            format!("5120{}", hex(&[0x44; 32]))
        );
    }

    #[test]
    fn multisig_counts_above_sixteen_are_pushed() {
        // 1-of-1 uses the OP_N opcodes, 17-of-17 has to push the numbers.
        let key = vec![0x02; 33];
        assert!(multisig(1, std::slice::from_ref(&key)).starts_with(&[0x51, 0x21]));
        let many = vec![key; 17];
        let script = multisig(17, &many);
        assert!(script.starts_with(&[0x01, 0x11]), "threshold push");
        assert!(script.ends_with(&[0x01, 0x11, 0xae]), "count push");
    }
}
