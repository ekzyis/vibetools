//! BIP-32 extended keys: the serialization format, and the child key
//! derivation function that turns one key into a tree of them.
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

use base58::{decode_check, encode_check};
use ripemd160::hash160;
use secp256k1::{scalar, Point};
use sha512::hmac_sha512;

/// Child indices from this value up are hardened: deriving them needs the
/// parent's private key, which is what stops an xpub leak from exposing the
/// whole subtree.
pub const HARDENED: u32 = 0x8000_0000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Network {
    Mainnet,
    Testnet,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyKind {
    Public,
    Private,
}

/// One registered pair of version bytes, i.e. one human-readable prefix.
///
/// BIP-32 defines the `xpub`/`xprv` and `tpub`/`tprv` pairs; the rest are the
/// SLIP-132 prefixes wallets use to also record which script type an account
/// is for. The script type is advice for a wallet, not part of the key, so it
/// is not tracked here — a descriptor states the script type itself.
struct Serialization {
    public: u32,
    private: u32,
    network: Network,
    public_prefix: &'static str,
    private_prefix: &'static str,
}

#[rustfmt::skip]
const SERIALIZATIONS: &[Serialization] = &[
    Serialization { public: 0x0488b21e, private: 0x0488ade4, network: Network::Mainnet, public_prefix: "xpub", private_prefix: "xprv" },
    Serialization { public: 0x049d7cb2, private: 0x049d7878, network: Network::Mainnet, public_prefix: "ypub", private_prefix: "yprv" },
    Serialization { public: 0x04b24746, private: 0x04b2430c, network: Network::Mainnet, public_prefix: "zpub", private_prefix: "zprv" },
    Serialization { public: 0x0295b43f, private: 0x0295b005, network: Network::Mainnet, public_prefix: "Ypub", private_prefix: "Yprv" },
    Serialization { public: 0x02aa7ed3, private: 0x02aa7a99, network: Network::Mainnet, public_prefix: "Zpub", private_prefix: "Zprv" },
    Serialization { public: 0x043587cf, private: 0x04358394, network: Network::Testnet, public_prefix: "tpub", private_prefix: "tprv" },
    Serialization { public: 0x044a5262, private: 0x044a4e28, network: Network::Testnet, public_prefix: "upub", private_prefix: "uprv" },
    Serialization { public: 0x045f1cf6, private: 0x045f18bc, network: Network::Testnet, public_prefix: "vpub", private_prefix: "vprv" },
    Serialization { public: 0x024289ef, private: 0x024285b5, network: Network::Testnet, public_prefix: "Upub", private_prefix: "Uprv" },
    Serialization { public: 0x02575483, private: 0x02575048, network: Network::Testnet, public_prefix: "Vpub", private_prefix: "Vprv" },
];

fn lookup_version(version: u32) -> Option<(&'static Serialization, KeyKind)> {
    SERIALIZATIONS.iter().find_map(|s| {
        if s.public == version {
            Some((s, KeyKind::Public))
        } else if s.private == version {
            Some((s, KeyKind::Private))
        } else {
            None
        }
    })
}

/// The raw fields of a BIP-32 serialized extended key.
#[derive(Clone)]
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
            return Err(format!(
                "expected 78-byte payload, got {} bytes",
                data.len()
            ));
        }

        let key = ExtendedKey {
            version: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            depth: data[4],
            parent_fingerprint: data[5..9].try_into().unwrap(),
            child_number: u32::from_be_bytes([data[9], data[10], data[11], data[12]]),
            chain_code: data[13..45].try_into().unwrap(),
            key_data: data[45..78].try_into().unwrap(),
        };
        key.validate()?;
        Ok(key)
    }

    /// Reject the serializations BIP-32 calls invalid: unknown version bytes,
    /// key data that does not match the version, keys off the curve or out of
    /// range, and a master key that claims to have a parent.
    fn validate(&self) -> Result<(), String> {
        let (_, kind) = lookup_version(self.version)
            .ok_or_else(|| format!("unknown version bytes: {:#010x}", self.version))?;

        match kind {
            KeyKind::Private => {
                if self.key_data[0] != 0x00 {
                    return Err(format!(
                        "private key data must start with 0x00, got {:#04x}",
                        self.key_data[0]
                    ));
                }
                let scalar: [u8; 32] = self.key_data[1..].try_into().unwrap();
                if !scalar::is_in_range(&scalar) {
                    return Err("private key is not in 1..n-1".to_string());
                }
            }
            KeyKind::Public => {
                if self.key_data[0] != 0x02 && self.key_data[0] != 0x03 {
                    return Err(format!(
                        "public key data must start with 0x02 or 0x03, got {:#04x}",
                        self.key_data[0]
                    ));
                }
                if Point::from_compressed(&self.key_data).is_none() {
                    return Err("public key is not a point on the curve".to_string());
                }
            }
        }

        if self.depth == 0 {
            if self.parent_fingerprint != [0; 4] {
                return Err("master key has a non-zero parent fingerprint".to_string());
            }
            if self.child_number != 0 {
                return Err("master key has a non-zero child number".to_string());
            }
        }
        Ok(())
    }

    /// Serialize back to the Base58Check form, the inverse of [`Self::parse`].
    pub fn serialize(&self) -> String {
        let mut payload = Vec::with_capacity(78);
        payload.extend_from_slice(&self.version.to_be_bytes());
        payload.push(self.depth);
        payload.extend_from_slice(&self.parent_fingerprint);
        payload.extend_from_slice(&self.child_number.to_be_bytes());
        payload.extend_from_slice(&self.chain_code);
        payload.extend_from_slice(&self.key_data);
        encode_check(&payload)
    }

    fn serialization(&self) -> &'static Serialization {
        // Every parsed key has known version bytes, so this cannot fail.
        lookup_version(self.version).expect("validated version").0
    }

    pub fn network(&self) -> Network {
        self.serialization().network
    }

    pub fn kind(&self) -> KeyKind {
        lookup_version(self.version).expect("validated version").1
    }

    /// The human-readable prefix this key serializes with, e.g. `"xpub"`.
    pub fn prefix(&self) -> &'static str {
        let serialization = self.serialization();
        match self.kind() {
            KeyKind::Public => serialization.public_prefix,
            KeyKind::Private => serialization.private_prefix,
        }
    }

    /// The compressed public key, computed from the scalar for a private key.
    pub fn public_key(&self) -> [u8; 33] {
        match self.kind() {
            KeyKind::Public => self.key_data,
            KeyKind::Private => {
                let secret = self.private_key().expect("private key");
                Point::from_secret(&secret)
                    .expect("validated scalar")
                    .to_compressed()
                    .expect("secret times G is never infinity")
            }
        }
    }

    /// The 32-byte private scalar, for a private key only.
    pub fn private_key(&self) -> Option<[u8; 32]> {
        match self.kind() {
            KeyKind::Private => Some(self.key_data[1..].try_into().unwrap()),
            KeyKind::Public => None,
        }
    }

    /// The key's identifier is `HASH160` of its public key; the fingerprint is
    /// the first four bytes, which children record to point back at the parent.
    pub fn fingerprint(&self) -> [u8; 4] {
        hash160(&self.public_key())[..4].try_into().unwrap()
    }

    /// The matching public key: a public key is returned unchanged, a private
    /// key is converted (keeping the network and prefix flavour).
    pub fn to_public(&self) -> ExtendedKey {
        ExtendedKey {
            version: self.serialization().public,
            key_data: self.public_key(),
            ..self.clone()
        }
    }

    /// Derive the child at `index`, hardened if `index >= HARDENED`
    /// (BIP-32 "Child key derivation (CKD) functions").
    ///
    /// Deriving from a private key gives a private child; deriving from a
    /// public key gives a public child, and only for non-hardened indices.
    pub fn derive_child(&self, index: u32) -> Result<ExtendedKey, String> {
        if self.depth == u8::MAX {
            return Err("cannot derive past depth 255".to_string());
        }
        let hardened = index >= HARDENED;
        let secret = self.private_key();
        if hardened && secret.is_none() {
            return Err(format!(
                "cannot derive hardened child {}' from a public key",
                index - HARDENED
            ));
        }

        // The HMAC input is the parent's private key for a hardened child (so
        // the public key alone is not enough to follow), else its public key.
        let mut message = Vec::with_capacity(37);
        if hardened {
            message.push(0x00);
            message.extend_from_slice(&secret.expect("checked above"));
        } else {
            message.extend_from_slice(&self.public_key());
        }
        message.extend_from_slice(&index.to_be_bytes());

        let digest = hmac_sha512(&self.chain_code, &message);
        let (tweak, chain_code) = digest.split_at(32);
        let tweak: [u8; 32] = tweak.try_into().unwrap();

        // A tweak at or above the group order would wrap, so BIP-32 says to
        // skip such a child. It has never been observed and never will be.
        if tweak[..] >= scalar::ORDER[..] {
            return Err(format!(
                "child {index} is invalid: tweak >= n (try the next index)"
            ));
        }

        let key_data = match secret {
            // Private child: add the tweak to the parent scalar.
            Some(parent_secret) => {
                let child_secret = scalar::add_mod_order(&tweak, &parent_secret);
                if child_secret == [0u8; 32] {
                    return Err(format!("child {index} is invalid: key is zero"));
                }
                let mut data = [0u8; 33];
                data[1..].copy_from_slice(&child_secret);
                data
            }
            // Public child: the same addition, carried out on the curve.
            None => {
                let parent_point = Point::from_compressed(&self.key_data)
                    .ok_or_else(|| "public key is not a point on the curve".to_string())?;
                let child_point = Point::generator().multiply(&tweak) + parent_point;
                child_point
                    .to_compressed()
                    .ok_or_else(|| format!("child {index} is invalid: key is the identity"))?
            }
        };

        Ok(ExtendedKey {
            version: self.version,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: index,
            chain_code: chain_code.try_into().unwrap(),
            key_data,
        })
    }

    /// Derive a whole path, one index at a time.
    pub fn derive_path(&self, path: &[u32]) -> Result<ExtendedKey, String> {
        let mut key = self.clone();
        for &index in path {
            key = key.derive_child(index)?;
        }
        Ok(key)
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
        assert_eq!(k.prefix(), "xprv");
        assert_eq!(k.network(), Network::Mainnet);
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

    #[test]
    fn serialize_round_trips() {
        for key in [XPRV, XPUB] {
            assert_eq!(ExtendedKey::parse(key).unwrap().serialize(), key);
        }
    }

    #[test]
    fn public_half_matches_private() {
        let private = ExtendedKey::parse(XPRV).unwrap();
        assert_eq!(private.to_public().serialize(), XPUB);
    }

    /// Walk a BIP-32 test vector chain: each step derives the child from the
    /// private parent and checks both serializations, then re-derives the same
    /// child from the *public* parent where the index is not hardened.
    fn check_chain(master: &str, chain: &[(u32, &str, &str)]) {
        let mut key = ExtendedKey::parse(master).unwrap();
        for &(index, expected_xprv, expected_xpub) in chain {
            let child = key.derive_child(index).unwrap();
            assert_eq!(child.serialize(), expected_xprv, "index {index}");
            assert_eq!(
                child.to_public().serialize(),
                expected_xpub,
                "index {index}"
            );

            let public_parent = key.to_public();
            if index < HARDENED {
                assert_eq!(
                    public_parent.derive_child(index).unwrap().serialize(),
                    expected_xpub,
                    "index {index} from public parent"
                );
            } else {
                assert!(public_parent.derive_child(index).is_err());
            }
            key = child;
        }
    }

    // BIP-32 "Test Vectors", Test vector 1: m/0h/1/2h/2/1000000000.
    #[test]
    fn test_vector_1() {
        check_chain(XPRV, &[
            (HARDENED, "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"),
            (1, "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"),
            (2 + HARDENED, "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM", "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"),
            (2, "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334", "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"),
            (1000000000, "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76", "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"),
        ]);
    }

    // BIP-32 Test vector 2: m/0/2147483647h/1/2147483646h/2, the chain that
    // alternates hardened and normal steps.
    #[test]
    fn test_vector_2() {
        check_chain("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U", &[
            (0, "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt", "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"),
            (2147483647 + HARDENED, "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9", "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"),
            (1, "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef", "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"),
            (2147483646 + HARDENED, "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc", "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"),
            (2, "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j", "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"),
        ]);
    }

    // BIP-32 Test vectors 3 and 4, which exist to catch implementations that
    // drop leading zero bytes somewhere in the derivation.
    #[test]
    fn test_vectors_3_and_4() {
        check_chain("xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6", &[
            (HARDENED, "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L", "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"),
        ]);
        check_chain("xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv", &[
            (HARDENED, "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G", "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m"),
            (1 + HARDENED, "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1", "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt"),
        ]);
    }

    // BIP-32 Test vector 5: keys that must be recognized as invalid.
    #[test]
    fn test_vector_5_rejects_invalid_keys() {
        for key in [
            "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",
        ] {
            assert!(
                ExtendedKey::parse(key).is_err(),
                "should be rejected: {key}"
            );
        }
    }

    #[test]
    fn derives_a_path_in_one_call() {
        let master = ExtendedKey::parse(XPRV).unwrap();
        let stepwise = master
            .derive_child(HARDENED)
            .unwrap()
            .derive_child(1)
            .unwrap();
        let at_once = master.derive_path(&[HARDENED, 1]).unwrap();
        assert_eq!(stepwise.serialize(), at_once.serialize());
    }

    #[test]
    fn fingerprint_links_child_to_parent() {
        let master = ExtendedKey::parse(XPRV).unwrap();
        let child = master.derive_child(0).unwrap();
        assert_eq!(child.parent_fingerprint, master.fingerprint());
        assert_eq!(child.depth, 1);
    }
}
