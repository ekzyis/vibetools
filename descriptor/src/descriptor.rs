//! Parsing output script descriptors and turning them into addresses.
//!
//! A descriptor is a small expression that says exactly which scriptPubKeys a
//! wallet owns, e.g. `wsh(sortedmulti(2,xpubA/0/*,xpubB/0/*))#checksum`. Each
//! function describes one layer of the script, the key expressions inside
//! describe the keys, and a `*` wildcard turns the whole thing into an endless
//! list of scripts — one per address index.
//!
//! Supported: `pk`, `pkh`, `wpkh`, `multi`, `sortedmulti`, `sh`, `wsh` and
//! single-key `tr`. See the README for what that leaves out.

use bip32::Network;
use ripemd160::hash160;
use sha256::sha256;

use crate::address::{self, Payload};
use crate::checksum;
use crate::key::KeyExpression;
use crate::multipath;
use crate::script;
use crate::taproot;

/// A descriptor function and its arguments.
pub enum Descriptor {
    /// `pk(KEY)`: pay to a bare public key.
    Pk(KeyExpression),
    /// `pkh(KEY)`: pay to a public key hash.
    Pkh(KeyExpression),
    /// `wpkh(KEY)`: pay to a witness public key hash.
    Wpkh(KeyExpression),
    /// `sh(SCRIPT)`: pay to the hash of the inner script.
    Sh(Box<Descriptor>),
    /// `wsh(SCRIPT)`: pay to the witness hash of the inner script.
    Wsh(Box<Descriptor>),
    /// `multi(k,KEY...)`, or `sortedmulti(k,KEY...)` which puts the derived
    /// keys in lexicographic order so that every signer builds the same script.
    Multi {
        threshold: u8,
        keys: Vec<KeyExpression>,
        sorted: bool,
    },
    /// `tr(KEY)`: pay to a taproot output with no script tree.
    Tr(KeyExpression),
}

/// Where in a descriptor an expression sits. The allowed functions differ:
/// `sh()` only wraps the top level, and segwit scripts cannot nest.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Context {
    Top,
    /// Inside `sh()`, i.e. a P2SH redeem script.
    Sh,
    /// Inside `wsh()`, i.e. a P2WSH witness script.
    Wsh,
}

/// A parsed descriptor, with its checksum and the text it came from.
///
/// A multipath descriptor (BIP-389) stands for several single-path descriptors;
/// one instance covers one of them, named by [`Self::chain`].
pub struct WalletDescriptor {
    pub body: String,
    pub checksum: String,
    /// Which of the multipath chains this instance derives; 0 without them.
    pub chain: usize,
    /// How many chains the body stands for; 1 without multipath elements.
    pub chain_count: usize,
    /// The single-path body for `chain`, when the body has multipath elements.
    expanded_body: Option<String>,
    pub descriptor: Descriptor,
}

impl WalletDescriptor {
    /// Parse a descriptor, taking the first chain of a multipath one.
    pub fn parse(text: &str) -> Result<WalletDescriptor, String> {
        WalletDescriptor::parse_chain(text, 0)
    }

    /// Parse the `chain`-th single-path descriptor of a multipath descriptor.
    pub fn parse_chain(text: &str, chain: usize) -> Result<WalletDescriptor, String> {
        let text = text.trim();
        let (body, checksum) = checksum::split(text)?;

        // Substituting the tuples first leaves an ordinary single-path
        // descriptor for the parser below.
        let chain_count = multipath::chain_count(body)?;
        if chain >= chain_count {
            return Err(format!(
                "this descriptor has {chain_count} chain(s), so chain {chain} does not exist"
            ));
        }
        let expanded_body = match chain_count {
            1 => None,
            _ => Some(multipath::expand(body, chain)?),
        };

        let descriptor = parse_expression(expanded_body.as_deref().unwrap_or(body), Context::Top)?;
        descriptor.check_networks()?;
        Ok(WalletDescriptor {
            body: body.to_string(),
            checksum,
            chain,
            chain_count,
            expanded_body,
            descriptor,
        })
    }

    /// The descriptor with its checksum attached, as it should be stored.
    pub fn canonical(&self) -> String {
        format!("{}#{}", self.body, self.checksum)
    }

    /// The single-path descriptor for the selected chain, with its own
    /// checksum — what to hand to software that does not know BIP-389.
    pub fn expanded_canonical(&self) -> Option<String> {
        self.expanded_body.as_ref().map(|body| {
            // Expanding only removes characters, so the body is still valid.
            let checksum = checksum::create(body).expect("expanded body stays in the charset");
            format!("{body}#{checksum}")
        })
    }

    /// Whether the descriptor describes a list of scripts rather than one.
    pub fn has_wildcard(&self) -> bool {
        self.descriptor.keys().iter().any(|k| k.has_wildcard())
    }

    pub fn network(&self) -> Network {
        self.descriptor.keys()[0].network()
    }

    /// A short name for the kind of output this pays to.
    pub fn output_kind(&self) -> &'static str {
        self.descriptor.output_kind()
    }

    pub fn script_pubkey(&self, index: u32) -> Result<Vec<u8>, String> {
        self.descriptor.script(index)
    }

    pub fn address(&self, index: u32) -> Result<String, String> {
        let payload = self.descriptor.payload(index)?;
        address::encode(&payload, self.network())
    }

    /// Every key expression in the descriptor, outermost first.
    pub fn keys(&self) -> Vec<&KeyExpression> {
        self.descriptor.keys()
    }
}

impl Descriptor {
    /// The script this expression evaluates to at address `index`: the
    /// scriptPubKey at the top level, or the inner script within `sh`/`wsh`.
    fn script(&self, index: u32) -> Result<Vec<u8>, String> {
        match self {
            Descriptor::Pk(key) => Ok(script::p2pk(&key.public_key(index)?)),
            Descriptor::Pkh(key) => Ok(script::p2pkh(&hash160(&key.public_key(index)?))),
            Descriptor::Wpkh(key) => Ok(script::witness_program(
                0,
                &hash160(&key.public_key(index)?),
            )),
            Descriptor::Sh(inner) => Ok(script::p2sh(&hash160(&inner.script(index)?))),
            Descriptor::Wsh(inner) => {
                Ok(script::witness_program(0, &sha256(&inner.script(index)?)))
            }
            Descriptor::Multi {
                threshold,
                keys,
                sorted,
            } => {
                let derived: Vec<Vec<u8>> = keys
                    .iter()
                    .map(|key| key.public_key(index).map(|k| k.to_vec()))
                    .collect::<Result<_, _>>()?;
                Ok(match sorted {
                    true => script::sorted_multisig(*threshold, &derived),
                    false => script::multisig(*threshold, &derived),
                })
            }
            Descriptor::Tr(key) => Ok(script::witness_program(
                1,
                &taproot::output_key(&key.public_key(index)?)?,
            )),
        }
    }

    /// What the top-level script pays to, for address encoding.
    fn payload(&self, index: u32) -> Result<Payload, String> {
        match self {
            Descriptor::Pkh(key) => Ok(Payload::KeyHash(hash160(&key.public_key(index)?))),
            Descriptor::Sh(_) => Ok(Payload::ScriptHash(hash160(&self.inner_script(index)?))),
            Descriptor::Wpkh(key) => Ok(Payload::Witness {
                version: 0,
                program: hash160(&key.public_key(index)?).to_vec(),
            }),
            Descriptor::Wsh(_) => Ok(Payload::Witness {
                version: 0,
                program: sha256(&self.inner_script(index)?).to_vec(),
            }),
            Descriptor::Tr(key) => Ok(Payload::Witness {
                version: 1,
                program: taproot::output_key(&key.public_key(index)?)?.to_vec(),
            }),
            // These pay to a script that is not a hash of anything, so there is
            // nothing for an address to abbreviate.
            Descriptor::Pk(_) => Err("pk() pays to a bare public key, which has no address; \
                 use pkh(), wpkh() or tr() instead"
                .to_string()),
            Descriptor::Multi { .. } => Err("a bare multi()/sortedmulti() script has no address; \
                 wrap it in wsh(...) or sh(...)"
                .to_string()),
        }
    }

    fn inner_script(&self, index: u32) -> Result<Vec<u8>, String> {
        match self {
            Descriptor::Sh(inner) | Descriptor::Wsh(inner) => inner.script(index),
            _ => unreachable!("only sh() and wsh() have an inner script"),
        }
    }

    fn output_kind(&self) -> &'static str {
        match self {
            Descriptor::Pk(_) => "bare p2pk (no address)",
            Descriptor::Pkh(_) => "p2pkh",
            Descriptor::Wpkh(_) => "p2wpkh",
            Descriptor::Multi { .. } => "bare multisig (no address)",
            Descriptor::Tr(_) => "p2tr",
            Descriptor::Wsh(_) => "p2wsh",
            Descriptor::Sh(inner) => match **inner {
                Descriptor::Wpkh(_) => "p2sh-p2wpkh",
                Descriptor::Wsh(_) => "p2sh-p2wsh",
                _ => "p2sh",
            },
        }
    }

    fn keys(&self) -> Vec<&KeyExpression> {
        match self {
            Descriptor::Pk(key)
            | Descriptor::Pkh(key)
            | Descriptor::Wpkh(key)
            | Descriptor::Tr(key) => vec![key],
            Descriptor::Sh(inner) | Descriptor::Wsh(inner) => inner.keys(),
            Descriptor::Multi { keys, .. } => keys.iter().collect(),
        }
    }

    /// All keys must be for the same network, or the addresses would be a mix
    /// of mainnet and testnet.
    fn check_networks(&self) -> Result<(), String> {
        let keys = self.keys();
        let network = keys[0].network();
        if keys.iter().any(|key| key.network() != network) {
            return Err("descriptor mixes mainnet and testnet keys".to_string());
        }
        Ok(())
    }
}

fn parse_expression(text: &str, context: Context) -> Result<Descriptor, String> {
    let (name, arguments) = split_function(text)?;
    match name {
        "pk" => Ok(Descriptor::Pk(parse_single_key(name, arguments)?)),
        "pkh" => Ok(Descriptor::Pkh(parse_single_key(name, arguments)?)),
        "wpkh" => {
            // A witness script cannot contain another witness program.
            require_context(name, context, &[Context::Top, Context::Sh])?;
            Ok(Descriptor::Wpkh(parse_single_key(name, arguments)?))
        }
        "sh" => {
            require_context(name, context, &[Context::Top])?;
            Ok(Descriptor::Sh(Box::new(parse_expression(
                single_argument(name, arguments)?,
                Context::Sh,
            )?)))
        }
        "wsh" => {
            require_context(name, context, &[Context::Top, Context::Sh])?;
            Ok(Descriptor::Wsh(Box::new(parse_expression(
                single_argument(name, arguments)?,
                Context::Wsh,
            )?)))
        }
        "multi" | "sortedmulti" => parse_multi(name, arguments, context),
        "tr" => {
            require_context(name, context, &[Context::Top])?;
            if arguments.len() > 1 {
                return Err("tr() with a script tree is not supported, only tr(KEY)".to_string());
            }
            Ok(Descriptor::Tr(parse_single_key(name, arguments)?))
        }
        "combo" | "raw" | "addr" | "rawtr" | "pk_k" | "pk_h" | "multi_a" | "sortedmulti_a" => Err(
            format!("{name}() is a descriptor function this tool does not support"),
        ),
        other => Err(format!("unknown descriptor function: {other}()")),
    }
}

/// Split `name(arg,arg)` into the name and the top-level arguments.
fn split_function(text: &str) -> Result<(&str, Vec<&str>), String> {
    let open = text
        .find('(')
        .ok_or_else(|| format!("expected a descriptor function, got {text:?}"))?;
    if !text.ends_with(')') {
        return Err(format!("missing closing ')' in {text:?}"));
    }
    let name = &text[..open];
    let inside = &text[open + 1..text.len() - 1];
    if name.is_empty() {
        return Err(format!("missing function name in {text:?}"));
    }
    Ok((name, split_arguments(inside)?))
}

/// Split on the commas that are not inside nested parentheses or brackets.
fn split_arguments(inside: &str) -> Result<Vec<&str>, String> {
    let mut arguments = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, ch) in inside.char_indices() {
        match ch {
            '(' | '[' => depth += 1,
            ')' | ']' => {
                depth -= 1;
                if depth < 0 {
                    return Err("unbalanced brackets".to_string());
                }
            }
            ',' if depth == 0 => {
                arguments.push(&inside[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err("unbalanced brackets".to_string());
    }
    arguments.push(&inside[start..]);
    Ok(arguments)
}

fn single_argument<'a>(name: &str, arguments: Vec<&'a str>) -> Result<&'a str, String> {
    match arguments.as_slice() {
        [only] => Ok(only),
        _ => Err(format!(
            "{name}() takes one argument, got {}",
            arguments.len()
        )),
    }
}

fn parse_single_key(name: &str, arguments: Vec<&str>) -> Result<KeyExpression, String> {
    let argument = single_argument(name, arguments)?;
    if argument.contains('(') {
        return Err(format!("{name}() takes a key, not a script"));
    }
    KeyExpression::parse(argument).map_err(|e| format!("in {name}(): {e}"))
}

fn parse_multi(name: &str, arguments: Vec<&str>, context: Context) -> Result<Descriptor, String> {
    let (threshold_text, key_texts) = arguments
        .split_first()
        .ok_or_else(|| format!("{name}() takes a threshold and at least one key"))?;
    let threshold: u8 = threshold_text
        .parse()
        .map_err(|_| format!("invalid {name}() threshold: {threshold_text:?}"))?;

    let keys: Vec<KeyExpression> = key_texts
        .iter()
        .map(|text| KeyExpression::parse(text).map_err(|e| format!("in {name}(): {e}")))
        .collect::<Result<_, _>>()?;

    if keys.is_empty() {
        return Err(format!("{name}() needs at least one key"));
    }
    if threshold == 0 {
        return Err(format!("{name}() threshold must be at least 1"));
    }
    if threshold as usize > keys.len() {
        return Err(format!(
            "{name}() threshold {threshold} is larger than its {} keys",
            keys.len()
        ));
    }
    // OP_CHECKMULTISIG verifies at most 20 keys, and a P2SH redeem script has
    // to fit in 520 bytes, which leaves room for 15 compressed keys.
    let limit = if context == Context::Sh { 15 } else { 20 };
    if keys.len() > limit {
        return Err(format!(
            "{name}() has {} keys, more than the {limit} allowed here",
            keys.len()
        ));
    }

    Ok(Descriptor::Multi {
        threshold,
        keys,
        sorted: name == "sortedmulti",
    })
}

fn require_context(name: &str, context: Context, allowed: &[Context]) -> Result<(), String> {
    if allowed.contains(&context) {
        return Ok(());
    }
    let place = match context {
        Context::Top => "at the top level",
        Context::Sh => "inside sh()",
        Context::Wsh => "inside wsh()",
    };
    Err(format!("{name}() is not allowed {place}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Check a descriptor's scriptPubKeys at indices 0, 1, 2 — the form the
    /// BIP-382/383 test vectors are written in.
    fn check_scripts(descriptor: &str, expected: &[&str]) {
        let parsed =
            WalletDescriptor::parse(descriptor).unwrap_or_else(|e| panic!("{descriptor}: {e}"));
        for (index, want) in expected.iter().enumerate() {
            let script = parsed.script_pubkey(index as u32).unwrap();
            assert_eq!(hex(&script), *want, "{descriptor} at index {index}");
        }
    }

    const XPRV_MASTER: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const XPRV_M0: &str = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt";
    const XPUB_M0: &str = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";

    // BIP-382 test vectors, the ones written with extended keys.
    #[test]
    fn bip382_wpkh_and_sh_wpkh() {
        check_scripts(
            &format!("wpkh([ffffffff/13h]{XPRV_M0}/1/2/0)"),
            &["0014326b2249e3a25d5dc60935f044ee835d090ba859"],
        );
        check_scripts(
            &format!("wpkh([ffffffff/13h]{XPUB_M0}/1/2/*)"),
            &[
                "0014326b2249e3a25d5dc60935f044ee835d090ba859",
                "0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7",
                "00141fa798efd1cbf95cebf912c031b8a4a6e9fb9f27",
            ],
        );
        // The same vector with a hardened wildcard, written both ways.
        for wildcard in ["*'", "*h"] {
            check_scripts(
                &format!("sh(wpkh({XPRV_MASTER}/10/20/30/40/{wildcard}))"),
                &[
                    "a9149a4d9901d6af519b2a23d4a2f51650fcba87ce7b87",
                    "a914bed59fc0024fae941d6e20a3b44a109ae740129287",
                    "a9148483aa1116eb9c05c482a72bada4b1db24af654387",
                ],
            );
        }
    }

    // BIP-383 test vectors, the ones written with extended keys.
    #[test]
    fn bip383_multisig() {
        check_scripts(
            "sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))",
            &["a91445a9a622a8b0a1269944be477640eedc447bbd8487"],
        );
        // sortedmulti() puts the derived keys in order, so the script is the
        // same whichever order the key expressions are written in.
        check_scripts(
            "sortedmulti(2,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/0/*)",
            &[
                "5221025d5fc65ebb8d44a5274b53bac21ff8307fec2334a32df05553459f8b1f7fe1b62102fbd47cc8034098f0e6a94c6aeee8528abf0a2153a5d8e46d325b7284c046784652ae",
                "52210264fd4d1f5dea8ded94c61e9641309349b62f27fbffe807291f664e286bfbe6472103f4ece6dfccfa37b211eb3d0af4d0c61dba9ef698622dc17eecdf764beeb005a652ae",
                "5221022ccabda84c30bad578b13c89eb3b9544ce149787e5b538175b1d1ba259cbb83321024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c52ae",
            ],
        );
        let master2 = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
        check_scripts(
            &format!(
                "wsh(multi(2,{master2}/2147483647'/0,{XPRV_M0}/1/2/*,{XPRV_MASTER}/10/20/30/40/*'))"
            ),
            &[
                "0020b92623201f3bb7c3771d45b2ad1d0351ea8fbf8cfe0a0e570264e1075fa1948f",
                "002036a08bbe4923af41cf4316817c93b8d37e2f635dd25cfff06bd50df6ae7ea203",
                "0020a96e7ab4607ca6b261bfe3245ffda9c746b28d3f59e83d34820ec0e2b36c139c",
            ],
        );
    }

    // BIP-84 test vectors: the reference account's first two receive addresses
    // and first change address.
    #[test]
    fn bip84_native_segwit_addresses() {
        let account = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
        let receive = WalletDescriptor::parse(&format!("wpkh({account}/0/*)")).unwrap();
        assert_eq!(receive.output_kind(), "p2wpkh");
        assert_eq!(
            receive.address(0).unwrap(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(
            receive.address(1).unwrap(),
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        );
        let change = WalletDescriptor::parse(&format!("wpkh({account}/1/*)")).unwrap();
        assert_eq!(
            change.address(0).unwrap(),
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
        );
    }

    // BIP-49 test vector: a testnet P2SH-wrapped segwit address.
    #[test]
    fn bip49_nested_segwit_address() {
        let account = "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY";
        let descriptor = WalletDescriptor::parse(&format!("sh(wpkh({account}/0/*))")).unwrap();
        assert_eq!(descriptor.network(), Network::Testnet);
        assert_eq!(descriptor.output_kind(), "p2sh-p2wpkh");
        assert_eq!(
            descriptor.address(0).unwrap(),
            "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"
        );
    }

    // BIP-86 test vectors: single-key taproot addresses.
    #[test]
    fn bip86_taproot_addresses() {
        let account = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";
        let receive = WalletDescriptor::parse(&format!("tr({account}/0/*)")).unwrap();
        assert_eq!(receive.output_kind(), "p2tr");
        assert_eq!(
            receive.address(0).unwrap(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert_eq!(
            receive.address(1).unwrap(),
            "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
        );
        assert_eq!(
            hex(&receive.script_pubkey(0).unwrap()),
            "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        );
        let change = WalletDescriptor::parse(&format!("tr({account}/1/*)")).unwrap();
        assert_eq!(
            change.address(0).unwrap(),
            "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"
        );
    }

    #[test]
    fn checksum_is_kept_and_completed() {
        let body = format!("wpkh({XPUB_M0}/0/*)");
        let without = WalletDescriptor::parse(&body).unwrap();
        let canonical = without.canonical();
        assert!(canonical.starts_with(&body));
        // Re-parsing the canonical form verifies the checksum we just wrote.
        let with = WalletDescriptor::parse(&canonical).unwrap();
        assert_eq!(with.canonical(), canonical);
        // And a corrupted checksum is caught.
        let corrupted = canonical.replace('#', "#q");
        assert!(WalletDescriptor::parse(&corrupted).is_err());
    }

    // The nesting rules from BIP-382 and BIP-386, with extended keys in place
    // of the raw keys the BIPs use.
    #[test]
    fn rejects_invalid_nesting() {
        for descriptor in [
            format!("wsh(wpkh({XPUB_M0}))"),     // wpkh inside wsh
            format!("wsh(wsh(pkh({XPUB_M0})))"), // wsh inside wsh
            format!("sh(wsh(wsh(pkh({XPUB_M0}))))"),
            format!("wpkh(wsh(pkh({XPUB_M0})))"), // a script where a key goes
            format!("wsh({XPUB_M0})"),            // a key where a script goes
            format!("wsh(tr({XPUB_M0}))"),        // tr is top level only
            format!("sh(tr({XPUB_M0}))"),
            format!("sh(sh(pkh({XPUB_M0})))"), // sh is top level only
            format!("pkh({XPUB_M0}"),          // missing ')'
            format!("nosuch({XPUB_M0})"),      // unknown function
            format!("combo({XPUB_M0})"),       // valid but unsupported
            format!("tr({XPUB_M0},pk({XPUB_M0}))"), // script tree
            format!("pkh({XPUB_M0},{XPUB_M0})"), // too many arguments
        ] {
            assert!(
                WalletDescriptor::parse(&descriptor).is_err(),
                "should be invalid: {descriptor}"
            );
        }
    }

    // BIP-383's invalid multisig cases.
    #[test]
    fn rejects_invalid_multisig() {
        for descriptor in [
            format!("multi(a,{XPUB_M0},{XPUB_M0})"), // non-numeric threshold
            format!("multi(0,{XPUB_M0},{XPUB_M0})"), // threshold of zero
            format!("multi(3,{XPUB_M0},{XPUB_M0})"), // threshold above key count
            format!("sh(multi(16,{}))", vec![XPUB_M0; 16].join(",")), // 16 keys under sh
            format!("wsh(multi(21,{}))", vec![XPUB_M0; 21].join(",")), // 21 keys
        ] {
            assert!(
                WalletDescriptor::parse(&descriptor).is_err(),
                "should be invalid: {descriptor}"
            );
        }
        // 20-of-20 is the most CHECKMULTISIG allows, and it fits under wsh().
        let twenty =
            WalletDescriptor::parse(&format!("wsh(multi(20,{}))", vec![XPUB_M0; 20].join(",")))
                .unwrap();
        assert!(twenty.address(0).unwrap().starts_with("bc1q"));
    }

    #[test]
    fn rejects_mixed_networks() {
        let testnet = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp";
        let mixed = format!("wsh(multi(2,{XPUB_M0}/0/*,{testnet}/0/*))");
        assert!(WalletDescriptor::parse(&mixed).is_err());
    }

    #[test]
    fn bare_scripts_have_no_address() {
        let bare_pk = WalletDescriptor::parse(&format!("pk({XPUB_M0}/0/*)")).unwrap();
        assert!(bare_pk.script_pubkey(0).is_ok());
        assert!(bare_pk.address(0).is_err());

        let bare_multi = WalletDescriptor::parse(&format!("multi(1,{XPUB_M0}/0/*)")).unwrap();
        assert!(bare_multi.script_pubkey(0).is_ok());
        assert!(bare_multi.address(0).is_err());
    }

    // BIP-389: each chain of a multipath descriptor derives exactly what the
    // single-path descriptor it expands into does. Chain 0 here is the BIP-382
    // `wpkh(.../1/2/*)` vector.
    #[test]
    fn multipath_chains_match_their_expansions() {
        let multipath = format!("wpkh([ffffffff/13h]{XPUB_M0}/<1;3>/2/*)");

        let receive = WalletDescriptor::parse(&multipath).unwrap();
        assert_eq!((receive.chain, receive.chain_count), (0, 2));
        assert_eq!(
            hex(&receive.script_pubkey(0).unwrap()),
            "0014326b2249e3a25d5dc60935f044ee835d090ba859"
        );

        let change = WalletDescriptor::parse_chain(&multipath, 1).unwrap();
        assert_eq!((change.chain, change.chain_count), (1, 2));
        let expanded =
            WalletDescriptor::parse(&format!("wpkh([ffffffff/13h]{XPUB_M0}/3/2/*)")).unwrap();
        for index in 0..3 {
            assert_eq!(
                change.script_pubkey(index).unwrap(),
                expanded.script_pubkey(index).unwrap(),
                "index {index}"
            );
            assert_ne!(
                change.address(index).unwrap(),
                receive.address(index).unwrap()
            );
        }
        assert!(WalletDescriptor::parse_chain(&multipath, 2).is_err());
    }

    #[test]
    fn expanded_form_is_a_descriptor_of_its_own() {
        let multipath = format!("wpkh({XPUB_M0}/<0;1>/*)");
        let parsed = WalletDescriptor::parse_chain(&multipath, 1).unwrap();
        let expanded = parsed.expanded_canonical().unwrap();
        assert_eq!(
            expanded,
            format!(
                "wpkh({XPUB_M0}/1/*)#{}",
                checksum::create(&format!("wpkh({XPUB_M0}/1/*)")).unwrap()
            )
        );

        // Re-parsing it is a plain single-path descriptor with the same scripts.
        let reparsed = WalletDescriptor::parse(&expanded).unwrap();
        assert_eq!(reparsed.chain_count, 1);
        assert_eq!(reparsed.expanded_canonical(), None);
        assert_eq!(
            reparsed.script_pubkey(0).unwrap(),
            parsed.script_pubkey(0).unwrap()
        );
    }

    #[test]
    fn descriptors_without_a_wildcard_describe_one_script() {
        let fixed = WalletDescriptor::parse(&format!("wpkh({XPUB_M0}/0/0)")).unwrap();
        assert!(!fixed.has_wildcard());
        // The index is unused, so every index gives the same address.
        assert_eq!(fixed.address(0).unwrap(), fixed.address(5).unwrap());
    }
}
