//! Key expressions — the part of a descriptor that names a key (BIP-380
//! "Key Expressions").
//!
//! A key expression is an optional key origin, a key, and an optional
//! derivation path that may end in a `*` wildcard:
//!
//! ```text
//!   [d34db33f/84h/0h/0h]xpub6C.../0/*
//!    └── origin ──────┘ └ key ┘ └ path
//! ```
//!
//! The origin records where the key came from in the owner's master key tree.
//! It is documentation: nothing can be checked against it without the master
//! key, so it does not take part in derivation.
//!
//! The fixed part of the path is walked once when the expression is parsed, so
//! that deriving address `i` costs exactly one child derivation.

use bip32::{ExtendedKey, Network, HARDENED};

/// One element of a derivation path as written in the descriptor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathStep {
    Index(u32),
    /// `*` (or `*h`): stands for the index of the address being derived.
    Wildcard {
        hardened: bool,
    },
}

/// Where a key sits in its owner's master key tree.
pub struct Origin {
    pub fingerprint: [u8; 4],
    pub path: Vec<u32>,
}

pub struct KeyExpression {
    pub origin: Option<Origin>,
    /// The path as written, kept for display.
    pub steps: Vec<PathStep>,
    /// The key with every fixed path step already applied.
    base: ExtendedKey,
    /// `Some(hardened)` if the path ends in a wildcard.
    wildcard: Option<bool>,
}

impl KeyExpression {
    pub fn parse(expression: &str) -> Result<KeyExpression, String> {
        let (origin, rest) = split_origin(expression)?;

        let mut parts = rest.split('/');
        let key_text = parts.next().expect("split yields at least one part");
        if key_text.is_empty() {
            return Err("key expression has no key".to_string());
        }
        if key_text.starts_with('[') {
            return Err("key expression has more than one key origin".to_string());
        }
        let key = ExtendedKey::parse(key_text).map_err(|e| {
            format!("{e} (this tool takes extended keys, i.e. xpub/xprv and the like)")
        })?;

        // Walk the path, which may end in a wildcard.
        let mut steps = Vec::new();
        let mut wildcard = None;
        for part in parts {
            if wildcard.is_some() {
                return Err("a wildcard '*' must be the last path element".to_string());
            }
            let step = match part.strip_prefix('*') {
                Some(suffix) => {
                    let hardened = parse_hardened_marker(suffix)?;
                    wildcard = Some(hardened);
                    PathStep::Wildcard { hardened }
                }
                None => PathStep::Index(parse_index(part)?),
            };
            steps.push(step);
        }

        // Apply the fixed steps now; only the wildcard is left per address.
        let fixed: Vec<u32> = steps
            .iter()
            .filter_map(|step| match step {
                PathStep::Index(index) => Some(*index),
                PathStep::Wildcard { .. } => None,
            })
            .collect();
        let base = key.derive_path(&fixed)?;

        Ok(KeyExpression {
            origin,
            steps,
            base,
            wildcard,
        })
    }

    pub fn has_wildcard(&self) -> bool {
        self.wildcard.is_some()
    }

    pub fn network(&self) -> Network {
        self.base.network()
    }

    /// The compressed public key for address `index`. Without a wildcard the
    /// expression names a single key and the index is not used.
    pub fn public_key(&self, index: u32) -> Result<[u8; 33], String> {
        match self.wildcard {
            None => Ok(self.base.public_key()),
            Some(hardened) => {
                if index >= HARDENED {
                    return Err(format!("address index {index} is out of range"));
                }
                let child = if hardened { index + HARDENED } else { index };
                Ok(self.base.derive_child(child)?.public_key())
            }
        }
    }

    /// The full derivation path for address `index`, from the master key where
    /// an origin says which one: `84h/0h/0h/0/3`.
    pub fn path_at(&self, index: u32) -> String {
        let origin_steps = self
            .origin
            .iter()
            .flat_map(|origin| origin.path.iter().map(|&i| format_index(i)));
        let steps = self.steps.iter().map(|step| match *step {
            PathStep::Index(i) => format_index(i),
            PathStep::Wildcard { hardened } => {
                format_index(if hardened { index + HARDENED } else { index })
            }
        });
        origin_steps.chain(steps).collect::<Vec<_>>().join("/")
    }
}

fn format_index(index: u32) -> String {
    if index >= HARDENED {
        format!("{}h", index - HARDENED)
    } else {
        index.to_string()
    }
}

/// Split a leading `[fingerprint/path]` off a key expression.
fn split_origin(expression: &str) -> Result<(Option<Origin>, &str), String> {
    let Some(rest) = expression.strip_prefix('[') else {
        if expression.contains(']') {
            return Err("key origin is missing its opening '['".to_string());
        }
        return Ok((None, expression));
    };
    let (inside, rest) = rest
        .split_once(']')
        .ok_or_else(|| "key origin is missing its closing ']'".to_string())?;

    let mut parts = inside.split('/');
    let fingerprint_text = parts.next().expect("split yields at least one part");
    if fingerprint_text.len() != 8 || !fingerprint_text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "key origin fingerprint must be 8 hex digits, got {fingerprint_text:?}"
        ));
    }
    let mut fingerprint = [0u8; 4];
    for (byte, text) in fingerprint
        .iter_mut()
        .zip(fingerprint_text.as_bytes().chunks(2))
    {
        *byte = u8::from_str_radix(std::str::from_utf8(text).unwrap(), 16)
            .map_err(|e| format!("bad fingerprint: {e}"))?;
    }

    let mut path = Vec::new();
    for part in parts {
        if part.starts_with('*') {
            return Err("a key origin cannot contain a wildcard".to_string());
        }
        path.push(parse_index(part)?);
    }

    Ok((Some(Origin { fingerprint, path }), rest))
}

/// Parse one path element, e.g. `0`, `44h` or `44'`.
pub(crate) fn parse_index(element: &str) -> Result<u32, String> {
    let digits = element
        .strip_suffix('h')
        .or_else(|| element.strip_suffix('\''))
        .unwrap_or(element);
    let hardened = digits.len() != element.len();

    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid derivation index: {element:?}"));
    }
    let index: u32 = digits
        .parse()
        .map_err(|_| format!("derivation index out of range: {element:?}"))?;
    if index >= HARDENED {
        return Err(format!("derivation index out of range: {element:?}"));
    }
    Ok(index + if hardened { HARDENED } else { 0 })
}

/// Read the hardened marker after a `*`: nothing, `h` or `'`.
fn parse_hardened_marker(suffix: &str) -> Result<bool, String> {
    match suffix {
        "" => Ok(false),
        "h" | "'" => Ok(true),
        other => Err(format!("invalid wildcard: '*{other}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-32 test vector 2, chain m/0, as used by the BIP-382 vectors.
    const XPUB: &str = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";
    const XPRV: &str = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt";

    // BIP-380 "Test Vectors", the key expression cases that use extended keys.
    #[test]
    fn valid_expressions() {
        for expression in [
            XPUB.to_string(),
            format!("[deadbeef/0h/1h/2h]{XPUB}"),
            format!("[deadbeef/0'/1'/2']{XPUB}"),
            format!("[deadbeef/0'/1h/2']{XPUB}"),
            format!("[deadbeef/0h/1h/2h]{XPUB}/3/4/5"),
            format!("[deadbeef/0h/1h/2h]{XPUB}/3/4/5/*"),
            XPRV.to_string(),
            format!("[deadbeef/0h/1h/2h]{XPRV}/3/4/5/*"),
            format!("{XPRV}/3h/4h/5h/*"),
            format!("{XPRV}/3h/4h/5h/*h"),
            format!("[deadbeef/0h/1h/2]{XPRV}/3h/4h/5h/*h"),
        ] {
            KeyExpression::parse(&expression).unwrap_or_else(|e| panic!("{expression}: {e}"));
        }
    }

    // BIP-380's invalid key expressions.
    #[test]
    fn invalid_expressions() {
        for expression in [
            format!("[deadbeef/0h/0h/0h/*]{XPUB}"), // wildcard in the origin
            format!("[deadbeef/0h/0h/0h/]{XPUB}"),  // trailing slash in the origin
            format!("[deadbef/0h/0h/0h]{XPUB}"),    // fingerprint too short
            format!("[deadbeeef/0h/0h/0h]{XPUB}"),  // fingerprint too long
            format!("[deadbeef/0f/0f/0f]{XPUB}"),   // invalid hardened marker
            format!("[deadbeef/-0/-0/-0]{XPUB}"),   // invalid hardened marker
            format!("[deadbeef/0H/0H/0H]{XPUB}"),   // invalid hardened marker
            format!("[deadbeef/0h/1h/2]{XPRV}/3H/4h/5h/*H"), // invalid markers
            format!("[aaaaaaaa][aaaaaaaa]{XPRV}/2147483647'/0"), // two origins
            format!("aaaaaaaa]{XPRV}/2147483647'/0"), // origin without '['
            format!("[gaaaaaaa]{XPRV}/2147483647'/0"), // non-hex fingerprint
            "[deadbeef]".to_string(),               // origin with no key
            format!("{XPRV}/2147483648"),           // index out of range
            format!("{XPRV}/1aa"),                  // invalid index
            format!("{XPUB}/*/0"),                  // wildcard not last
        ] {
            assert!(
                KeyExpression::parse(&expression).is_err(),
                "should be invalid: {expression}"
            );
        }
    }

    #[test]
    fn hardened_steps_need_a_private_key() {
        // BIP-380 allows writing this, but there is no way to derive it.
        let error = KeyExpression::parse(&format!("{XPUB}/3h/4h/5h/*"))
            .err()
            .expect("hardened derivation from an xpub cannot work");
        assert!(error.contains("hardened"), "{error}");
    }

    #[test]
    fn origin_is_recorded_but_not_derived() {
        let plain = KeyExpression::parse(&format!("{XPUB}/1/2/3")).unwrap();
        let with_origin = KeyExpression::parse(&format!("[ffffffff/13h]{XPUB}/1/2/3")).unwrap();
        assert_eq!(
            plain.public_key(0).unwrap(),
            with_origin.public_key(0).unwrap()
        );
        let origin = with_origin.origin.as_ref().unwrap();
        assert_eq!(origin.fingerprint, [0xff, 0xff, 0xff, 0xff]);
        assert_eq!(origin.path, vec![13 + HARDENED]);
        assert_eq!(with_origin.path_at(0), "13h/1/2/3");
    }

    #[test]
    fn wildcard_is_filled_in_per_index() {
        let expression = KeyExpression::parse(&format!("{XPUB}/1/2/*")).unwrap();
        assert!(expression.has_wildcard());
        assert_eq!(expression.path_at(7), "1/2/7");
        assert_ne!(
            expression.public_key(0).unwrap(),
            expression.public_key(1).unwrap()
        );
        // A fixed path and a wildcard that lands on the same index agree.
        let fixed = KeyExpression::parse(&format!("{XPUB}/1/2/0")).unwrap();
        assert_eq!(
            fixed.public_key(0).unwrap(),
            expression.public_key(0).unwrap()
        );
        assert!(!fixed.has_wildcard());
    }

    #[test]
    fn hardened_wildcard_needs_a_private_key() {
        let private = KeyExpression::parse(&format!("{XPRV}/1/2/*h")).unwrap();
        assert_eq!(private.path_at(3), "1/2/3h");
        assert!(private.public_key(3).is_ok());
    }
}
