//! Multipath key expressions (BIP-389).
//!
//! A path element written as a tuple, `/<0;1>/`, stands for several
//! descriptors at once: one per value in the tuple. Wallets use it to keep the
//! receiving and change descriptors — which differ in exactly one path step —
//! as a single string.
//!
//! The specification defines the notation by substitution, and so does this
//! module: it finds the tuples in a descriptor body and writes out the
//! ordinary single-path descriptor for one chain, which the rest of the parser
//! then handles knowing nothing about multipath.

use crate::key::parse_index;

/// One `<a;b;…>` element: where it sits in the body, and the values it stands
/// for, as written.
struct Tuple<'a> {
    start: usize,
    /// Just past the closing `>`.
    end: usize,
    values: Vec<&'a str>,
}

/// How many single-path descriptors a body stands for; 1 if it has no tuples.
pub fn chain_count(body: &str) -> Result<usize, String> {
    Ok(find_tuples(body)?
        .first()
        .map_or(1, |tuple| tuple.values.len()))
}

/// The body with every tuple replaced by its `chain`-th value.
pub fn expand(body: &str, chain: usize) -> Result<String, String> {
    let tuples = find_tuples(body)?;
    let mut expanded = String::with_capacity(body.len());
    let mut copied = 0;
    for tuple in &tuples {
        let value = tuple.values.get(chain).ok_or_else(|| {
            format!(
                "chain {chain} is out of range for a multipath element with {} values",
                tuple.values.len()
            )
        })?;
        expanded.push_str(&body[copied..tuple.start]);
        expanded.push_str(value);
        copied = tuple.end;
    }
    expanded.push_str(&body[copied..]);
    Ok(expanded)
}

/// Locate the tuples in a body, rejecting the ones BIP-389 does not allow.
fn find_tuples(body: &str) -> Result<Vec<Tuple<'_>>, String> {
    let bytes = body.as_bytes();
    let mut tuples: Vec<Tuple> = Vec::new();
    let mut in_origin = false;
    // Tuples live inside key expressions, which `(`, `)` and `,` separate.
    let mut tuples_in_expression = 0;

    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => in_origin = true,
            b']' => in_origin = false,
            b'(' | b')' | b',' => tuples_in_expression = 0,
            b'>' => return Err("multipath element has a '>' with no '<'".to_string()),
            b'<' => {
                if in_origin {
                    return Err("a key origin cannot contain a multipath element".to_string());
                }
                let closing = body[i..]
                    .find('>')
                    .ok_or_else(|| "multipath element is missing its closing '>'".to_string())?;
                let end = i + closing + 1;
                let inside = &body[i + 1..end - 1];

                let values: Vec<&str> = inside.split(';').collect();
                if values.len() < 2 {
                    return Err(format!(
                        "a multipath element needs at least two values, got '<{inside}>'"
                    ));
                }
                let mut seen = Vec::with_capacity(values.len());
                for value in &values {
                    let index = parse_index(value)?;
                    if seen.contains(&index) {
                        return Err(format!("multipath element '<{inside}>' uses {value} twice"));
                    }
                    seen.push(index);
                }

                tuples_in_expression += 1;
                if tuples_in_expression > 1 {
                    return Err(
                        "a key expression may contain only one multipath element".to_string()
                    );
                }
                tuples.push(Tuple {
                    start: i,
                    end,
                    values,
                });
                i = end;
                continue;
            }
            _ => {}
        }
        i += 1;
    }

    // Every tuple is stepped through together, so they must agree in length.
    if let Some(first) = tuples.first() {
        if let Some(other) = tuples
            .iter()
            .find(|tuple| tuple.values.len() != first.values.len())
        {
            return Err(format!(
                "multipath elements have different lengths: {} and {}",
                first.values.len(),
                other.values.len()
            ));
        }
    }
    Ok(tuples)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
    const B: &str = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y";
    const C: &str = "xpub661MyMwAqRbcGDZQUKLqmWodYLcoBQnQH33yYkkF3jjxeLvY8qr2wWGEWkiKFaaQfJCoi3HeEq3Dc5DptfbCyjD38fNhSqtKc1UHaP4ba3t";
    const XPRV: &str = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
    const XPUB_V2: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
    const XPUB_M0: &str = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";

    /// Check a BIP-389 vector: the body expands into exactly these descriptors.
    fn check_expansion(body: &str, expected: &[String]) {
        assert_eq!(chain_count(body).unwrap(), expected.len(), "{body}");
        for (chain, want) in expected.iter().enumerate() {
            assert_eq!(&expand(body, chain).unwrap(), want, "{body} chain {chain}");
        }
        assert!(expand(body, expected.len()).is_err(), "chain past the end");
    }

    // BIP-389 "Test Vectors": valid multipath descriptors and what they expand
    // into.
    #[test]
    fn expands_spec_vectors() {
        check_expansion(
            &format!("pk({B}/<0;1>)"),
            &[format!("pk({B}/0)"), format!("pk({B}/1)")],
        );
        check_expansion(
            &format!("pkh({XPRV}/<2147483647h;0>/0)"),
            &[
                format!("pkh({XPRV}/2147483647h/0)"),
                format!("pkh({XPRV}/0/0)"),
            ],
        );
        check_expansion(
            &format!("wpkh([ffffffff/13h]{XPUB_M0}/<1;3>/2/*)"),
            &[
                format!("wpkh([ffffffff/13h]{XPUB_M0}/1/2/*)"),
                format!("wpkh([ffffffff/13h]{XPUB_M0}/3/2/*)"),
            ],
        );
        check_expansion(
            &format!("multi(2,{A}/<1;2>/*,{B}/<3;4>/0/*)"),
            &[
                format!("multi(2,{A}/1/*,{B}/3/0/*)"),
                format!("multi(2,{A}/2/*,{B}/4/0/*)"),
            ],
        );
        check_expansion(
            &format!("pkh({XPUB_V2}/<0;1;2>)"),
            &[
                format!("pkh({XPUB_V2}/0)"),
                format!("pkh({XPUB_V2}/1)"),
                format!("pkh({XPUB_V2}/2)"),
            ],
        );
        check_expansion(
            &format!("sh(multi(2,{A}/<1;2;3>/0/*,{B}/0/*,{C}/0/0/<3;4;5>/*))"),
            &[
                format!("sh(multi(2,{A}/1/0/*,{B}/0/*,{C}/0/0/3/*))"),
                format!("sh(multi(2,{A}/2/0/*,{B}/0/*,{C}/0/0/4/*))"),
                format!("sh(multi(2,{A}/3/0/*,{B}/0/*,{C}/0/0/5/*))"),
            ],
        );
    }

    // BIP-389's invalid descriptors. They are checked here rather than through
    // a full parse so that each one fails for its multipath reason.
    #[test]
    fn rejects_spec_invalid_vectors() {
        for body in [
            format!("pkh({XPRV}/<0;1>/<2;3>)"), // two tuples in one key
            format!("pkh([deadbeef/<0;1>]{XPUB_V2}/0)"), // tuple in the origin
            format!("tr({A}/<6;7;8;9>/*,{{pk({A}/<1;2;3>/0/*),pk({A}/0/0/<3;4;5>/*)}})"),
            format!("sh(multi(2,{XPRV}/<1;2;3>/0/*,{XPRV}/0/*,{XPRV}/0/0/<3;4>/*))"),
            format!("wpkh({A}/<>/*)"),   // empty tuple
            format!("wpkh({A}/0>/*)"),   // missing start
            format!("wpkh({A}/<0/*)"),   // missing end
            format!("wpkh({A}/<0;>/*)"), // missing index
        ] {
            assert!(chain_count(&body).is_err(), "should be invalid: {body}");
        }
    }

    #[test]
    fn rejects_duplicate_and_lone_values() {
        assert!(chain_count(&format!("wpkh({A}/<0;0>/*)")).is_err());
        assert!(chain_count(&format!("wpkh({A}/<0>/*)")).is_err());
        // Differently written steps are different steps, not duplicates.
        assert!(chain_count(&format!("wpkh({A}/<0;0h>/*)")).is_ok());
    }

    #[test]
    fn leaves_single_path_bodies_alone() {
        let body = format!("wpkh({A}/0/*)");
        assert_eq!(chain_count(&body).unwrap(), 1);
        assert_eq!(expand(&body, 0).unwrap(), body);
        assert!(expand(&body, 1).is_ok(), "no tuple to run out of values");
    }
}
