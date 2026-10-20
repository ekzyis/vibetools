//! The descriptor checksum from BIP-380.
//!
//! Like bech32 this is a BCH code, but over the 64-ish characters descriptors
//! are written in rather than 32. Each character contributes two symbols: its
//! position within a group of 32, and — folded in three at a time — which group
//! it came from. That split is what lets the code also catch a character
//! swapped for one that looks similar but sits in a different group.

/// Every character a descriptor may contain, arranged so that characters which
/// are easy to confuse land in different groups of 32.
const INPUT_CHARSET: &str =
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

/// The alphabet the 8-character checksum itself is written in (bech32's).
const CHECKSUM_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Coefficients of the BCH code's generator polynomial.
const GENERATOR: [u64; 5] = [
    0xf5dee51989,
    0xa9fdca3312,
    0x1bab10e32d,
    0x3706b1677a,
    0x644d626ffd,
];

/// Shift one symbol into the checksum register and reduce.
fn polymod(symbols: impl Iterator<Item = u64>) -> u64 {
    let mut checksum = 1u64;
    for value in symbols {
        let top = checksum >> 35;
        checksum = (checksum & 0x7_ffff_ffff) << 5 ^ value;
        for (i, g) in GENERATOR.iter().enumerate() {
            if top >> i & 1 == 1 {
                checksum ^= g;
            }
        }
    }
    checksum
}

/// Turn a descriptor's characters into code symbols, or report the first
/// character that descriptors are not allowed to contain.
fn expand(descriptor: &str) -> Result<Vec<u64>, String> {
    let mut symbols = Vec::new();
    let mut groups = Vec::new();
    for ch in descriptor.chars() {
        let position = INPUT_CHARSET
            .chars()
            .position(|c| c == ch)
            .ok_or_else(|| format!("character {ch:?} cannot appear in a descriptor"))?
            as u64;
        // Low 5 bits: the character's position inside its group of 32.
        symbols.push(position & 31);
        // High bits: which group. Three groups pack into one symbol.
        groups.push(position >> 5);
        if groups.len() == 3 {
            symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
            groups.clear();
        }
    }
    // Whatever group numbers are left over are folded in the same way.
    match groups.len() {
        1 => symbols.push(groups[0]),
        2 => symbols.push(groups[0] * 3 + groups[1]),
        _ => {}
    }
    Ok(symbols)
}

/// The 8-character checksum for a descriptor body (the part before `#`).
pub fn create(descriptor: &str) -> Result<String, String> {
    let symbols = expand(descriptor)?;
    // Eight zero symbols make room for the checksum, as in bech32.
    let checksum = polymod(symbols.into_iter().chain([0; 8])) ^ 1;
    Ok((0..8)
        .map(|i| CHECKSUM_CHARSET[(checksum >> (5 * (7 - i)) & 31) as usize] as char)
        .collect())
}

/// Split a descriptor into its body and checksum, verifying the checksum if one
/// is present. A descriptor without a checksum is accepted — writing one is
/// optional — but a wrong one is an error.
pub fn split(descriptor: &str) -> Result<(&str, String), String> {
    let Some((body, checksum)) = descriptor.split_once('#') else {
        let computed = create(descriptor)?;
        return Ok((descriptor, computed));
    };

    if checksum.contains('#') {
        return Err("descriptor has more than one '#'".to_string());
    }
    if checksum.len() != 8 {
        return Err(format!(
            "checksum must be 8 characters, got {}",
            checksum.len()
        ));
    }
    let computed = create(body)?;
    if checksum != computed {
        return Err(format!(
            "bad checksum: found '{checksum}', expected '{computed}'"
        ));
    }
    Ok((body, computed))
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-380 "Test Vectors", the checksum and character set cases.
    #[test]
    fn valid_checksum() {
        assert_eq!(create("raw(deadbeef)").unwrap(), "89f8spxm");
        assert_eq!(split("raw(deadbeef)#89f8spxm").unwrap().0, "raw(deadbeef)");
    }

    #[test]
    fn missing_checksum_is_filled_in() {
        // No checksum at all is allowed, and we report the one it should have.
        assert_eq!(split("raw(deadbeef)").unwrap().1, "89f8spxm");
    }

    #[test]
    fn rejects_bad_checksums() {
        for descriptor in [
            "raw(deadbeef)#",          // missing
            "raw(deadbeef)#89f8spxmx", // too long
            "raw(deadbeef)#89f8spx",   // too short
            "raw(deedbeef)#89f8spxm",  // error in the payload
            "raw(deedbeef)##9f8spxm",  // error in the checksum
        ] {
            assert!(split(descriptor).is_err(), "should fail: {descriptor}");
        }
    }

    #[test]
    fn rejects_characters_outside_the_charset() {
        assert!(split("raw(Ü)#00000000").is_err());
    }
}
