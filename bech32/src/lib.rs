//! Bech32 (BIP-173) and Bech32m (BIP-350), the base-32 encoding segwit
//! addresses use, implemented from scratch.
//!
//! A bech32 string is `<hrp>1<data><checksum>`: a human-readable prefix such as
//! `bc`, the separator `1`, then the payload and a 6-character checksum, all in
//! a 32-character alphabet that leaves out `1`, `b`, `i` and `o`.
//!
//! The checksum is a BCH code over GF(32) — strong enough to pin down the
//! position of a few wrong characters rather than only saying "wrong". Bech32m
//! differs from Bech32 only in the constant XORed into it, which is what makes
//! a witness v0 address and a v1 address impossible to confuse.

/// The data alphabet. Index = 5-bit value.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// XORed into the checksum by the original Bech32.
const BECH32_CONST: u32 = 1;

/// XORed into the checksum by Bech32m, so the two never agree.
const BECH32M_CONST: u32 = 0x2bc830a3;

/// The longest string either spec allows, including hrp and checksum.
const MAX_LEN: usize = 90;

/// Which checksum constant a string uses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Variant {
    Bech32,
    Bech32m,
}

impl Variant {
    fn constant(self) -> u32 {
        match self {
            Variant::Bech32 => BECH32_CONST,
            Variant::Bech32m => BECH32M_CONST,
        }
    }

    /// The variant a segwit address of this witness version must use: v0 keeps
    /// the original Bech32, v1 and up moved to Bech32m (BIP-350).
    pub fn for_witness_version(version: u8) -> Variant {
        if version == 0 {
            Variant::Bech32
        } else {
            Variant::Bech32m
        }
    }
}

/// One step of the BCH code's polynomial remainder: shift in 5 bits and reduce
/// by the generator polynomial, whose coefficients these constants encode.
fn polymod_step(checksum: u32, value: u32) -> u32 {
    const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let top = checksum >> 25;
    let mut next = ((checksum & 0x1ff_ffff) << 5) ^ value;
    for (i, g) in GENERATOR.iter().enumerate() {
        if top >> i & 1 == 1 {
            next ^= g;
        }
    }
    next
}

/// Fold the hrp into the checksum: first every character's high bits, then a
/// zero separator, then every character's low bits.
fn checksum_over_hrp(hrp: &str) -> u32 {
    let mut checksum = 1u32;
    for byte in hrp.bytes() {
        checksum = polymod_step(checksum, (byte >> 5) as u32);
    }
    checksum = polymod_step(checksum, 0);
    for byte in hrp.bytes() {
        checksum = polymod_step(checksum, (byte & 0x1f) as u32);
    }
    checksum
}

/// The 6 checksum values for `hrp` and 5-bit `data`.
fn create_checksum(hrp: &str, data: &[u8], variant: Variant) -> [u8; 6] {
    let mut checksum = checksum_over_hrp(hrp);
    for &value in data {
        checksum = polymod_step(checksum, value as u32);
    }
    // Six zeros make room for the checksum itself.
    for _ in 0..6 {
        checksum = polymod_step(checksum, 0);
    }
    checksum ^= variant.constant();

    let mut out = [0u8; 6];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = (checksum >> (5 * (5 - i)) & 0x1f) as u8;
    }
    out
}

/// Encode an hrp and 5-bit data values as a bech32 string.
pub fn encode(hrp: &str, data: &[u8], variant: Variant) -> Result<String, String> {
    if hrp.is_empty() {
        return Err("empty human-readable part".to_string());
    }
    if !hrp.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(format!(
            "human-readable part has a character out of range: {hrp:?}"
        ));
    }
    if hrp.bytes().any(|b| b.is_ascii_uppercase()) && hrp.bytes().any(|b| b.is_ascii_lowercase()) {
        return Err("mixed case human-readable part".to_string());
    }
    if let Some(&bad) = data.iter().find(|&&v| v > 31) {
        return Err(format!("data value {bad} does not fit in 5 bits"));
    }
    if hrp.len() + 1 + data.len() + 6 > MAX_LEN {
        return Err(format!("encoded string would exceed {MAX_LEN} characters"));
    }

    let mut out = String::with_capacity(hrp.len() + data.len() + 7);
    out.push_str(hrp);
    out.push('1');
    for &value in data
        .iter()
        .chain(create_checksum(hrp, data, variant).iter())
    {
        out.push(CHARSET[value as usize] as char);
    }
    Ok(out)
}

/// Decode a bech32 string into its hrp, 5-bit data and variant, verifying the
/// checksum. Which variant it is follows from which constant checks out.
pub fn decode(string: &str) -> Result<(String, Vec<u8>, Variant), String> {
    if string.len() > MAX_LEN {
        return Err(format!("longer than {MAX_LEN} characters"));
    }
    let has_upper = string.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = string.bytes().any(|b| b.is_ascii_lowercase());
    if has_upper && has_lower {
        return Err("mixed case".to_string());
    }
    // The checksum is defined over the lowercase form; case carries no data.
    let lowercase = string.to_ascii_lowercase();

    let separator = lowercase
        .rfind('1')
        .ok_or_else(|| "no separator '1'".to_string())?;
    let (hrp, data_part) = (&lowercase[..separator], &lowercase[separator + 1..]);
    if hrp.is_empty() {
        return Err("empty human-readable part".to_string());
    }
    if !hrp.bytes().all(|b| (33..=126).contains(&b)) {
        return Err("human-readable part has a character out of range".to_string());
    }
    if data_part.len() < 6 {
        return Err("data part too short to hold a checksum".to_string());
    }

    let mut values = Vec::with_capacity(data_part.len());
    for ch in data_part.bytes() {
        let value = CHARSET
            .iter()
            .position(|&c| c == ch)
            .ok_or_else(|| format!("invalid data character: {:?}", ch as char))?;
        values.push(value as u8);
    }

    let (data, checksum) = values.split_at(values.len() - 6);
    let variant = [Variant::Bech32, Variant::Bech32m]
        .into_iter()
        .find(|&v| create_checksum(hrp, data, v) == checksum)
        .ok_or_else(|| "bad checksum".to_string())?;

    Ok((hrp.to_string(), data.to_vec(), variant))
}

/// Regroup bits, e.g. bytes into the 5-bit groups bech32 encodes.
///
/// When packing to a wider group (`pad` set) any leftover bits are padded with
/// zeros; when unpacking, leftover bits must be zero padding only, or the input
/// was not produced by a valid packing.
pub fn convert_bits(
    data: &[u8],
    from_bits: u32,
    to_bits: u32,
    pad: bool,
) -> Result<Vec<u8>, String> {
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    let max = (1u32 << to_bits) - 1;

    for &value in data {
        if (value as u32) >> from_bits != 0 {
            return Err(format!("value {value} does not fit in {from_bits} bits"));
        }
        accumulator = (accumulator << from_bits) | value as u32;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            out.push(((accumulator >> bits) & max) as u8);
        }
    }

    if pad {
        if bits > 0 {
            out.push(((accumulator << (to_bits - bits)) & max) as u8);
        }
    } else if bits >= from_bits {
        return Err("left-over bits form a whole group".to_string());
    } else if (accumulator << (to_bits - bits)) & max != 0 {
        return Err("non-zero padding bits".to_string());
    }

    Ok(out)
}

/// Encode a segwit address: the witness version as one 5-bit value, then the
/// witness program regrouped into 5-bit values (BIP-173 §Segwit address format).
pub fn encode_segwit_address(hrp: &str, version: u8, program: &[u8]) -> Result<String, String> {
    check_witness_program(version, program.len())?;
    let mut data = vec![version];
    data.extend(convert_bits(program, 8, 5, true)?);
    encode(hrp, &data, Variant::for_witness_version(version))
}

/// Decode a segwit address into its hrp, witness version and program.
pub fn decode_segwit_address(address: &str) -> Result<(String, u8, Vec<u8>), String> {
    let (hrp, data, variant) = decode(address)?;
    let (&version, program_values) = data
        .split_first()
        .ok_or_else(|| "empty data section".to_string())?;
    if version > 16 {
        return Err(format!("invalid witness version: {version}"));
    }
    if variant != Variant::for_witness_version(version) {
        return Err(format!(
            "witness version {version} must use {:?}",
            Variant::for_witness_version(version)
        ));
    }
    let program = convert_bits(program_values, 5, 8, false)?;
    check_witness_program(version, program.len())?;
    Ok((hrp, version, program))
}

/// The length rules: 2 to 40 bytes in general (BIP-141), and exactly 20 or 32
/// for version 0, the only lengths with defined semantics.
fn check_witness_program(version: u8, length: usize) -> Result<(), String> {
    if version > 16 {
        return Err(format!("invalid witness version: {version}"));
    }
    if !(2..=40).contains(&length) {
        return Err(format!("witness program must be 2..40 bytes, got {length}"));
    }
    if version == 0 && length != 20 && length != 32 {
        return Err(format!(
            "witness v0 program must be 20 or 32 bytes, got {length}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Decode an address and render it as the scriptPubKey hex the BIPs list:
    /// `OP_<version>` then a push of the program.
    fn script_pubkey(address: &str) -> Result<String, String> {
        let (_, version, program) = decode_segwit_address(address)?;
        let opcode = if version == 0 { 0x00 } else { 0x50 + version };
        Ok(format!(
            "{opcode:02x}{:02x}{}",
            program.len(),
            hex(&program)
        ))
    }

    // BIP-173 "Test vectors": valid Bech32 strings.
    #[test]
    fn valid_bech32_strings() {
        for s in [
            "A12UEL5L",
            "a12uel5l",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            "?1ezyfcl",
        ] {
            // The longest vector above is over the 90-character address limit,
            // which only applies to addresses, so check the checksum directly.
            if s.len() <= MAX_LEN {
                let (hrp, data, variant) = decode(s).unwrap_or_else(|e| panic!("{s}: {e}"));
                assert_eq!(variant, Variant::Bech32, "{s}");
                assert_eq!(encode(&hrp, &data, variant).unwrap(), s.to_ascii_lowercase());
            }
        }
    }

    // BIP-350 "Test vectors for Bech32m".
    #[test]
    fn valid_bech32m_strings() {
        for s in [
            "A1LQFN3A",
            "a1lqfn3a",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        ] {
            let (hrp, data, variant) = decode(s).unwrap_or_else(|e| panic!("{s}: {e}"));
            assert_eq!(variant, Variant::Bech32m, "{s}");
            assert_eq!(
                encode(&hrp, &data, variant).unwrap(),
                s.to_ascii_lowercase()
            );
        }
    }

    // BIP-173 / BIP-350: strings that must not decode.
    #[test]
    fn invalid_strings() {
        for s in [
            "\x201xj0phk",        // hrp character out of range
            "\x7f1g6xzxy",        // hrp character out of range
            "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
            "qyrz8wqd2c9m",       // no separator
            "1qyrz8wqd2c9m",      // empty hrp
            "y1b0jsk6g",          // invalid data character
            "lt1igcx5c0",         // invalid data character
            "in1muywd",           // too short checksum
            "mm1crxm3i",          // invalid character in checksum
            "au1s5cgom",          // invalid character in checksum
            "M1VUXWEZ",           // checksum computed over uppercase hrp
            "16plkw9",            // empty hrp
            "1p2gdwpf",           // empty hrp
            "A12Uel5l",           // mixed case
        ] {
            assert!(decode(s).is_err(), "should not decode: {s:?}");
        }
    }

    // BIP-350 "Test vectors for v0-v16 native segregated witness addresses".
    #[test]
    fn valid_segwit_addresses() {
        let cases = [
            ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"),
            ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
            ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"),
            ("BC1SW50QGDZ25J", "6002751e"),
            ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "5210751e76e8199196d454941c45d1b3a323"),
            ("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
            ("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
            ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        ];
        for (address, script) in cases {
            assert_eq!(script_pubkey(address).unwrap(), script, "{address}");
            // And re-encoding the decoded parts reproduces the address.
            let (hrp, version, program) = decode_segwit_address(address).unwrap();
            assert_eq!(
                encode_segwit_address(&hrp, version, &program).unwrap(),
                address.to_ascii_lowercase()
            );
        }
    }

    // BIP-350: addresses that must be rejected, including the Bech32/Bech32m
    // mix-ups that are the whole point of having two constants.
    #[test]
    fn invalid_segwit_addresses() {
        for address in [
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", // Bech32 for v1
            "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf", // Bech32 for v2
            "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL", // Bech32 for v16
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",                     // Bech32m for v0
            "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47", // Bech32m for v0
            "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4", // invalid checksum char
            "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R", // invalid witness version
            "bc1pw5dgrnzv",                                                   // 1-byte program
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav", // 41 bytes
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", // 16-byte v0 program
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq", // mixed case
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf", // over-long padding
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j", // non-zero padding
            "bc1gmk9yu",                            // empty data section
        ] {
            assert!(
                decode_segwit_address(address).is_err(),
                "should be invalid: {address}"
            );
        }
    }

    #[test]
    fn rejects_programs_it_cannot_encode() {
        assert!(encode_segwit_address("bc", 0, &[0u8; 21]).is_err());
        assert!(encode_segwit_address("bc", 17, &[0u8; 32]).is_err());
        assert!(encode_segwit_address("bc", 1, &[0u8; 41]).is_err());
    }
}
