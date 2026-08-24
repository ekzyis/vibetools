//! Base58 and Base58Check, implemented from scratch.
//!
//! Base58 is base-256 → base-58 with Bitcoin's alphabet (no 0, O, I, l, and no
//! + or / from base64). Base58Check wraps it with a 4-byte double-SHA-256
//! checksum so typos in a copied string are caught.

use sha256::double_sha256;

/// Bitcoin's Base58 alphabet. Index = digit value (0..58).
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode a Base58 string into bytes.
pub fn decode(input: &str) -> Result<Vec<u8>, String> {
    // Big-number approach: treat the string as a base-58 number and repeatedly
    // fold each digit into a base-256 accumulator (`bytes`, big-endian).
    let mut bytes: Vec<u8> = Vec::new();
    for ch in input.bytes() {
        let value = ALPHABET
            .iter()
            .position(|&a| a == ch)
            .ok_or_else(|| format!("invalid base58 character: {:?}", ch as char))?
            as u32;

        // bytes = bytes * 58 + value, with carry propagation.
        let mut carry = value;
        for byte in bytes.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    // Each leading '1' in the input is a leading zero byte (base58 has no
    // separate representation for leading zeros, so they're encoded as '1').
    for ch in input.bytes() {
        if ch == b'1' {
            bytes.insert(0, 0);
        } else {
            break;
        }
    }

    Ok(bytes)
}

/// Encode bytes as a Base58 string (inverse of [`decode`]).
pub fn encode(input: &[u8]) -> String {
    // Big-number approach mirrored: fold each input byte into a base-58
    // accumulator (`digits`, big-endian), then map to the alphabet.
    let mut digits: Vec<u8> = Vec::new();
    for &byte in input {
        let mut carry = byte as u32;
        for d in digits.iter_mut().rev() {
            carry += (*d as u32) * 256;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.insert(0, (carry % 58) as u8);
            carry /= 58;
        }
    }

    // Leading zero bytes become leading '1's.
    let mut out = String::new();
    for &byte in input {
        if byte == 0 {
            out.push('1');
        } else {
            break;
        }
    }
    for d in digits {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

/// Encode a payload as Base58Check: append a 4-byte double-SHA-256 checksum,
/// then Base58-encode the result (inverse of [`decode_check`]).
pub fn encode_check(payload: &[u8]) -> String {
    let mut data = payload.to_vec();
    data.extend_from_slice(&double_sha256(payload)[..4]);
    encode(&data)
}

/// Decode a Base58Check string and verify its checksum, returning the payload
/// (everything except the trailing 4 checksum bytes).
pub fn decode_check(input: &str) -> Result<Vec<u8>, String> {
    let data = decode(input)?;
    if data.len() < 4 {
        return Err("input too short to contain a checksum".to_string());
    }
    let (payload, checksum) = data.split_at(data.len() - 4);

    let expected = &double_sha256(payload)[..4];
    if checksum != expected {
        return Err(format!(
            "bad checksum: found {}, expected {}",
            hex(checksum),
            hex(expected),
        ));
    }
    Ok(payload.to_vec())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_leading_zeros() {
        // '1' maps to a 0x00 byte; three leading '1's => three leading zeros.
        assert_eq!(decode("111").unwrap(), vec![0, 0, 0]);
    }

    #[test]
    fn round_trip_known_value() {
        // Base58 of "hello world" bytes is "StV1DL6CwTryKyV".
        assert_eq!(decode("StV1DL6CwTryKyV").unwrap(), b"hello world");
    }

    #[test]
    fn rejects_invalid_char() {
        assert!(decode("0OIl").is_err());
    }

    #[test]
    fn detects_bad_checksum() {
        // Flip the last character of a valid Base58Check string.
        assert!(decode_check("StV1DL6CwTryKyV").is_err());
    }

    #[test]
    fn encode_decode_round_trip() {
        let payload = b"\x00\x01\x02the quick brown fox\xff\xff";
        assert_eq!(decode(&encode(payload)).unwrap(), payload);
        assert_eq!(decode_check(&encode_check(payload)).unwrap(), payload);
    }
}
