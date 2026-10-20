//! RIPEMD-160, implemented from scratch per the Dobbertin–Bosselaers–Preneel
//! specification, plus [`hash160`] — the `RIPEMD160(SHA256(x))` Bitcoin uses to
//! shorten public keys and scripts to 20 bytes.
//!
//! Unlike SHA-2, RIPEMD-160 runs *two* independent lines of 80 steps over each
//! block (with different constants, word orders and rotations) and combines
//! both results at the end. Words are little-endian throughout.

use sha256::sha256;

/// Message word index per step, left line: `X[r[j]]` is step `j`'s input word.
#[rustfmt::skip]
const R_LEFT: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

/// Message word index per step, right line.
#[rustfmt::skip]
const R_RIGHT: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

/// Rotation amount per step, left line.
#[rustfmt::skip]
const S_LEFT: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

/// Rotation amount per step, right line.
#[rustfmt::skip]
const S_RIGHT: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

/// Added constant per round (16 steps), left line: 0, then √2, ∛3, ∛5, ∛7
/// scaled by 2³².
const K_LEFT: [u32; 5] = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];

/// Added constant per round, right line: ∛2, ∛3, ∛5, ∛7 scaled by 2³², then 0.
const K_RIGHT: [u32; 5] = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

/// The initial hash state (the same nothing-up-my-sleeve values as MD4/SHA-1).
const H0: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// The nonlinear function for step `j`: a different boolean mix per round.
fn f(j: usize, x: u32, y: u32, z: u32) -> u32 {
    match j / 16 {
        0 => x ^ y ^ z,
        1 => (x & y) | (!x & z),
        2 => (x | !y) ^ z,
        3 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

/// Compute the RIPEMD-160 digest of `data`.
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut h = H0;

    // Padding, as in MD4: 0x80, zeros up to 56 mod 64, then the bit length as a
    // *little-endian* u64.
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for block in msg.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (i, word) in block.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes(word.try_into().unwrap());
        }

        // Both lines start from the current state and run 80 steps. The right
        // line walks the round functions backwards (`f(79 - j)`).
        let [mut al, mut bl, mut cl, mut dl, mut el] = h;
        let [mut ar, mut br, mut cr, mut dr, mut er] = h;

        for j in 0..80 {
            let tl = al
                .wrapping_add(f(j, bl, cl, dl))
                .wrapping_add(x[R_LEFT[j]])
                .wrapping_add(K_LEFT[j / 16])
                .rotate_left(S_LEFT[j])
                .wrapping_add(el);
            al = el;
            el = dl;
            dl = cl.rotate_left(10);
            cl = bl;
            bl = tl;

            let tr = ar
                .wrapping_add(f(79 - j, br, cr, dr))
                .wrapping_add(x[R_RIGHT[j]])
                .wrapping_add(K_RIGHT[j / 16])
                .rotate_left(S_RIGHT[j])
                .wrapping_add(er);
            ar = er;
            er = dr;
            dr = cr.rotate_left(10);
            cr = br;
            br = tr;
        }

        // Combine: each new state word mixes one word from each line, rotated
        // by one position relative to the other.
        h = [
            h[1].wrapping_add(cl).wrapping_add(dr),
            h[2].wrapping_add(dl).wrapping_add(er),
            h[3].wrapping_add(el).wrapping_add(ar),
            h[4].wrapping_add(al).wrapping_add(br),
            h[0].wrapping_add(bl).wrapping_add(cr),
        ];
    }

    let mut out = [0u8; 20];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// HASH160: `RIPEMD160(SHA256(data))`. Bitcoin uses it for public key hashes
/// (P2PKH, P2WPKH) and script hashes (P2SH).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // The specification's own table of test values.
    #[test]
    fn spec_test_values() {
        let cases: [(&[u8], &str); 6] = [
            (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
            (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            (
                b"message digest",
                "5d0689ef49d2fae572b881b123a85ffa21595f36",
            ),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(hex(&ripemd160(input)), expected, "input {input:?}");
        }
    }

    #[test]
    fn one_million_a() {
        // The spec's long-message value; crosses many blocks.
        assert_eq!(
            hex(&ripemd160(&[b'a'; 1_000_000])),
            "52783243c1697bdbe16d37f97f68f08325dc1528"
        );
    }

    // BIP-49 test vectors: keyhash = HASH160(pubkey).
    #[test]
    fn bip49_pubkey_hash() {
        let pubkey = [
            0x03, 0xa1, 0xaf, 0x80, 0x4a, 0xc1, 0x08, 0xa8, 0xa5, 0x17, 0x82, 0x19, 0x8c, 0x2d,
            0x03, 0x4b, 0x28, 0xbf, 0x90, 0xc8, 0x80, 0x3f, 0x5a, 0x53, 0xf7, 0x62, 0x76, 0xfa,
            0x69, 0xa4, 0xea, 0xe7, 0x7f,
        ];
        assert_eq!(
            hex(&hash160(&pubkey)),
            "38971f73930f6c141d977ac4fd4a727c854935b3"
        );
    }
}
