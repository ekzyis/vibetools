//! Arithmetic in the secp256k1 base field, i.e. modulo
//! `p = 2²⁵⁶ - 2³² - 977`.
//!
//! An element is four 64-bit limbs, least significant first, always held fully
//! reduced (`< p`). Multiplication goes through a 512-bit schoolbook product
//! that is folded back down using the special shape of `p`: since
//! `2²⁵⁶ ≡ 2³² + 977 (mod p)`, the high half can be multiplied by that small
//! constant and added to the low half instead of doing a real division.

/// `p`, the field modulus, as limbs.
const P: [u64; 4] = [
    0xfffffffefffffc2f,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
];

/// `2²⁵⁶ mod p` = `2³² + 977`. The reduction constant.
const C: u128 = 0x1_0000_03d1;

/// `p - 2`, the exponent that inverts a nonzero element (Fermat's little
/// theorem: `a^(p-2) ≡ a⁻¹`), big-endian.
const P_MINUS_2: [u8; 32] =
    hex_const("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d");

/// `(p + 1) / 4`. Because `p ≡ 3 (mod 4)`, `a^((p+1)/4)` is a square root of
/// `a` whenever one exists, big-endian.
const P_PLUS_1_OVER_4: [u8; 32] =
    hex_const("3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c");

/// Parse a 64-character hex literal at compile time, so the exponents above can
/// be written the way the specification prints them.
const fn hex_const(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = hex_digit(bytes[2 * i]) * 16 + hex_digit(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("not a lowercase hex digit"),
    }
}

use std::ops::{Add, Mul, Neg, Sub};

/// An element of the field of integers modulo `p`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fe([u64; 4]);

impl Fe {
    pub const ZERO: Fe = Fe([0, 0, 0, 0]);
    pub const ONE: Fe = Fe([1, 0, 0, 0]);

    /// Build an element from limbs that are already known to be `< p`.
    pub(crate) const fn from_limbs(limbs: [u64; 4]) -> Fe {
        Fe(limbs)
    }

    /// Interpret 32 big-endian bytes as a field element, rejecting values that
    /// are not canonical (`>= p`), as the curve serialization formats require.
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Option<Fe> {
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            // Byte 0 is the most significant, so it fills the *last* limb.
            limbs[3 - i] = u64::from_be_bytes(chunk.try_into().unwrap());
        }
        if cmp(&limbs, &P).is_lt() {
            Some(Fe(limbs))
        } else {
            None
        }
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            out[24 - 8 * i..32 - 8 * i].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    /// Whether the element is odd — the bit a compressed point encodes about y.
    pub fn is_odd(self) -> bool {
        self.0[0] & 1 == 1
    }

    pub fn square(self) -> Fe {
        self * self
    }

    /// `self` raised to a big-endian exponent, by square-and-multiply.
    fn pow(self, exponent: &[u8; 32]) -> Fe {
        let mut result = Fe::ONE;
        for byte in exponent {
            for bit in (0..8).rev() {
                result = result.square();
                if byte >> bit & 1 == 1 {
                    result = result * self;
                }
            }
        }
        result
    }

    /// The multiplicative inverse, or zero for zero.
    pub fn invert(self) -> Fe {
        self.pow(&P_MINUS_2)
    }

    /// A square root, if one exists. Of the two roots this returns whichever
    /// the exponentiation yields; callers pick the parity they want.
    pub fn sqrt(self) -> Option<Fe> {
        let root = self.pow(&P_PLUS_1_OVER_4);
        // Only half the field has square roots, so the candidate must be checked.
        if root.square() == self {
            Some(root)
        } else {
            None
        }
    }
}

// The operators below are the field's arithmetic: every result is reduced
// modulo p, so `Fe` values can be combined with `+`, `-` and `*` and the curve
// formulas read the way they are written on paper.

impl Add for Fe {
    type Output = Fe;

    fn add(self, other: Fe) -> Fe {
        let mut sum = [0u64; 4];
        let mut carry = 0u128;
        for (i, slot) in sum.iter_mut().enumerate() {
            let t = self.0[i] as u128 + other.0[i] as u128 + carry;
            *slot = t as u64;
            carry = t >> 64;
        }
        // A carry out means the true sum is `sum + 2²⁵⁶`, and `2²⁵⁶ ≡ C`.
        if carry > 0 {
            add_small(&mut sum, C);
        }
        reduce_once(&mut sum);
        Fe(sum)
    }
}

impl Sub for Fe {
    type Output = Fe;

    fn sub(self, other: Fe) -> Fe {
        // Add p before subtracting so the intermediate never goes negative.
        let mut diff = [0u64; 4];
        let mut carry = 0i128;
        for i in 0..4 {
            let t = self.0[i] as i128 + P[i] as i128 - other.0[i] as i128 + carry;
            diff[i] = t as u64;
            // t is in -2⁶⁴..2⁶⁵, so this is -1, 0 or 1: a borrow or a carry.
            carry = t >> 64;
        }
        // A carry past limb 3 is a factor of 2²⁵⁶, which folds in as C.
        if carry > 0 {
            add_small(&mut diff, C);
        }
        // `self + p - other` is below 2p, so at most one subtraction is left.
        reduce_once(&mut diff);
        Fe(diff)
    }
}

impl Neg for Fe {
    type Output = Fe;

    fn neg(self) -> Fe {
        if self.is_zero() {
            self
        } else {
            Fe::ZERO - self
        }
    }
}

impl Mul for Fe {
    type Output = Fe;

    fn mul(self, other: Fe) -> Fe {
        // 512-bit schoolbook product, limb by limb.
        let mut wide = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = self.0[i] as u128 * other.0[j] as u128 + wide[i + j] as u128 + carry;
                wide[i + j] = t as u64;
                carry = t >> 64;
            }
            wide[i + 4] = carry as u64;
        }
        Fe(reduce_wide(wide))
    }
}

/// Compare two little-endian limb arrays as integers.
fn cmp(a: &[u64; 4], b: &[u64; 4]) -> std::cmp::Ordering {
    for i in (0..4).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Subtract `p` once if the value is at least `p`.
fn reduce_once(value: &mut [u64; 4]) {
    if cmp(value, &P).is_lt() {
        return;
    }
    let mut borrow = 0i128;
    for i in 0..4 {
        let t = value[i] as i128 - P[i] as i128 - borrow;
        value[i] = t as u64;
        borrow = if t < 0 { 1 } else { 0 };
    }
}

/// Add a value that fits in 128 bits to the low end, wrapping the carry back in
/// through `2²⁵⁶ ≡ C` until nothing is left to carry.
fn add_small(value: &mut [u64; 4], mut addend: u128) {
    while addend != 0 {
        let mut carry = addend;
        for limb in value.iter_mut() {
            let t = *limb as u128 + (carry & u64::MAX as u128);
            *limb = t as u64;
            carry = (carry >> 64) + (t >> 64);
        }
        addend = carry * C;
    }
}

/// Fold a 512-bit product down to a field element.
fn reduce_wide(wide: [u64; 8]) -> [u64; 4] {
    let mut low = [wide[0], wide[1], wide[2], wide[3]];
    let high = [wide[4], wide[5], wide[6], wide[7]];

    // low += high * C, in place, with the overflow past limb 3 kept aside.
    let mut carry = 0u128;
    for i in 0..4 {
        let t = high[i] as u128 * C + low[i] as u128 + carry;
        low[i] = t as u64;
        carry = t >> 64;
    }
    // That overflow sits at the 2²⁵⁶ place, so it folds in as another `* C`.
    add_small(&mut low, carry * C);
    reduce_once(&mut low);
    low
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe(hex: &str) -> Fe {
        Fe::from_be_bytes(&hex_const(hex)).unwrap()
    }

    #[test]
    fn rejects_non_canonical() {
        // p itself and p+1 are not valid field element encodings.
        assert!(Fe::from_be_bytes(&hex_const(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        ))
        .is_none());
        assert!(Fe::from_be_bytes(&hex_const(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30"
        ))
        .is_none());
        // p - 1 is the largest element, and adding one wraps to zero.
        assert!((fe(P_MINUS_1) + Fe::ONE).is_zero());
    }

    #[test]
    fn add_sub_round_trip() {
        let a = fe("00000000000000000000000000000000000000000000000000000000deadbeef");
        let b = fe("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        assert_eq!(a + b - b, a);
        assert_eq!(a - b + b, a);
        assert_eq!(a + -a, Fe::ZERO);
    }

    // The generator's coordinates, as convenient large operands.
    const GX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const GY: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    #[test]
    fn mul_matches_known_products() {
        assert_eq!(
            fe(GX) * fe(GY),
            fe("fd3dc529c6eb60fb9d166034cf3c1a5a72324aa9dfd3428a56d7e1ce0179fd9b")
        );
        assert_eq!(
            fe(GX).square(),
            fe("8550e7d238fcf3086ba9adcf0fb52a9de3652194d06cb5bb38d50229b854fc49")
        );
    }

    #[test]
    fn sub_wraps_both_ways() {
        assert_eq!(
            fe(GX) - fe(GY),
            fe("31838c07d338f746f7fb6699c076025e058448928748d4bfbdaab0cb1be742e0")
        );
        assert_eq!(
            fe(GY) - fe(GX),
            fe("ce7c73f82cc708b9080499663f89fda1fa7bb76d78b72b4042554f33e418b94f")
        );
        assert_eq!(Fe::ZERO - Fe::ONE, fe(P_MINUS_1));
    }

    const P_MINUS_1: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e";

    #[test]
    fn inverse_and_sqrt() {
        let a = fe(GX);
        assert_eq!(a * a.invert(), Fe::ONE);
        assert_eq!(
            a.invert(),
            fe("237afdf1d2938d86870aaeb8ad77626a67b8e794abfb076be61d003687ca9ef6")
        );
        let root = a.square().sqrt().unwrap();
        assert!(root == a || root == -a);
        // 3 is not a quadratic residue modulo this p, so it has no root.
        assert!(
            fe("0000000000000000000000000000000000000000000000000000000000000003")
                .sqrt()
                .is_none()
        );
    }
}
