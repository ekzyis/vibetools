//! Arithmetic on secp256k1 scalars — integers modulo the group order `n`.
//!
//! Scalars are kept as 32 big-endian bytes, the form keys and hashes arrive in.
//! Only the operations the key derivation needs are here: a range check and
//! addition, which is all BIP-32 (`k_child = k_parent + IL`) and the taproot
//! tweak ask for.

/// `n`, the order of the generator, big-endian.
pub const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Whether `value` is a valid private key or tweak: in `1..n-1`.
///
/// Zero is excluded because it has no inverse and gives the point at infinity;
/// values at or above `n` are excluded because they are not canonical.
pub fn is_in_range(value: &[u8; 32]) -> bool {
    *value != [0u8; 32] && value[..] < ORDER[..]
}

/// `(a + b) mod n`, for `a` and `b` below `n`.
pub fn add_mod_order(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut sum = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let t = a[i] as u16 + b[i] as u16 + carry;
        sum[i] = t as u8;
        carry = t >> 8;
    }
    // Both inputs are below n, so the sum is below 2n: one subtraction is enough.
    if carry > 0 || sum[..] >= ORDER[..] {
        subtract_order(&mut sum);
    }
    sum
}

fn subtract_order(value: &mut [u8; 32]) {
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let t = value[i] as i16 - ORDER[i] as i16 - borrow;
        value[i] = t as u8;
        borrow = if t < 0 { 1 } else { 0 };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_check() {
        assert!(!is_in_range(&[0u8; 32]));
        assert!(!is_in_range(&ORDER));
        assert!(!is_in_range(&[0xff; 32]));
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(is_in_range(&one));
    }

    #[test]
    fn addition_wraps_at_the_order() {
        let mut one = [0u8; 32];
        one[31] = 1;
        // (n - 1) + 1 == 0 mod n.
        let mut order_minus_1 = ORDER;
        order_minus_1[31] -= 1;
        assert_eq!(add_mod_order(&order_minus_1, &one), [0u8; 32]);
        // (n - 1) + 2 == 1 mod n.
        let mut two = [0u8; 32];
        two[31] = 2;
        assert_eq!(add_mod_order(&order_minus_1, &two), one);
    }
}
