//! Points on the secp256k1 curve `y² = x³ + 7`.
//!
//! Points are stored in affine coordinates, so every addition needs a field
//! inversion. That is slower than the projective coordinates a production
//! library uses, but it is the arithmetic as the textbook states it, and
//! deriving a few addresses needs only a handful of scalar multiplications.

use std::ops::Add;

use crate::field::Fe;
use crate::scalar;

/// The curve constant `b` in `y² = x³ + ax + b`; secp256k1 has `a = 0, b = 7`.
const B: Fe = Fe::from_limbs([7, 0, 0, 0]);

/// The generator `G`, whose order is [`scalar::ORDER`].
const GENERATOR: Point = Point::Affine {
    x: Fe::from_limbs([
        0x59f2815b16f81798,
        0x029bfcdb2dce28d9,
        0x55a06295ce870b07,
        0x79be667ef9dcbbac,
    ]),
    y: Fe::from_limbs([
        0x9c47d08ffb10d4b8,
        0xfd17b448a6855419,
        0x5da4fbfc0e1108a8,
        0x483ada7726a3c465,
    ]),
};

/// A curve point: either a finite `(x, y)` or the identity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Point {
    /// The point at infinity, the group's identity element.
    Infinity,
    Affine {
        x: Fe,
        y: Fe,
    },
}

impl Point {
    pub const fn generator() -> Point {
        GENERATOR
    }

    pub fn is_infinity(self) -> bool {
        self == Point::Infinity
    }

    /// Whether the coordinates satisfy the curve equation.
    pub fn is_on_curve(self) -> bool {
        match self {
            Point::Infinity => true,
            Point::Affine { x, y } => y.square() == x.square() * x + B,
        }
    }

    pub fn negate(self) -> Point {
        match self {
            Point::Infinity => Point::Infinity,
            Point::Affine { x, y } => Point::Affine { x, y: -y },
        }
    }

    /// Doubling uses the tangent at the point instead of a chord.
    pub fn double(self) -> Point {
        let Point::Affine { x, y } = self else {
            return Point::Infinity;
        };
        if y.is_zero() {
            // A vertical tangent: the third intersection is infinity.
            return Point::Infinity;
        }
        // λ = 3x² / 2y, the derivative of the curve equation at (x, y).
        let three_x_squared = x.square() * Fe::from_limbs([3, 0, 0, 0]);
        let lambda = three_x_squared * (y + y).invert();
        Point::from_slope(lambda, x, y, x)
    }

    /// The third intersection of a line of slope `lambda` through `(x1, y1)`
    /// and `x2`, reflected over the x-axis: `x3 = λ² - x1 - x2`,
    /// `y3 = λ(x1 - x3) - y1`.
    fn from_slope(lambda: Fe, x1: Fe, y1: Fe, x2: Fe) -> Point {
        let x3 = lambda.square() - x1 - x2;
        let y3 = lambda * (x1 - x3) - y1;
        Point::Affine { x: x3, y: y3 }
    }

    /// `scalar * self`, by double-and-add over the big-endian scalar's bits.
    pub fn multiply(self, scalar: &[u8; 32]) -> Point {
        let mut result = Point::Infinity;
        for byte in scalar {
            for bit in (0..8).rev() {
                result = result.double();
                if byte >> bit & 1 == 1 {
                    result = result + self;
                }
            }
        }
        result
    }

    /// The public key for a private key: `secret * G`.
    ///
    /// Returns `None` unless the secret is in `1..n-1`.
    pub fn from_secret(secret: &[u8; 32]) -> Option<Point> {
        if !scalar::is_in_range(secret) {
            return None;
        }
        Some(GENERATOR.multiply(secret))
    }

    /// Parse a 33-byte compressed SEC1 encoding: a `0x02`/`0x03` prefix giving
    /// y's parity, then x. y is recovered as `√(x³ + 7)`.
    pub fn from_compressed(bytes: &[u8; 33]) -> Option<Point> {
        let wants_odd_y = match bytes[0] {
            0x02 => false,
            0x03 => true,
            _ => return None,
        };
        let x = Fe::from_be_bytes(&bytes[1..33].try_into().unwrap())?;
        let y = (x.square() * x + B).sqrt()?;
        let y = if y.is_odd() == wants_odd_y { y } else { -y };
        Some(Point::Affine { x, y })
    }

    pub fn to_compressed(self) -> Option<[u8; 33]> {
        let Point::Affine { x, y } = self else {
            return None;
        };
        let mut out = [0u8; 33];
        out[0] = if y.is_odd() { 0x03 } else { 0x02 };
        out[1..].copy_from_slice(&x.to_be_bytes());
        Some(out)
    }

    /// BIP-340 `lift_x`: the point with this x coordinate and even y.
    pub fn lift_x(x_only: &[u8; 32]) -> Option<Point> {
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(x_only);
        Point::from_compressed(&compressed)
    }

    /// The x coordinate alone, as taproot keys are serialized.
    pub fn x_only(self) -> Option<[u8; 32]> {
        match self {
            Point::Infinity => None,
            Point::Affine { x, .. } => Some(x.to_be_bytes()),
        }
    }
}

/// The group law. Adding a point to its own negation gives infinity, and adding
/// a point to itself falls through to [`Point::double`].
impl Add for Point {
    type Output = Point;

    fn add(self, other: Point) -> Point {
        let (Point::Affine { x: x1, y: y1 }, Point::Affine { x: x2, y: y2 }) = (self, other) else {
            // Infinity is the identity, so the other operand passes through.
            return if self.is_infinity() { other } else { self };
        };

        if x1 == x2 {
            return if y1 == y2 {
                self.double()
            } else {
                Point::Infinity
            };
        }

        // The chord through both points: slope λ = (y2 - y1) / (x2 - x1).
        let lambda = (y2 - y1) * (x2 - x1).invert();
        Point::from_slope(lambda, x1, y1, x2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn secret(value: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = value;
        s
    }

    #[test]
    fn generator_is_on_curve() {
        assert!(GENERATOR.is_on_curve());
        assert_eq!(
            hex(&GENERATOR.to_compressed().unwrap()),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    /// Multiples of G, from the widely published secp256k1 multiples table.
    #[test]
    fn small_multiples() {
        let expected = [
            (
                1,
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
            (
                2,
                "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            ),
            (
                3,
                "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            ),
            (
                4,
                "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
            ),
            (
                5,
                "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
            ),
        ];
        for (k, compressed) in expected {
            let point = Point::from_secret(&secret(k)).unwrap();
            assert!(point.is_on_curve());
            assert_eq!(hex(&point.to_compressed().unwrap()), compressed, "{k}G");
        }
    }

    #[test]
    fn group_law_holds() {
        let g = GENERATOR;
        let two_g = g.double();
        assert_eq!(g + g, two_g);
        assert_eq!(two_g + g, Point::from_secret(&secret(3)).unwrap());
        assert_eq!(g + g.negate(), Point::Infinity);
        assert_eq!(g + Point::Infinity, g);
        // n * G is the identity, since n is G's order.
        assert_eq!(g.multiply(&scalar::ORDER), Point::Infinity);
    }

    #[test]
    fn compressed_round_trip_recovers_y() {
        for k in 1..6u8 {
            let point = Point::from_secret(&secret(k)).unwrap();
            let bytes = point.to_compressed().unwrap();
            assert_eq!(Point::from_compressed(&bytes).unwrap(), point);
        }
    }

    #[test]
    fn lift_x_picks_even_y() {
        let point = Point::from_secret(&secret(7)).unwrap();
        let lifted = Point::lift_x(&point.x_only().unwrap()).unwrap();
        let Point::Affine { y, .. } = lifted else {
            panic!("lifted to infinity")
        };
        assert!(!y.is_odd());
        assert!(lifted == point || lifted == point.negate());
    }

    #[test]
    fn rejects_x_with_no_curve_point() {
        // x = 7 has no y on this curve.
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[32] = 7;
        assert!(Point::from_compressed(&compressed).is_none());
    }

    #[test]
    fn rejects_out_of_range_secret() {
        assert!(Point::from_secret(&[0u8; 32]).is_none());
        assert!(Point::from_secret(&scalar::ORDER).is_none());
    }
}
