//! The Boolean part of BABE's garbled circuit (§5.6, steps 1 and 2): from
//! π1's coordinate bits, check the point (x, y < p and y² = x³ + 3), and
//! output the bits of its features `x, y, x², y², xy`; for a point that
//! fails, the generator's. The constant feature `1` needs no bits: the
//! DRE's constant term carries it.

use std::sync::OnceLock;

use ark_bn254::{Fq, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};

use crate::circuit::{Bit, Builder, Circuit};
use crate::field::{self, bits, constant, BITS};

/// The features after the constant: x, y, x², y², xy.
pub const BLOCKS: usize = 5;

/// The circuit's outputs: [`BLOCKS`] of [`BITS`].
pub const OUTPUTS: usize = BLOCKS * BITS;

/// `π`'s features after the constant.
pub fn features(p: &G1Affine) -> [Fq; BLOCKS] {
    let (x, y) = (p.x, p.y);
    [x, y, x * x, y * y, x * y]
}

/// `π`'s coordinates as the circuit takes them, and as π1 is signed: x's
/// bits, then y's, little-endian. The point at infinity is (0, 0).
pub fn input(p: &G1Affine) -> Vec<bool> {
    let (x, y) = p.xy().unwrap_or_default();
    bits(x).into_iter().chain(bits(y)).collect()
}

/// The circuit, built once.
pub fn circuit() -> &'static Circuit {
    static C: OnceLock<Circuit> = OnceLock::new();
    C.get_or_init(build)
}

fn build() -> Circuit {
    let (mut builder, i) = Builder::new(2 * BITS);
    let (x, y) = i.split_at(BITS);
    let b = &mut builder;
    let x2 = field::square_mod(b, x);
    let y2 = field::square_mod(b, y);
    let xy = field::mul_mod(b, x, y);
    // x³ + 3, mod p
    let mut cols = field::product(b, &x2, x);
    cols[0].push(Bit::Const(true));
    cols[1].push(Bit::Const(true));
    let x3 = field::compress(b, cols);
    let x3 = field::reduce(b, x3);
    let p = &Fq::MODULUS.to_bits_le()[..BITS];
    let x_ok = field::lt_const(b, x, p);
    let y_ok = field::lt_const(b, y, p);
    let on = field::eq(b, &y2, &x3);
    let ok = b.and(x_ok, y_ok);
    let ok = b.and(ok, on);
    let fallback = features(&G1Affine::generator());
    let blocks: [&[Bit]; BLOCKS] = [x, y, &x2, &y2, &xy];
    let mut out = Vec::with_capacity(OUTPUTS);
    for (blk, g) in blocks.iter().zip(fallback) {
        for (v, g) in blk.iter().zip(constant(&bits(g))) {
            out.push(b.mux(ok, *v, g));
        }
    }
    builder.finish(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G1Projective;
    use ark_ff::{BigInteger, UniformRand};

    fn expect(p: &G1Affine) -> Vec<bool> {
        features(p).iter().flat_map(|f| bits(*f)).collect()
    }

    #[test]
    fn features_of_points_and_the_fallback() {
        let c = circuit();
        println!("the point gadget: {} ANDs, {} gates", c.ands(), c.gates.len());
        let rng = &mut ark_std::test_rng();
        let g = G1Affine::generator();
        for _ in 0..4 {
            let p: G1Affine = G1Projective::rand(rng).into();
            assert_eq!(c.eval(&input(&p)), expect(&p));
            // off the curve: y + 1
            let mut bad = input(&p);
            let i = bad[BITS..].iter().position(|b| !b).unwrap();
            bad[BITS..BITS + i + 1].iter_mut().for_each(|b| *b = !*b);
            assert_eq!(c.eval(&bad), expect(&g));
        }
        // −g: on the curve, y = p − 2
        assert_eq!(c.eval(&input(&-g)), expect(&-g));
        // infinity, (0, 0): the fallback
        assert_eq!(c.eval(&input(&G1Affine::identity())), expect(&g));
        // −g with x + p for x (1 + p < 2^254): the same point mod p, refused
        let mut x = Fq::MODULUS;
        assert!(!x.add_with_carry(&1u64.into()));
        let mut over = input(&-g);
        over[..BITS].copy_from_slice(&x.to_bits_le()[..BITS]);
        assert_eq!(c.eval(&over), expect(&g));
    }
}
