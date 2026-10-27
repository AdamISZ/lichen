//! BN254's base field in gates: what the point check and the feature
//! bits need (BABE §5.6, steps 1 and 2). Numbers are bits, little-endian.
//!
//! Sums go through columns of bits compressed by full adders, one AND a
//! bit removed; a product is its partial products' columns. Reduction
//! folds the bits above 2^254 back as their residues `2^w mod p` (no AND:
//! a residue is a constant, its 1-bits the wire), until the value is under
//! 2^257 < 16p, then subtracts 8p, 4p, 2p and p where they fit. Schoolbook,
//! not Karatsuba: correct first, smaller later.

use ark_bn254::Fq;
use ark_ff::{BigInteger, Field, PrimeField};

use crate::circuit::{Bit, Builder};

/// The bits of an element of Fq (and of Fr): 254.
pub const BITS: usize = 254;

pub type Num = Vec<Bit>;

/// `f`'s canonical bits, [`BITS`] of them.
pub fn bits(f: Fq) -> Vec<bool> {
    let mut b = f.into_bigint().to_bits_le();
    b.truncate(BITS);
    b
}

pub fn constant(bits: &[bool]) -> Num {
    bits.iter().map(|b| Bit::Const(*b)).collect()
}

/// `2^w mod p`'s bits.
fn residue(w: usize) -> Vec<bool> {
    bits(Fq::from(2u64).pow([w as u64]))
}

/// `2^k·p`'s bits, as many as it needs.
fn multiple(k: usize) -> Vec<bool> {
    let mut b = vec![false; k];
    b.extend(Fq::MODULUS.to_bits_le());
    while b.last() == Some(&false) {
        b.pop();
    }
    b
}

fn full_add(b: &mut Builder, x: Bit, y: Bit, z: Bit) -> (Bit, Bit) {
    let xz = b.xor(x, z);
    let yz = b.xor(y, z);
    let t = b.and(xz, yz);
    let carry = b.xor(t, z);
    let sum = b.xor(xz, y);
    (sum, carry)
}

/// The sum of columns of bits, column `w` of weight `2^w`: every carry
/// kept, so the result is exact.
pub fn compress(b: &mut Builder, mut cols: Vec<Vec<Bit>>) -> Num {
    let mut out = Vec::with_capacity(cols.len() + 1);
    let mut w = 0;
    while w < cols.len() {
        let mut col = core::mem::take(&mut cols[w]);
        col.retain(|x| *x != Bit::Const(false));
        while col.len() > 1 {
            let (sum, carry) = if col.len() >= 3 {
                let (x, y, z) = (col.pop().unwrap(), col.pop().unwrap(), col.pop().unwrap());
                full_add(b, x, y, z)
            } else {
                let (x, y) = (col.pop().unwrap(), col.pop().unwrap());
                (b.xor(x, y), b.and(x, y))
            };
            col.push(sum);
            if carry != Bit::Const(false) {
                if w + 1 == cols.len() {
                    cols.push(Vec::new());
                }
                cols[w + 1].push(carry);
            }
        }
        out.push(col.pop().unwrap_or(Bit::Const(false)));
        w += 1;
    }
    trim(&mut out);
    out
}

fn trim(n: &mut Num) {
    while n.last() == Some(&Bit::Const(false)) {
        n.pop();
    }
}

/// `x·y`'s columns.
pub fn product(b: &mut Builder, x: &[Bit], y: &[Bit]) -> Vec<Vec<Bit>> {
    let mut cols = vec![Vec::new(); x.len() + y.len()];
    for (i, xi) in x.iter().enumerate() {
        for (j, yj) in y.iter().enumerate() {
            let t = b.and(*xi, *yj);
            cols[i + j].push(t);
        }
    }
    cols
}

/// `x²`'s columns: each cross product once, doubled.
pub fn square(b: &mut Builder, x: &[Bit]) -> Vec<Vec<Bit>> {
    let mut cols = vec![Vec::new(); 2 * x.len()];
    for (i, xi) in x.iter().enumerate() {
        cols[2 * i].push(*xi);
        for (j, xj) in x.iter().enumerate().skip(i + 1) {
            let t = b.and(*xi, *xj);
            cols[i + j + 1].push(t);
        }
    }
    cols
}

/// `x − c` for a constant `c` (as wide as `x`, or the borrow is set),
/// and the borrow: `x < c`.
fn sub_const(b: &mut Builder, x: &[Bit], c: &[bool]) -> (Num, Bit) {
    // x + ¬c + 1
    let mut carry = Bit::Const(true);
    let mut d = Vec::with_capacity(x.len());
    for (w, xw) in x.iter().enumerate() {
        let nc = Bit::Const(!c.get(w).copied().unwrap_or(false));
        let (s, k) = full_add(b, *xw, nc, carry);
        d.push(s);
        carry = k;
    }
    let borrow = if c.len() > x.len() && c[x.len()..].iter().any(|v| *v) { Bit::Const(true) } else { b.not(carry) };
    (d, borrow)
}

/// Whether `x < c`.
pub fn lt_const(b: &mut Builder, x: &[Bit], c: &[bool]) -> Bit {
    sub_const(b, x, c).1
}

pub fn eq(b: &mut Builder, x: &[Bit], y: &[Bit]) -> Bit {
    assert_eq!(x.len(), y.len());
    let mut any = Bit::Const(false);
    for (xw, yw) in x.iter().zip(y) {
        let d = b.xor(*xw, *yw);
        any = b.or(any, d);
    }
    b.not(any)
}

/// `v mod p`, [`BITS`] bits.
pub fn reduce(b: &mut Builder, mut v: Num) -> Num {
    while v.len() > BITS + 3 {
        let mut cols = vec![Vec::new(); BITS];
        for (w, bit) in v.iter().enumerate() {
            if w < BITS {
                cols[w].push(*bit);
            } else {
                for (z, one) in residue(w).iter().enumerate() {
                    if *one {
                        cols[z].push(*bit);
                    }
                }
            }
        }
        v = compress(b, cols);
    }
    // v < 2^len ≤ 2^(len − 253)·p: subtract 2^k·p where it fits, k down to 0
    for k in (0..=v.len().saturating_sub(BITS)).rev() {
        let (d, borrow) = sub_const(b, &v, &multiple(k));
        v = v.iter().zip(&d).map(|(x, y)| b.mux(borrow, *x, *y)).collect();
    }
    v.resize(BITS, Bit::Const(false));
    v
}

pub fn mul_mod(b: &mut Builder, x: &[Bit], y: &[Bit]) -> Num {
    let cols = product(b, x, y);
    let v = compress(b, cols);
    reduce(b, v)
}

pub fn square_mod(b: &mut Builder, x: &[Bit]) -> Num {
    let cols = square(b, x);
    let v = compress(b, cols);
    reduce(b, v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{AdditiveGroup, UniformRand};

    fn value(bits: &[bool]) -> Fq {
        let mut f = Fq::from(0u64);
        let mut pow = Fq::from(1u64);
        for b in bits {
            if *b {
                f += pow;
            }
            pow.double_in_place();
        }
        f
    }

    #[test]
    fn mul_and_square_mod_p() {
        let (mut b, i) = Builder::new(2 * BITS);
        let (x, y) = i.split_at(BITS);
        let m = mul_mod(&mut b, x, y);
        let s = square_mod(&mut b, x);
        let below = lt_const(&mut b, x, &bits(-Fq::from(1u64)));
        let mut out = m.clone();
        out.extend(s);
        out.push(below);
        let c = b.finish(&out);
        println!("mul_mod and square_mod: {} ANDs", c.ands());
        let rng = &mut ark_std::test_rng();
        let m1 = -Fq::from(1u64);
        let cases = [(m1, m1), (Fq::from(0u64), m1), (Fq::from(1u64), Fq::from(2u64))];
        for (x, y) in cases.into_iter().chain((0..8).map(|_| (Fq::rand(rng), Fq::rand(rng)))) {
            let input: Vec<bool> = bits(x).into_iter().chain(bits(y)).collect();
            let o = c.eval(&input);
            assert_eq!(o[..BITS], bits(x * y), "canonical: the bits, not only the value");
            assert_eq!(o[BITS..2 * BITS], bits(x * x));
            assert_eq!(o[2 * BITS], x != m1, "x < p − 1");
        }
        // inputs at or above p: still reduced, as values mod p
        let mut big = vec![true; BITS];
        big[0] = false;
        let input: Vec<bool> = big.iter().copied().chain(bits(Fq::from(3u64))).collect();
        let o = c.eval(&input);
        assert_eq!(value(&o[..BITS]), value(&big) * Fq::from(3u64));
        assert_eq!(o[..BITS], bits(value(&o[..BITS])));
        assert!(!o[2 * BITS]);
    }
}
