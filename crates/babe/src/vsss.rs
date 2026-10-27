//! The input secrets shared across the instances (Glock §3.4, BABE §9.4;
//! papers/lichen-babe v0.1.3 §8.5): verifiable Shamir secret sharing, so
//! one set of secrets on chain opens every kept instance.
//!
//! For each input bit `j` and value `β` the hub draws a polynomial
//! `f_{j,β}` over secp256k1's scalars, of degree N − M, and commits to its
//! coefficients (Feldman): `C_t = a_t·G`. Instance `i` (1 to N) takes
//! `f(i)` as its input secret. At setup Alice is given the N − M opened
//! instances' shares, checked against the commitments. In
//! `challenge_assert` the hub reveals `f(0)` for π1's bits (`C_0` is the
//! adaptor point the reveal is tied to); with the N − M shares that makes
//! N − M + 1 points, so Alice interpolates the kept instances' secrets.
//! Before that she has N − M points of a degree N − M polynomial: the
//! kept secrets are hidden.

use k256::elliptic_curve::ff::{Field, PrimeField};
use k256::{ProjectivePoint, Scalar};
use rand_core::{CryptoRng, RngCore};

use crate::setup::Secret;

/// The hub's polynomials: per input bit, for 0 and for 1, their
/// coefficients, the constant first.
pub struct Dealer {
    polys: Vec<[Vec<Scalar>; 2]>,
}

/// The commitments to the polynomials' coefficients, `C_0 = f(0)·G` first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dealing {
    pub commitments: Vec<[Vec<ProjectivePoint>; 2]>,
}

fn eval(coeffs: &[Scalar], x: u64) -> Scalar {
    let x = Scalar::from(x);
    coeffs.iter().rev().fold(Scalar::ZERO, |acc, c| acc * x + c)
}

pub fn secret(s: &Scalar) -> Secret {
    s.to_bytes().into()
}

pub fn scalar(s: &Secret) -> Option<Scalar> {
    Option::from(Scalar::from_repr((*s).into()))
}

/// Polynomials of `degree` (N − M) for `bits` input bits.
pub fn deal<R: RngCore + CryptoRng>(bits: usize, degree: usize, rng: &mut R) -> (Dealer, Dealing) {
    let polys: Vec<[Vec<Scalar>; 2]> = (0..bits).map(|_| core::array::from_fn(|_| (0..=degree).map(|_| Scalar::random(&mut *rng)).collect())).collect();
    let commitments = polys.iter().map(|p| p.clone().map(|c| c.iter().map(|a| ProjectivePoint::GENERATOR * a).collect())).collect();
    (Dealer { polys }, Dealing { commitments })
}

impl Dealer {
    /// Instance `i`'s input secrets (`i` from 1): `f(i)`.
    pub fn shares(&self, i: u64) -> Vec<[Secret; 2]> {
        assert!(i > 0, "f(0) is the secret on chain");
        self.polys.iter().map(|p| p.clone().map(|c| secret(&eval(&c, i)))).collect()
    }

    /// The secret revealed on chain for bit `j` of value `value`: `f(0)`.
    pub fn reveal(&self, j: usize, value: bool) -> Secret {
        secret(&self.polys[j][value as usize][0])
    }
}

impl Dealing {
    /// The adaptor point of bit `j`'s value `value`: `f(0)·G`.
    pub fn point(&self, j: usize, value: bool) -> ProjectivePoint {
        self.commitments[j][value as usize][0]
    }

    /// Whether `shares` (instance index, its secrets) are all on their
    /// polynomials: one check for them all, under random weights.
    pub fn verify<R: RngCore + CryptoRng>(&self, shares: &[(u64, Vec<[Secret; 2]>)], rng: &mut R) -> bool {
        let degree = self.commitments.first().map_or(0, |c| c[0].len() - 1);
        // Σ w·f(i) against Σ_t C_t·(Σ w·i^t), per polynomial
        let mut lhs = Scalar::ZERO;
        let mut weights = vec![[vec![Scalar::ZERO; degree + 1], vec![Scalar::ZERO; degree + 1]]; self.commitments.len()];
        for (i, secrets) in shares {
            if secrets.len() != self.commitments.len() {
                return false;
            }
            for (j, pair) in secrets.iter().enumerate() {
                for (v, s) in pair.iter().enumerate() {
                    let Some(s) = scalar(s) else { return false };
                    let w = Scalar::random(&mut *rng);
                    lhs += w * s;
                    let mut pow = w;
                    for wt in weights[j][v].iter_mut() {
                        *wt += pow;
                        pow *= Scalar::from(*i);
                    }
                }
            }
        }
        let rhs = self
            .commitments
            .iter()
            .zip(&weights)
            .flat_map(|(c, w)| c.iter().zip(w).flat_map(|(c, w)| c.iter().zip(w)))
            .fold(ProjectivePoint::IDENTITY, |acc, (c, w)| acc + *c * w);
        ProjectivePoint::GENERATOR * lhs == rhs
    }
}

/// The Lagrange coefficients at `at` of the points `xs`.
pub fn lagrange(xs: &[u64], at: u64) -> Vec<Scalar> {
    let at = Scalar::from(at);
    xs.iter()
        .map(|&m| {
            let xm = Scalar::from(m);
            let (num, den) =
                xs.iter().filter(|&&n| n != m).fold((Scalar::ONE, Scalar::ONE), |(num, den), &n| (num * (at - Scalar::from(n)), den * (xm - Scalar::from(n))));
            num * den.invert().expect("distinct points")
        })
        .collect()
}

/// A kept instance's secrets for π1's bits, interpolated from the opened
/// instances' shares of them and the secrets revealed on chain (x = 0).
/// `opened`: (index, its secrets for the bits' values); `revealed`: one
/// a bit.
pub fn interpolate(at: u64, opened: &[(u64, Vec<Secret>)], revealed: &[Secret]) -> Option<Vec<Secret>> {
    let xs: Vec<u64> = core::iter::once(0).chain(opened.iter().map(|(i, _)| *i)).collect();
    let l = lagrange(&xs, at);
    (0..revealed.len())
        .map(|j| {
            let mut s = l[0] * scalar(&revealed[j])?;
            for (c, (_, secrets)) in l[1..].iter().zip(opened) {
                s += *c * scalar(secrets.get(j)?)?;
            }
            Some(secret(&s))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn shares_verify_and_interpolate() {
        let rng = &mut ChaCha20Rng::seed_from_u64(3);
        let (n, m, bits) = (12u64, 4u64, 5);
        let (dealer, dealing) = deal(bits, (n - m) as usize, rng);
        let opened: Vec<(u64, Vec<[Secret; 2]>)> = (1..=n - m).map(|i| (i, dealer.shares(i))).collect();
        assert!(dealing.verify(&opened, rng));
        // one share off its polynomial
        let mut bad = opened.clone();
        bad[3].1[2][1] = secret(&(scalar(&bad[3].1[2][1]).unwrap() + Scalar::ONE));
        assert!(!dealing.verify(&bad, rng));
        // the revealed secrets are the adaptor points' logs
        let values = [true, false, false, true, true];
        let revealed: Vec<Secret> = values.iter().enumerate().map(|(j, v)| dealer.reveal(j, *v)).collect();
        for (j, v) in values.iter().enumerate() {
            assert_eq!(ProjectivePoint::GENERATOR * scalar(&revealed[j]).unwrap(), dealing.point(j, *v));
        }
        // a kept instance's secrets, interpolated
        let of_values: Vec<(u64, Vec<Secret>)> = opened.iter().map(|(i, s)| (*i, s.iter().zip(values).map(|(p, v)| p[v as usize]).collect())).collect();
        for k in n - m + 1..=n {
            let want: Vec<Secret> = dealer.shares(k).iter().zip(values).map(|(p, v)| p[v as usize]).collect();
            assert_eq!(interpolate(k, &of_values, &revealed).unwrap(), want);
        }
    }
}
