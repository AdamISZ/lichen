//! The grants L2 with one note per account, in sequence
//! (papers/lichen-grants-v0.5.6): the hashes and encodings its notes,
//! halves, spends and grants are made of, Algorithm 1, and the hub's
//! statement. One implementation, for the hub and wallet (`lichen_notes`)
//! and the guest.
//!
//! - **A note** `(o, k, v)`: owner, sequence number, value in sats
//!   (< 2^48). Its digest `H_note(o, ⟨k⟩₄, ⟨v⟩₆)` is what the issuer signs.
//!   Every account starts at 0: a contract key's note 0 is its mint, any
//!   other key's the empty note.
//! - **A half** `(o, k_in, v_in, v_out, λ)`: an owner's live note, the
//!   value it leaves with, a blinding. Its step gives `(o, k_in + 1, v_out)`.
//! - **A spend**: two halves of distinct owners, `o₁ < o₂`; both owners
//!   sign `α = H_auth(δ(S), T, ρ₁, ρ₂)`, `δ(S) = H_spend(o₁, h₁, o₂, h₂)`.
//! - **The unlock**: a 16-byte seed `z_S = [H_unlock(k_iss, δ(S))]₁₆`, its
//!   scalar `t = H_unlock-scalar(z, ⟨ctr⟩₄)`, its point `T = tG`.
//! - **The posted claim** `Q = ⟨k⟩₄ ‖ ⟨v⟩₆ ‖ σ` ([`Q_LEN`] bytes).
//! - **The statement** ([`check`]): "the claim Alice signed is owed at most
//!   the `b_corr` she countersigned". It reads no chain: `Q` and `b` reach
//!   it under her one-time keys from `request`, `b_corr` and `U` under her
//!   countersignatures from `ack`, all four keys hashed into the journal.

use alloc::vec::Vec;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::schnorr::{Signature, VerifyingKey};
use k256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

use crate::codec::{R, W};
use crate::{Hash, Reject};

/// The posted claim's length: `⟨k⟩₄ ‖ ⟨v⟩₆ ‖ σ`.
pub const Q_LEN: usize = 74;
/// The unlock's length: one seed.
pub const U_LEN: usize = 16;
/// The blinding's length.
pub const BLIND_LEN: usize = 16;
/// The journal's length: `c ‖ D`.
pub const JOURNAL_LEN: usize = 36;
/// Values are below this (6 bytes).
pub const VALUE_LIMIT: u64 = 1 << 48;

pub type Seed = [u8; U_LEN];

// ----- the hashes -----

/// The L2's tagged hash: SHA-256 over `lichen/notes/<tag>`, a zero byte,
/// and each part length-prefixed (4 bytes).
pub fn tagged(tag: &str, parts: &[&[u8]]) -> Hash {
    let mut s = Sha256::new();
    s.update(b"lichen/notes/");
    s.update(tag.as_bytes());
    s.update([0u8]);
    for p in parts {
        s.update((p.len() as u32).to_be_bytes());
        s.update(p);
    }
    s.finalize().into()
}

/// A value's 6 bytes.
pub fn v6(v: u64) -> [u8; 6] {
    v.to_be_bytes()[2..].try_into().unwrap()
}

fn from_v6(b: &[u8; 6]) -> u64 {
    let mut w = [0u8; 8];
    w[2..].copy_from_slice(b);
    u64::from_be_bytes(w)
}

/// A note's digest, `H_note(o, ⟨k⟩₄, ⟨v⟩₆)`: what the issuer signs.
pub fn note_digest(o: &Hash, k: u32, v: u64) -> Hash {
    tagged("note", &[o, &k.to_be_bytes(), &v6(v)])
}

/// A half: owner `o`'s note `(o, k_in, v_in)`, the value `v_out` it leaves
/// with, and its blinding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Half {
    pub owner: Hash,
    pub k_in: u32,
    pub v_in: u64,
    pub v_out: u64,
    pub blind: [u8; BLIND_LEN],
}

impl Half {
    /// `h(η) = H_half(o, ⟨k_in⟩₄, ⟨v_in⟩₆, ⟨v_out⟩₆, λ)`.
    pub fn digest(&self) -> Hash {
        tagged("half", &[&self.owner, &self.k_in.to_be_bytes(), &v6(self.v_in), &v6(self.v_out), &self.blind])
    }
    /// The note its step gives: `(o, k_in + 1, v_out)`, if the number
    /// doesn't overflow.
    pub fn next(&self) -> Option<(Hash, u32, u64)> {
        Some((self.owner, self.k_in.checked_add(1)?, self.v_out))
    }
    /// Its values in range.
    pub fn in_range(&self) -> bool {
        self.v_in < VALUE_LIMIT && self.v_out < VALUE_LIMIT && self.k_in < u32::MAX
    }
}

/// The two sides of a spend in owner order: `(o, h(η))` each, the lesser
/// owner first. None if the owners are equal.
pub fn ordered(a: (Hash, Hash), b: (Hash, Hash)) -> Option<[(Hash, Hash); 2]> {
    match a.0.cmp(&b.0) {
        core::cmp::Ordering::Less => Some([a, b]),
        core::cmp::Ordering::Greater => Some([b, a]),
        core::cmp::Ordering::Equal => None,
    }
}

/// `δ(S) = H_spend(o₁, h₁, o₂, h₂)`, the sides in owner order.
pub fn spend_digest(sides: &[(Hash, Hash); 2]) -> Hash {
    tagged("spend", &[&sides[0].0, &sides[0].1, &sides[1].0, &sides[1].1])
}

/// `α = H_auth(δ(S), T, ρ₁, ρ₂)`: what both owners sign, the grant's point
/// compressed and its pre-signatures (`R'` compressed, `s'`) in owner
/// order.
pub fn auth_msg(ds: &Hash, t_point: &[u8; 33], rho: &[[u8; 65]; 2]) -> Hash {
    tagged("auth", &[ds, t_point, &rho[0], &rho[1]])
}

/// The hub's seed for a spend, `[H_unlock(k_iss, δ(S))]₁₆`: from its key
/// and the spend, so it keeps no secret per spend.
pub fn seed(issuer_secret: &[u8; 32], ds: &Hash) -> Seed {
    tagged("unlock", &[issuer_secret, ds])[..U_LEN].try_into().unwrap()
}

/// A seed's scalar, `H_unlock-scalar(z, ⟨ctr⟩₄)` for the least `ctr` with
/// `0 < t < n`.
pub fn scalar_of(z: &Seed) -> Scalar {
    let mut ctr = 0u32;
    loop {
        let h = tagged("unlock-scalar", &[z, &ctr.to_be_bytes()]);
        if let Some(t) = Option::<Scalar>::from(Scalar::from_repr(h.into())) {
            if !bool::from(t.is_zero()) {
                return t;
            }
        }
        ctr += 1;
    }
}

/// A seed's scalar as 32 bytes.
pub fn scalar_bytes(z: &Seed) -> [u8; 32] {
    scalar_of(z).to_bytes().into()
}

/// `T = tG`, compressed, for seed `z`.
pub fn point_of(z: &Seed) -> [u8; 33] {
    (ProjectivePoint::GENERATOR * scalar_of(z)).to_affine().to_encoded_point(true).as_bytes().try_into().unwrap()
}

/// Whether `sig` is `pk`'s BIP340 signature on `msg`.
pub fn verify(pk: &Hash, msg: &Hash, sig: &[u8; 64]) -> bool {
    let (Ok(k), Ok(s)) = (VerifyingKey::from_bytes(pk), Signature::try_from(&sig[..])) else { return false };
    k.verify_raw(msg, &s).is_ok()
}

// ----- the claim -----

/// The posted claim: a note of her account `(O_c, k, v)` and its
/// signature; for `k = 0` (the mint) `v` and the signature are zeros.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub k: u32,
    pub v: u64,
    pub sig: [u8; 64],
}

impl Claim {
    /// The mint's claim.
    pub fn mint() -> Claim {
        Claim { k: 0, v: 0, sig: [0; 64] }
    }
    /// Its [`Q_LEN`] bytes.
    pub fn to_bytes(&self) -> [u8; Q_LEN] {
        let mut q = [0u8; Q_LEN];
        q[..4].copy_from_slice(&self.k.to_be_bytes());
        q[4..10].copy_from_slice(&v6(self.v));
        q[10..].copy_from_slice(&self.sig);
        q
    }
    /// The claim, if these are a claim's bytes (zeros for the mint's value
    /// and signature).
    pub fn from_bytes(q: &[u8]) -> Option<Claim> {
        let q: &[u8; Q_LEN] = q.try_into().ok()?;
        let c = Claim { k: u32::from_be_bytes(q[..4].try_into().unwrap()), v: from_v6(q[4..10].try_into().unwrap()), sig: q[10..].try_into().unwrap() };
        (c.k > 0 || (c.v == 0 && c.sig == [0; 64])).then_some(c)
    }
}

/// A spend the hub cites against a claim (`X`): her half, the other
/// owner and its half's digest, the grant's point and pre-signatures, and
/// both owners' signatures, the last two in owner order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cited {
    pub half: Half,
    pub other: Hash,
    pub other_h: Hash,
    pub t_point: [u8; 33],
    pub rho: [[u8; 65]; 2],
    pub psi: [[u8; 64]; 2],
}

impl Cited {
    /// The spend's sides in owner order, if the owners differ.
    pub fn sides(&self) -> Option<[(Hash, Hash); 2]> {
        ordered((self.half.owner, self.half.digest()), (self.other, self.other_h))
    }
    /// `α`, as both owners signed it.
    pub fn alpha(&self) -> Option<Hash> {
        Some(auth_msg(&spend_digest(&self.sides()?), &self.t_point, &self.rho))
    }
    /// Rule 1: both owners' signatures on `α`, together.
    pub fn signed_by_both(&self) -> bool {
        let (Some(sides), Some(alpha)) = (self.sides(), self.alpha()) else { return false };
        verify(&sides[0].0, &alpha, &self.psi[0]) && verify(&sides[1].0, &alpha, &self.psi[1])
    }
}

/// What a claim is owed (Algorithm 1), in units: 0 if malformed; the
/// cited step's `v_out` if it supersedes the claim; else the claimed
/// note's value; at most `b`.
///
/// `owner` is the contract's key, `issuer` the hub's, `v0` the mint's
/// value, `x` the cited spend, `u` the unlock.
#[allow(clippy::too_many_arguments)]
pub fn owed(q: Option<&Claim>, b: u32, owner: &Hash, issuer: &Hash, unit: u64, v0: u64, x: Option<&Cited>, u: &Seed) -> u32 {
    let Some(q) = q else { return 0 };
    if unit == 0 {
        return 0;
    }
    let v = if q.k == 0 { v0 } else { q.v };
    if q.k > 0 && !verify(issuer, &note_digest(owner, q.k, q.v), &q.sig) {
        return 0;
    }
    let units = |v: u64| u32::try_from(v / unit).unwrap_or(u32::MAX);
    if b > units(v) {
        return 0;
    }
    let supersedes = x.is_some_and(|x| x.half.owner == *owner && x.half.in_range() && x.signed_by_both() && *u != [0; U_LEN] && point_of(u) == x.t_point && x.half.k_in >= q.k);
    match x {
        Some(x) if supersedes => b.min(units(x.half.v_out)),
        _ => b.min(units(v)),
    }
}

// ----- one-time signatures (SHA-256 chains) -----

/// A Winternitz key's digit counts for `n` bytes: 2 digits a byte, and
/// enough base-16 checksum digits for `15 · 2n`.
pub fn wots_digits(n_bytes: usize) -> (usize, usize) {
    let m = 2 * n_bytes;
    let (mut c, mut cur) = (0, 1u64);
    while cur < (15 * m + 1) as u64 {
        cur *= 16;
        c += 1;
    }
    (m, c)
}

fn sha(x: &[u8]) -> Hash {
    Sha256::digest(x).into()
}

/// A one-time signature: per digit, the chain element and the digit
/// (message digits, then checksum digits).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wots {
    pub hashes: Vec<Hash>,
    pub digits: Vec<u8>,
}

/// The message `sig` signs under `key` (its chains' ends) for `n` bytes,
/// if it verifies: each element hashed `15 − d` times reaches its end,
/// the checksum digits are the message's.
pub fn wots_verify(key: &[Hash], n_bytes: usize, sig: &Wots) -> Option<Vec<u8>> {
    let (m, c) = wots_digits(n_bytes);
    if key.len() != m + c || sig.hashes.len() != m + c || sig.digits.len() != m + c {
        return None;
    }
    for i in 0..m + c {
        let d = sig.digits[i];
        if d > 15 {
            return None;
        }
        let mut h = sig.hashes[i];
        for _ in 0..15 - d {
            h = sha(&h);
        }
        if h != key[i] {
            return None;
        }
    }
    let mut sum: u32 = (15 * m) as u32 - sig.digits[..m].iter().map(|d| u32::from(*d)).sum::<u32>();
    for i in (m..m + c).rev() {
        if u32::from(sig.digits[i]) != sum % 16 {
            return None;
        }
        sum /= 16;
    }
    Some(sig.digits[..m].chunks(2).map(|p| (p[0] << 4) | p[1]).collect())
}

// ----- the statement -----

/// The contract as the journal binds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contract {
    pub c: u32,
    pub issuer: Hash,
    pub owner: Hash,
    pub unit: u64,
    pub v0: u64,
    /// Her one-time keys, each its chains' ends: `K_Q`, `K_b`, `A_corr`,
    /// `A_U`.
    pub keys: [Vec<Hash>; 4],
}

impl Contract {
    /// `κ = SHA256(K_Q ‖ K_b ‖ A_corr ‖ A_U)`.
    pub fn kappa(&self) -> Hash {
        let mut s = Sha256::new();
        for k in &self.keys {
            for h in k {
                s.update(h);
            }
        }
        s.finalize().into()
    }
    /// `D = SHA256("lichen/grants/contract" ‖ x(P_iss) ‖ x(O_c) ‖ ⟨u⟩₈ ‖
    /// ⟨v₀⟩₆ ‖ κ)`.
    pub fn d(&self) -> Hash {
        let mut s = Sha256::new();
        s.update(b"lichen/grants/contract");
        s.update(self.issuer);
        s.update(self.owner);
        s.update(self.unit.to_be_bytes());
        s.update(v6(self.v0));
        s.update(self.kappa());
        s.finalize().into()
    }
    /// `J = ⟨c⟩₄ ‖ D`.
    pub fn journal(&self) -> [u8; JOURNAL_LEN] {
        let mut j = [0u8; JOURNAL_LEN];
        j[..4].copy_from_slice(&self.c.to_be_bytes());
        j[4..].copy_from_slice(&self.d());
        j
    }
    /// Each key's length in bytes signed: `Q`, `b`, `b_corr`, `U`.
    pub const LENS: [usize; 4] = [Q_LEN, 4, 4, U_LEN];
    /// Its keys of the right lengths.
    pub fn well_formed(&self) -> bool {
        self.keys.iter().zip(Self::LENS).all(|(k, n)| {
            let (m, c) = wots_digits(n);
            k.len() == m + c
        })
    }
}

/// The hub's statement's input: the contract, her four signatures (on
/// `Q`, `b`, `b_corr`, `U`, from `request` and `ack`), and at most one
/// cited spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub contract: Contract,
    pub sigs: [Wots; 4],
    pub cited: Option<Cited>,
}

/// What the four signatures sign, if each verifies: `Q`'s bytes, `b`,
/// `b_corr`, `U`.
pub fn signed(contract: &Contract, sigs: &[Wots; 4]) -> Option<(Vec<u8>, u32, u32, Seed)> {
    let mut m: Vec<Vec<u8>> = Vec::new();
    for i in 0..4 {
        m.push(wots_verify(&contract.keys[i], Contract::LENS[i], &sigs[i])?);
    }
    let word = |b: &[u8]| u32::from_be_bytes(b.try_into().unwrap());
    Some((m[0].clone(), word(&m[1]), word(&m[2]), m[3][..].try_into().unwrap()))
}

/// The hub's statement: the claim Alice signed is owed at most the
/// `b_corr` she countersigned. Its journal, or why not.
pub fn check(input: &Input) -> Result<[u8; JOURNAL_LEN], Reject> {
    let c = &input.contract;
    if !c.well_formed() {
        return Err(Reject::Encoding);
    }
    let (q, b, b_corr, u) = signed(c, &input.sigs).ok_or(Reject::BadSignature)?;
    let claim = Claim::from_bytes(&q);
    if owed(claim.as_ref(), b, &c.owner, &c.issuer, c.unit, c.v0, input.cited.as_ref(), &u) > b_corr {
        return Err(Reject::Holds);
    }
    Ok(c.journal())
}

// ----- encodings -----

fn put_wots(w: &mut W, s: &Wots) {
    w.list(&s.hashes);
    w.bytes(&s.digits);
}

fn read_wots(r: &mut R) -> Result<Wots, Reject> {
    Ok(Wots { hashes: r.list()?, digits: r.bytes()? })
}

impl Half {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 4 + 12 + BLIND_LEN);
        v.extend(self.owner);
        v.extend(self.k_in.to_be_bytes());
        v.extend(v6(self.v_in));
        v.extend(v6(self.v_out));
        v.extend(self.blind);
        v
    }
    fn read(r: &mut R) -> Result<Half, Reject> {
        Ok(Half { owner: r.take()?, k_in: u32::from_be_bytes(r.take()?), v_in: from_v6(&r.take()?), v_out: from_v6(&r.take()?), blind: r.take()? })
    }
    pub fn from_bytes(b: &[u8]) -> Option<Half> {
        let mut r = R(b);
        let h = Half::read(&mut r).ok()?;
        r.0.is_empty().then_some(h)
    }
}

impl Input {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        let c = &self.contract;
        w.put(&c.c.to_be_bytes());
        w.put(&c.issuer);
        w.put(&c.owner);
        w.put(&c.unit.to_be_bytes());
        w.put(&c.v0.to_be_bytes());
        for k in &c.keys {
            w.list(k);
        }
        for s in &self.sigs {
            put_wots(&mut w, s);
        }
        match &self.cited {
            None => w.put(&[0]),
            Some(x) => {
                w.put(&[1]);
                w.put(&x.half.to_bytes());
                w.put(&x.other);
                w.put(&x.other_h);
                w.put(&x.t_point);
                w.put(&x.rho[0]);
                w.put(&x.rho[1]);
                w.put(&x.psi[0]);
                w.put(&x.psi[1]);
            }
        }
        w.0
    }

    pub fn from_bytes(b: &[u8]) -> Result<Input, Reject> {
        let mut r = R(b);
        let (cc, issuer, owner, unit, v0) = (u32::from_be_bytes(r.take()?), r.take()?, r.take()?, u64::from_be_bytes(r.take()?), u64::from_be_bytes(r.take()?));
        let keys = [r.list()?, r.list()?, r.list()?, r.list()?];
        let sigs = [read_wots(&mut r)?, read_wots(&mut r)?, read_wots(&mut r)?, read_wots(&mut r)?];
        let cited = match r.take()? {
            [0] => None,
            [1] => Some(Cited { half: Half::read(&mut r)?, other: r.take()?, other_h: r.take()?, t_point: r.take()?, rho: [r.take()?, r.take()?], psi: [r.take()?, r.take()?] }),
            _ => return Err(Reject::Encoding),
        };
        if !r.0.is_empty() {
            return Err(Reject::Encoding);
        }
        Ok(Input { contract: Contract { c: cc, issuer, owner, unit, v0, keys }, sigs, cited })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use k256::schnorr::SigningKey;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32]).unwrap()
    }
    fn pk(k: &SigningKey) -> Hash {
        k.verifying_key().to_bytes().into()
    }
    fn sign(k: &SigningKey, msg: &Hash) -> [u8; 64] {
        k.sign_raw(msg, &[0; 32]).unwrap().to_bytes()
    }

    /// A one-time key from `secret` for `n` bytes, and a signer.
    struct Ots {
        secret: u8,
        n: usize,
    }
    impl Ots {
        fn elem(&self, i: usize) -> Hash {
            sha(&[self.secret, i as u8, (i >> 8) as u8])
        }
        fn public(&self) -> Vec<Hash> {
            let (m, c) = wots_digits(self.n);
            (0..m + c)
                .map(|i| {
                    let mut h = self.elem(i);
                    for _ in 0..15 {
                        h = sha(&h);
                    }
                    h
                })
                .collect()
        }
        fn sign(&self, msg: &[u8]) -> Wots {
            let (m, c) = wots_digits(self.n);
            let mut digits: Vec<u8> = msg.iter().flat_map(|b| [b >> 4, b & 15]).collect();
            let mut sum: u32 = (15 * m) as u32 - digits.iter().map(|d| u32::from(*d)).sum::<u32>();
            let mut cs = vec![0u8; c];
            for d in cs.iter_mut().rev() {
                *d = (sum % 16) as u8;
                sum /= 16;
            }
            digits.extend(cs);
            let hashes = digits
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    let mut h = self.elem(i);
                    for _ in 0..*d {
                        h = sha(&h);
                    }
                    h
                })
                .collect();
            Wots { hashes, digits }
        }
    }

    /// A payment of `a` from `alice` (note `ka`, `va`) to `bob` (note `kb`,
    /// `vb`), its grant's seed `z`, signed by both.
    fn payment(alice: &SigningKey, ka: u32, va: u64, bob: &SigningKey, kb: u32, vb: u64, a: u64, z: &Seed) -> Cited {
        let her = Half { owner: pk(alice), k_in: ka, v_in: va, v_out: va - a, blind: [1; 16] };
        let his = Half { owner: pk(bob), k_in: kb, v_in: vb, v_out: vb + a, blind: [2; 16] };
        let mut x = Cited { half: her, other: his.owner, other_h: his.digest(), t_point: point_of(z), rho: [[3; 65], [4; 65]], psi: [[0; 64]; 2] };
        let alpha = x.alpha().unwrap();
        let sides = x.sides().unwrap();
        for (i, (o, _)) in sides.iter().enumerate() {
            let k = if *o == pk(alice) { alice } else { bob };
            x.psi[i] = sign(k, &alpha);
        }
        x
    }

    #[test]
    fn algorithm_one() {
        let (hub, alice, bob) = (key(1), key(2), key(3));
        let (issuer, owner) = (pk(&hub), pk(&alice));
        let unit = 100;
        let note = |k: u32, v: u64| Claim { k, v, sig: sign(&hub, &note_digest(&owner, k, v)) };
        let z: Seed = [7; 16];
        let o = |q: &Claim, b: u32, x: Option<&Cited>, u: &Seed| owed(Some(q), b, &owner, &issuer, unit, 0, x, u);
        // her note 5 of 100,000; her spend of it in flight, 50,000 to Bob
        let q5 = note(5, 100_000);
        let s = payment(&alice, 5, 100_000, &bob, 9, 1_000, 50_000, &z);
        assert_eq!(o(&q5, 1000, None, &[0; 16]), 1000);
        // cited with its seed: superseded, she is owed what it left her
        assert_eq!(o(&q5, 1000, Some(&s), &z), 500);
        // the wrong seed, or none: it doesn't count
        assert_eq!(o(&q5, 1000, Some(&s), &[8; 16]), 1000);
        assert_eq!(o(&q5, 1000, Some(&s), &[0; 16]), 1000);
        // Rule 1: one owner's signature alone doesn't count
        let mut half_signed = s.clone();
        half_signed.psi[1] = [0; 64];
        assert_eq!(o(&q5, 1000, Some(&half_signed), &z), 1000);
        half_signed = s.clone();
        half_signed.psi[0] = [0; 64];
        assert_eq!(o(&q5, 1000, Some(&half_signed), &z), 1000);
        // a stale claim (note 3 of 120,000): the later step supersedes it
        assert_eq!(o(&note(3, 120_000), 1200, Some(&s), &z), 500);
        // a later claim than the step: the step doesn't supersede (k_in < k)
        assert_eq!(o(&note(6, 50_000), 500, Some(&s), &z), 500);
        assert_eq!(o(&note(7, 60_000), 600, Some(&s), &z), 600);
        // a spend of another account doesn't count against hers
        let bobs = payment(&bob, 9, 1_000, &alice, 5, 100_000, 500, &z);
        assert_eq!(o(&q5, 1000, Some(&bobs), &z), 1000);
        // her incoming step cited: never above b, so never worth the hub's citing
        let mut incoming = payment(&bob, 9, 1_000, &alice, 5, 100_000, 500, &z);
        incoming.half = Half { owner, k_in: 5, v_in: 100_000, v_out: 100_500, blind: [2; 16] };
        assert!(o(&q5, 1000, Some(&incoming), &z) <= 1000);
        // malformed: a signature not the issuer's, b above the note
        let forged = Claim { k: 5, v: 100_000, sig: sign(&bob, &note_digest(&owner, 5, 100_000)) };
        assert_eq!(o(&forged, 1, None, &[0; 16]), 0);
        assert_eq!(o(&q5, 1001, None, &[0; 16]), 0);
        assert_eq!(owed(None, 1, &owner, &issuer, unit, 0, None, &[0; 16]), 0);
        // the mint: its value from the contract
        assert_eq!(owed(Some(&Claim::mint()), 40, &owner, &issuer, unit, 4_000, None, &[0; 16]), 40);
        assert_eq!(owed(Some(&Claim::mint()), 41, &owner, &issuer, unit, 4_000, None, &[0; 16]), 0);
        let from_mint = payment(&alice, 0, 4_000, &bob, 0, 0, 1_000, &z);
        assert_eq!(owed(Some(&Claim::mint()), 40, &owner, &issuer, unit, 4_000, Some(&from_mint), &z), 30);
        // the bytes
        assert_eq!(Claim::from_bytes(&q5.to_bytes()), Some(q5));
        assert_eq!(Claim::from_bytes(&Claim::mint().to_bytes()), Some(Claim::mint()));
        let mut junk = Claim::mint().to_bytes();
        junk[9] = 1;
        assert_eq!(Claim::from_bytes(&junk), None);
        assert_eq!(Half::from_bytes(&s.half.to_bytes()), Some(s.half));
    }

    #[test]
    fn one_time_signatures() {
        for n in [4usize, 16, Q_LEN] {
            let k = Ots { secret: n as u8, n };
            let msg: Vec<u8> = (0..n).map(|i| (i * 37 + 5) as u8).collect();
            let s = k.sign(&msg);
            assert_eq!(wots_verify(&k.public(), n, &s), Some(msg.clone()));
            // a digit raised: its chain falls short; lowered: the checksum
            let mut up = s.clone();
            up.digits[1] += 1;
            assert_eq!(wots_verify(&k.public(), n, &up), None);
            let mut other = msg.clone();
            other[0] ^= 0x10;
            assert_eq!(wots_verify(&k.public(), n, &k.sign(&other)), Some(other));
        }
        assert_eq!(wots_digits(Q_LEN), (148, 3));
        assert_eq!(wots_digits(4), (8, 2));
        assert_eq!(wots_digits(U_LEN), (32, 3));
    }

    #[test]
    fn the_statement() {
        let (hub, alice, bob) = (key(1), key(2), key(3));
        let ots: [Ots; 4] = [Ots { secret: 10, n: Q_LEN }, Ots { secret: 11, n: 4 }, Ots { secret: 12, n: 4 }, Ots { secret: 13, n: U_LEN }];
        let contract = Contract { c: 7, issuer: pk(&hub), owner: pk(&alice), unit: 100, v0: 0, keys: [ots[0].public(), ots[1].public(), ots[2].public(), ots[3].public()] };
        let q = Claim { k: 5, v: 100_000, sig: sign(&hub, &note_digest(&pk(&alice), 5, 100_000)) };
        let z: Seed = [7; 16];
        let s = payment(&alice, 5, 100_000, &bob, 9, 1_000, 50_000, &z);
        let input = |b_corr: u32, u: &Seed, cited: Option<Cited>| Input {
            contract: contract.clone(),
            sigs: [ots[0].sign(&q.to_bytes()), ots[1].sign(&1000u32.to_be_bytes()), ots[2].sign(&b_corr.to_be_bytes()), ots[3].sign(u)],
            cited,
        };
        let i = input(500, &z, Some(s.clone()));
        assert_eq!(check(&i), Ok(contract.journal()));
        assert_eq!(Input::from_bytes(&i.to_bytes()), Ok(i));
        // corrected too far: doesn't hold
        assert_eq!(check(&input(499, &z, Some(s.clone()))), Err(Reject::Holds));
        // no citation: owed in full
        assert_eq!(check(&input(500, &[0; 16], None)), Err(Reject::Holds));
        assert!(check(&input(1000, &[0; 16], None)).is_ok());
        // a signature not under her key
        let mut bad = input(500, &z, Some(s));
        bad.sigs[2] = Ots { secret: 99, n: 4 }.sign(&500u32.to_be_bytes());
        assert_eq!(check(&bad), Err(Reject::BadSignature));
        // the journal binds the keys
        let mut other = contract.clone();
        other.keys[3] = Ots { secret: 14, n: U_LEN }.public();
        assert_ne!(other.journal(), contract.journal());
    }
}
