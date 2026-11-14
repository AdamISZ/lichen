//! The grants L2, one note per account (papers/lichen-grants-v0.5.6): the
//! types the hub and the wallet exchange, on `lichen_withdraw::accounts`
//! (the hashes and encodings the statement reads too).
//!
//! - **A note** ([`Note`]) `(o, k, v)`: an account's `k`th note, `v` sats.
//!   It is *settled* ([`Settled`]) with the issuer's BIP340 signature on
//!   its digest; note 0 needs none (a contract key's mint, which the
//!   contract vouches for, or any other key's empty note).
//! - **A payment** is a spend of two halves ([`Half`]), the payer's and the
//!   payee's. The hub grants it ([`Grant`]): the point `T` of a seed it
//!   derives from the spend, and its adaptor pre-signatures under `T` on
//!   both new notes. Both owners sign `α` (the spend and the grant); the
//!   hub records it and releases the seed, which completes both new notes.
//! - **The protocol** ([`proto`]): what the wallet and the hub send each
//!   other.
//!
//! The hub keeps its [`book::Book`]: per account, its live note, the last
//! spend it took part in, and a payment pending.

pub mod book;
pub mod proto;

use anyhow::{ensure, Context, Result};
use bitcoin::key::{Keypair, XOnlyPublicKey};
use bitcoin::secp256k1::{schnorr, Message, PublicKey, SecretKey, SECP256K1};
use lngap_btc::adaptor::{adaptor_complete, adaptor_sign, adaptor_verify, AdaptorSig};
use serde::{Deserialize, Serialize};

pub use lichen_withdraw::accounts as core;
pub use lichen_withdraw::accounts::{Seed, BLIND_LEN, Q_LEN, U_LEN, VALUE_LIMIT};

pub type Hash = [u8; 32];

macro_rules! hex_bytes {
    ($name:ident, $n:expr) => {
        pub mod $name {
            use serde::{Deserialize, Deserializer, Serializer};
            pub fn serialize<S: Serializer>(h: &[u8; $n], s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&hex::encode(h))
            }
            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; $n], D::Error> {
                let v = hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)?;
                v.try_into().map_err(|_| serde::de::Error::custom(concat!("not ", stringify!($n), " bytes")))
            }
        }
    };
}
hex_bytes!(hex16, 16);
hex_bytes!(hex32, 32);
hex_bytes!(hex64, 64);

/// A key's x-only public key, as bytes (an account's owner, the issuer).
pub fn xonly(kp: &Keypair) -> Hash {
    kp.x_only_public_key().0.serialize()
}

/// A BIP340 signature by `kp` on `msg` (deterministic).
pub fn sign(kp: &Keypair, msg: &Hash) -> [u8; 64] {
    *SECP256K1.sign_schnorr_no_aux_rand(&Message::from_digest(*msg), kp).as_ref()
}

/// Whether `sig` is `pk`'s BIP340 signature on `msg`.
pub fn verify(pk: &Hash, msg: &Hash, sig: &[u8; 64]) -> bool {
    let (Ok(pk), Ok(sig)) = (XOnlyPublicKey::from_slice(pk), schnorr::Signature::from_slice(sig)) else { return false };
    SECP256K1.verify_schnorr(&sig, &Message::from_digest(*msg), &pk).is_ok()
}

/// A keypair from 32 secret bytes (the issuer's key, a wallet's).
pub fn keypair(secret: &[u8; 32]) -> Result<Keypair> {
    Ok(Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(secret).context("a secret key")?))
}

/// A note: account `owner`'s `k`th, of `v` sats.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Note {
    #[serde(with = "hex32")]
    pub owner: Hash,
    pub k: u32,
    pub v: u64,
}

impl Note {
    /// Its digest, what the issuer signs.
    pub fn digest(&self) -> Hash {
        core::note_digest(&self.owner, self.k, self.v)
    }
    /// The account's first note: a contract key's mint of `v0`, or the empty
    /// note.
    pub fn first(owner: Hash, v0: u64) -> Note {
        Note { owner, k: 0, v: v0 }
    }
}

/// A note with the issuer's signature (none for note 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settled {
    pub note: Note,
    #[serde(with = "hex64")]
    pub sig: [u8; 64],
}

impl Settled {
    /// The issuer's note: signed, or note 0 (which needs no signature).
    pub fn verify(&self, issuer: &Hash) -> bool {
        self.note.k == 0 || verify(issuer, &self.note.digest(), &self.sig)
    }
    /// Note 0, unsigned.
    pub fn first(owner: Hash, v0: u64) -> Settled {
        Settled { note: Note::first(owner, v0), sig: [0; 64] }
    }
    /// The claim an exit posts of it.
    pub fn claim(&self) -> core::Claim {
        if self.note.k == 0 {
            core::Claim::mint()
        } else {
            core::Claim { k: self.note.k, v: self.note.v, sig: self.sig }
        }
    }
}

/// The issuer's signature on `note`.
pub fn issue(issuer: &Keypair, note: Note) -> Settled {
    Settled { note, sig: if note.k == 0 { [0; 64] } else { sign(issuer, &note.digest()) } }
}

/// A half: `owner`'s note `(owner, k_in, v_in)`, the value it leaves with,
/// a blinding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Half {
    #[serde(with = "hex32")]
    pub owner: Hash,
    pub k_in: u32,
    pub v_in: u64,
    pub v_out: u64,
    #[serde(with = "hex16")]
    pub blind: [u8; BLIND_LEN],
}

impl Half {
    pub fn core(&self) -> core::Half {
        core::Half { owner: self.owner, k_in: self.k_in, v_in: self.v_in, v_out: self.v_out, blind: self.blind }
    }
    pub fn digest(&self) -> Hash {
        self.core().digest()
    }
    /// The note it takes.
    pub fn input(&self) -> Note {
        Note { owner: self.owner, k: self.k_in, v: self.v_in }
    }
    /// The note its step gives.
    pub fn next(&self) -> Result<Note> {
        let (owner, k, v) = self.core().next().context("an account's number overflows")?;
        Ok(Note { owner, k, v })
    }
    /// A half of `note`, leaving it `v_out`, freshly blinded.
    pub fn of(note: &Note, v_out: u64) -> Half {
        Half { owner: note.owner, k_in: note.k, v_in: note.v, v_out, blind: fresh16() }
    }
}

/// 16 random bytes.
pub fn fresh16() -> [u8; 16] {
    lichen_ledger::fresh_rho()[..16].try_into().unwrap()
}

/// A spend's sides in owner order: each owner and its half's digest.
pub type Sides = [(Hash, Hash); 2];

/// `δ(S)` of two sides.
pub fn spend_digest(sides: &Sides) -> Hash {
    core::spend_digest(sides)
}

/// An adaptor pre-signature as a grant carries it: `R'` and `s'` (65
/// bytes); the final nonce is `R' + T`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presig {
    pub r: PublicKey,
    pub s_prime: SecretKey,
}

impl Presig {
    pub fn bytes(&self) -> [u8; 65] {
        let mut b = [0u8; 65];
        b[..33].copy_from_slice(&self.r.serialize());
        b[33..].copy_from_slice(&self.s_prime.secret_bytes());
        b
    }
    /// As an adaptor signature under `t_point`, if `R' + T` is a point.
    pub fn adaptor(&self, t_point: &PublicKey) -> Option<AdaptorSig> {
        let r_final = self.r.combine(t_point).ok()?.x_only_public_key().0;
        Some(AdaptorSig { r_final, r: self.r, s_prime: self.s_prime })
    }
}

/// The hub's grant on a spend: `T`, and its pre-signatures under `T` on the
/// two new notes, in owner order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub t_point: PublicKey,
    pub rho: [Presig; 2],
}

/// A seed's scalar as a secret key.
pub fn scalar_key(z: &Seed) -> SecretKey {
    SecretKey::from_slice(&core::scalar_bytes(z)).expect("a seed's scalar is in range")
}

impl Grant {
    /// The issuer's grant, unlocked by seed `z`, on new notes `next` (in
    /// owner order).
    pub fn make(issuer: &Keypair, next: &[Note; 2], z: &Seed) -> Grant {
        let t_point = PublicKey::from_secret_key(SECP256K1, &scalar_key(z));
        let rho = next.map(|n| {
            let a = adaptor_sign(issuer, &Message::from_digest(n.digest()), &t_point);
            Presig { r: a.r, s_prime: a.s_prime }
        });
        Grant { t_point, rho }
    }
    /// `α` for the spend of `sides`.
    pub fn alpha(&self, sides: &Sides) -> Hash {
        core::auth_msg(&spend_digest(sides), &self.t_point.serialize(), &[self.rho[0].bytes(), self.rho[1].bytes()])
    }
    /// The pre-signature at `i` is the issuer's on `note` under `T`.
    pub fn verify(&self, issuer: &Hash, i: usize, note: &Note) -> Result<()> {
        let pk = XOnlyPublicKey::from_slice(issuer).context("the issuer key")?;
        let a = self.rho[i].adaptor(&self.t_point).context("the pre-signature's nonce")?;
        ensure!(adaptor_verify(&pk, &Message::from_digest(note.digest()), &self.t_point, &a), "the grant's pre-signature on the new note doesn't verify");
        Ok(())
    }
    /// Seed `z` is the grant's.
    pub fn opens(&self, z: &Seed) -> bool {
        PublicKey::from_secret_key(SECP256K1, &scalar_key(z)) == self.t_point
    }
    /// The new note at `i`, settled with seed `z`.
    pub fn complete(&self, issuer: &Hash, i: usize, note: &Note, z: &Seed) -> Result<Settled> {
        ensure!(self.opens(z), "not the grant's seed");
        let a = self.rho[i].adaptor(&self.t_point).context("the pre-signature's nonce")?;
        let s = Settled { note: *note, sig: *adaptor_complete(&a, &scalar_key(z)).as_ref() };
        ensure!(s.verify(issuer), "the completed signature doesn't verify");
        Ok(s)
    }
    /// What the statement cites of it, against `half` (hers): the other
    /// side, the grant, both signatures in owner order.
    pub fn cited(&self, half: &Half, sides: &Sides, psi: &[[u8; 64]; 2]) -> core::Cited {
        let other = if sides[0].0 == half.owner { sides[1] } else { sides[0] };
        core::Cited { half: half.core(), other: other.0, other_h: other.1, t_point: self.t_point.serialize(), rho: [self.rho[0].bytes(), self.rho[1].bytes()], psi: *psi }
    }
}

/// Order two halves' sides, and say where the first is: `(sides, i)` with
/// `sides[i]` the first's. Errs if the owners are equal.
pub fn sides_of(a: &Half, b: (Hash, Hash)) -> Result<(Sides, usize)> {
    let mine = (a.owner, a.digest());
    let sides = core::ordered(mine, b).context("a payment to oneself")?;
    Ok((sides, usize::from(sides[0].0 != a.owner)))
}

/// A seed from hex.
pub fn seed_hex(s: &str) -> Result<Seed> {
    hex::decode(s).ok().and_then(|v| v.try_into().ok()).context("a seed: 32 hex digits")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(b: u8) -> Keypair {
        keypair(&[b; 32]).unwrap()
    }

    #[test]
    fn a_grant_opens_both_notes_with_its_seed() {
        let (hub, alice, bob) = (kp(1), kp(2), kp(3));
        let issuer = xonly(&hub);
        let ha = Half::of(&Note { owner: xonly(&alice), k: 4, v: 1_000 }, 400);
        let hb = Half::of(&Note { owner: xonly(&bob), k: 0, v: 0 }, 600);
        let (sides, ia) = sides_of(&ha, (hb.owner, hb.digest())).unwrap();
        let ib = 1 - ia;
        let mut next = [ha.next().unwrap(); 2];
        next[ib] = hb.next().unwrap();
        let z = core::seed(&hub.secret_bytes(), &spend_digest(&sides));
        let g = Grant::make(&hub, &next, &z);
        g.verify(&issuer, ia, &next[ia]).unwrap();
        g.verify(&issuer, ib, &next[ib]).unwrap();
        assert!(g.verify(&issuer, ia, &next[ib]).is_err());
        assert!(g.complete(&issuer, ia, &next[ia], &[9; 16]).is_err());
        let a = g.complete(&issuer, ia, &next[ia], &z).unwrap();
        assert_eq!((a.note.k, a.note.v), (5, 400));
        assert!(g.complete(&issuer, ib, &next[ib], &z).unwrap().verify(&issuer));
        // the statement's view: both signed, the seed opens T
        let alpha = g.alpha(&sides);
        let psi = sides.map(|(o, _)| sign(if o == xonly(&alice) { &alice } else { &bob }, &alpha));
        let x = g.cited(&ha, &sides, &psi);
        assert!(x.signed_by_both());
        assert_eq!(core::point_of(&z), x.t_point);
        let q = issue(&hub, ha.input()).claim();
        assert_eq!(core::owed(Some(&q), 10, &xonly(&alice), &issuer, 100, 0, Some(&x), &z), 4);
    }

    #[test]
    fn one_time_signatures_agree_with_ln_gap() {
        use lngap_lamport::winternitz::{Wots256Secret, WotsParams};
        for n in [4usize, 16, Q_LEN] {
            let k = Wots256Secret::from_entropy(WotsParams::for_bytes(n as u32), [n as u8; 32]);
            let msg: Vec<u8> = (0..n).map(|i| (i * 13 + 1) as u8).collect();
            let s = k.sign(&msg).unwrap();
            let ours = core::Wots { hashes: s.hashes.clone(), digits: s.digits.clone() };
            assert_eq!(core::wots_verify(&k.public().digits, n, &ours), Some(msg));
        }
    }
}
