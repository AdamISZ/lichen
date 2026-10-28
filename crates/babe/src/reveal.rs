//! The reveal on chain (papers/lichen-babe v0.1.5 §8.5): Alice signs π1
//! in 2-bit digits under a one-time Lamport key, and `challenge_assert`
//! makes the hub reveal, for each digit, the secret of the value she
//! signed, by completing her adaptor pre-signature.
//!
//! At setup Alice gives the hub, for each digit `d` and value `v`, a
//! pre-signature on `challenge_assert` under a one-time key `A_{d,v}` of
//! hers, adapted to the dealing's point `f_{d,v}(0)·G`
//! ([`crate::vsss::Dealing::point`]). The leaf ([`challenge_leaf`]) reads
//! each digit from her Lamport preimage, which the hub copies from
//! `assert`, and checks a signature under the key that value selects. The
//! hub has none but her pre-signature's completion, which hands her
//! `f_{d,v}(0)` ([`extract`]). Each secret adapts exactly one
//! pre-signature, under a key used for nothing else.
//!
//! Two bits a step, so that the leaf's witness fits tapscript's initial
//! stack (1,000 elements, BIP 342): a preimage and a signature a digit,
//! 508 for π1's 254 digits, and the hub's signature. Bit by bit it would
//! be 1,017.

use k256::elliptic_curve::sec1::ToEncodedPoint;
use lngap_btc::adaptor::{adaptor_complete, adaptor_extract, adaptor_sign, adaptor_verify, AdaptorSig};
use lngap_btc::bitcoin::opcodes::all::*;
use lngap_btc::bitcoin::script::Builder;
use lngap_btc::bitcoin::ScriptBuf;
use lngap_btc::keys::{xonly, Seed};
use lngap_btc::script::BuilderExt;
use lngap_btc::secp256k1::{schnorr, Keypair, Message, PublicKey, SecretKey, XOnlyPublicKey};
use lngap_btc::{hash160, Hash160};

use crate::setup::{Secret, VALUES};
use crate::vsss::Dealing;

/// A Lamport preimage, as ln-gap's (`OP_HASH160`).
pub type Preimage = [u8; 20];

/// Alice's one-time Lamport key for π1: four preimages a digit.
pub struct LamportKey(Vec<[Preimage; VALUES]>);

/// Its public half: the preimages' hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LamportPub(pub Vec<[Hash160; VALUES]>);

impl LamportKey {
    pub fn new(seed: &Seed, digits: usize) -> LamportKey {
        LamportKey((0..digits).map(|d| core::array::from_fn(|v| seed.derive_bytes(&format!("babe/lamport/{d}/{v}"))[..20].try_into().unwrap())).collect())
    }

    pub fn public(&self) -> LamportPub {
        LamportPub(self.0.iter().map(|p| p.map(|x| hash160(&x))).collect())
    }

    /// The signature on `digits`: one preimage a digit.
    pub fn sign(&self, digits: &[u8]) -> Vec<Preimage> {
        assert_eq!(digits.len(), self.0.len(), "a digit a preimage");
        digits.iter().zip(&self.0).map(|(v, p)| p[*v as usize]).collect()
    }
}

impl LamportPub {
    /// The value preimage `p` signs for digit `d`, if any.
    pub fn read(&self, d: usize, p: &[u8]) -> Option<u8> {
        let h = hash160(p);
        self.0.get(d)?.iter().position(|x| *x == h).map(|v| v as u8)
    }

    /// `assert`'s check, digit after digit: each preimage, consumed in
    /// order, is one of its digit's four.
    pub fn verify(&self, b: Builder) -> Builder {
        self.0.iter().fold(b, |b, h| {
            let b = b.push_opcode(OP_HASH160).push_opcode(OP_DUP).push_bytes(&h[0]).push_opcode(OP_EQUAL);
            let b = h[1..3].iter().fold(b, |b, h| b.push_opcode(OP_OVER).push_bytes(h).push_opcode(OP_EQUAL).push_opcode(OP_BOOLOR));
            b.push_opcode(OP_SWAP).push_bytes(&h[3]).push_opcode(OP_EQUAL).push_opcode(OP_BOOLOR).push_opcode(OP_VERIFY)
        })
    }
}

/// Alice's one-time adaptor keys: one a digit and value.
pub struct AdaptorKeys(Vec<[Keypair; VALUES]>);

impl AdaptorKeys {
    pub fn new(seed: &Seed, digits: usize) -> AdaptorKeys {
        AdaptorKeys((0..digits).map(|d| core::array::from_fn(|v| seed.keypair(&format!("babe/adaptor/{d}/{v}")))).collect())
    }

    pub fn public(&self) -> Vec<[XOnlyPublicKey; VALUES]> {
        self.0.iter().map(|k| k.each_ref().map(xonly)).collect()
    }

    /// The pre-signatures on `challenge_assert`'s sighash `msg`, each
    /// adapted to its digit and value's point.
    pub fn presign(&self, msg: &Message, points: &[[PublicKey; VALUES]]) -> Vec<[AdaptorSig; VALUES]> {
        self.0.iter().zip(points).map(|(k, t)| core::array::from_fn(|v| adaptor_sign(&k[v], msg, &t[v]))).collect()
    }
}

/// The dealing's adaptor points, as secp256k1 keys.
pub fn points(dealing: &Dealing) -> Vec<[PublicKey; VALUES]> {
    (0..dealing.commitments.len())
        .map(|d| {
            core::array::from_fn(|v| {
                let p = dealing.point(d, v as u8).to_affine().to_encoded_point(true);
                PublicKey::from_slice(p.as_bytes()).expect("a dealt point is not the identity")
            })
        })
        .collect()
}

/// The hub's check of Alice's pre-signatures, at setup.
pub fn check_presigs(keys: &[[XOnlyPublicKey; VALUES]], msg: &Message, points: &[[PublicKey; VALUES]], presigs: &[[AdaptorSig; VALUES]]) -> bool {
    keys.len() == presigs.len()
        && points.len() == presigs.len()
        && keys.iter().zip(points).zip(presigs).all(|((k, t), s)| (0..VALUES).all(|v| adaptor_verify(&k[v], msg, &t[v], &s[v])))
}

/// `challenge_assert`'s leaf. Per digit, consuming Alice's preimage then a
/// signature: the preimage selects the key, which the signature must
/// satisfy; then the hub's own signature.
pub fn challenge_leaf(lamport: &LamportPub, keys: &[[XOnlyPublicKey; VALUES]], hub: &XOnlyPublicKey) -> ScriptBuf {
    assert_eq!(lamport.0.len(), keys.len(), "a key set a digit");
    let b = lamport.0.iter().zip(keys).fold(Builder::new(), |b, (h, k)| {
        // OP_HASH160, then for the first three values
        // OP_DUP <h_v> OP_EQUAL OP_IF OP_DROP <A_v> OP_ELSE; the last
        // <h_3> OP_EQUALVERIFY <A_3>, the branches closed
        let b = (0..VALUES - 1).fold(b.push_opcode(OP_HASH160), |b, v| {
            b.push_opcode(OP_DUP).push_bytes(&h[v]).push_opcode(OP_EQUAL).push_opcode(OP_IF).push_opcode(OP_DROP).push_x_only_key(&k[v]).push_opcode(OP_ELSE)
        });
        let b = b.push_bytes(&h[VALUES - 1]).push_opcode(OP_EQUALVERIFY).push_x_only_key(&k[VALUES - 1]);
        (0..VALUES - 1).fold(b, |b, _| b.push_opcode(OP_ENDIF)).push_opcode(OP_CHECKSIGVERIFY)
    });
    b.checksig(hub).into_script()
}

/// The hub's completions of the pre-signatures for `digits`, with their
/// secrets (`Dealer::reveal`).
pub fn complete(presigs: &[[AdaptorSig; VALUES]], digits: &[u8], secrets: &[Secret]) -> Vec<schnorr::Signature> {
    presigs
        .iter()
        .zip(digits)
        .zip(secrets)
        .map(|((s, v), t)| adaptor_complete(&s[*v as usize], &SecretKey::from_slice(t).expect("a dealt secret is a key")))
        .collect()
}

/// `challenge_assert`'s witness arguments, in consumption order.
pub fn challenge_args(preimages: &[Preimage], sigs: &[schnorr::Signature], hub: &schnorr::Signature) -> Vec<Vec<u8>> {
    preimages.iter().zip(sigs).flat_map(|(p, s)| [p.to_vec(), s.as_ref().to_vec()]).chain([hub.as_ref().to_vec()]).collect()
}

/// Alice's reading of a posted `challenge_assert`: its arguments, in
/// consumption order, give each digit's value and its secret.
pub fn extract(lamport: &LamportPub, presigs: &[[AdaptorSig; VALUES]], args: &[Vec<u8>]) -> Option<(Vec<u8>, Vec<Secret>)> {
    if args.len() != 2 * presigs.len() + 1 {
        return None;
    }
    args.chunks(2)
        .zip(presigs)
        .enumerate()
        .map(|(d, (pair, s))| {
            let v = lamport.read(d, &pair[0])?;
            let t = adaptor_extract(&s[v as usize], &schnorr::Signature::from_slice(&pair[1]).ok()?)?;
            Some((v, t.secret_bytes()))
        })
        .collect::<Option<Vec<_>>>()
        .map(|vs| vs.into_iter().unzip())
}
