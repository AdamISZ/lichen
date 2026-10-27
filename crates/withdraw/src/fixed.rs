//! The fixed statement, for BABE (docs/BABE_DISPUTE_PLAN.md §2,
//! docs/BABE_GADGET_PLAN.md step 1). BABE fixes the Groth16 public input
//! at setup, so the journal can't carry `b`: it is `c ‖ D ‖ H(pk_H)`, the
//! same for every amount. `b` moves into the witness, bound to the one
//! Alice claimed on chain by the hub's Winternitz signature on it, under
//! the contract's one-time key `pk_H`: the hub signs only in `respond`,
//! the `b` her `request` signed.
//!
//! The signature is Winternitz, laid out as ln-gap's
//! (`lngap_lamport::winternitz`): `b` big-endian in 4-bit digits, 8 of
//! them and 2 of checksum, each a chain of 15. But the chains are SHA-256,
//! not HASH160: RISC Zero accelerates SHA-256, and up to 150 RIPEMD-160s
//! in software would add about half the withdrawal's cycles again, against
//! 60 vB more in `respond` (12 bytes a digit in the signature, 12 in the
//! key).

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::{withdrawal, Hash, Reject, WithdrawInput};

/// The signature's digits: 8 of `b`, 2 of checksum.
pub const DIGITS: usize = 10;

/// The longest chain: a digit's key is its secret hashed this often.
pub const MAX_DIGIT: u8 = 15;

/// The journal's length in bytes: `c ‖ D ‖ H(pk_H)`.
pub const JOURNAL_LEN: usize = 68;

/// The hub's Winternitz key for `b` (one hash a digit) and its signature
/// (each digit's secret hashed as often as the digit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HubAuth {
    pub key: [Hash; DIGITS],
    pub sig: [Hash; DIGITS],
}

/// The fixed statement's input: the withdrawal and the hub's signature on
/// its `b`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedInput {
    pub withdraw: WithdrawInput,
    pub auth: HubAuth,
}

/// `b`'s digits as the hub signs them: big-endian nibbles, then the
/// checksum `Σ (15 − d)`, big-endian in two.
pub fn digits(b: u32) -> [u8; DIGITS] {
    let mut d = [0u8; DIGITS];
    for (i, byte) in b.to_be_bytes().iter().enumerate() {
        d[2 * i] = byte >> 4;
        d[2 * i + 1] = byte & 0xf;
    }
    let sum: u8 = d[..8].iter().map(|x| MAX_DIGIT - x).sum();
    d[8] = sum >> 4;
    d[9] = sum & 0xf;
    d
}

/// `h` hashed `n` times.
pub fn chain(mut h: Hash, n: u8) -> Hash {
    for _ in 0..n {
        h = Sha256::digest(h).into();
    }
    h
}

/// The hub's key `pk_H`, as the journal commits it.
pub fn key_digest(key: &[Hash; DIGITS]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/babe/pk_H");
    for k in key {
        h.update(k);
    }
    h.finalize().into()
}

/// Whether `auth` is the hub's signature on `b`.
pub fn verify(auth: &HubAuth, b: u32) -> bool {
    digits(b).iter().zip(&auth.sig).zip(&auth.key).all(|((d, s), k)| chain(*s, MAX_DIGIT - d) == *k)
}

/// The fixed statement: the withdrawal as [`crate::check`] checks it, and
/// the hub's signature on its `b`; on success, the journal
/// `c ‖ D ‖ H(pk_H)` (`c` little-endian, as the other journal's).
pub fn check(input: &FixedInput, chain_id: &Hash, verify_chain: &mut dyn FnMut(&[u8]) -> bool) -> Result<[u8; JOURNAL_LEN], Reject> {
    let (b, c, d) = withdrawal(&input.withdraw, chain_id, verify_chain)?;
    if !verify(&input.auth, b) {
        return Err(Reject::HubAuth);
    }
    let mut journal = [0u8; JOURNAL_LEN];
    journal[..4].copy_from_slice(&c.to_le_bytes());
    journal[4..36].copy_from_slice(&d);
    journal[36..].copy_from_slice(&key_digest(&input.auth.key));
    Ok(journal)
}

// ----- the encoding: the hub's key, its signature, then the withdrawal's -----

impl FixedInput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::new();
        for h in self.auth.key.iter().chain(&self.auth.sig) {
            w.extend_from_slice(h);
        }
        w.extend_from_slice(&self.withdraw.to_bytes());
        w
    }

    pub fn from_bytes(b: &[u8]) -> Result<FixedInput, Reject> {
        const AUTH: usize = 2 * DIGITS * 32;
        if b.len() < AUTH {
            return Err(Reject::Encoding);
        }
        let h = |i: usize| -> Hash { b[32 * i..32 * i + 32].try_into().unwrap() };
        let auth = HubAuth { key: core::array::from_fn(h), sig: core::array::from_fn(|i| h(DIGITS + i)) };
        Ok(FixedInput { withdraw: WithdrawInput::from_bytes(&b[AUTH..])?, auth })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_journal;
    use crate::tests::{input, input_of};

    /// The hub's key from `seed`, and its signature on `b`.
    fn auth(seed: u8, b: u32) -> HubAuth {
        let secret = |i: usize| -> Hash { Sha256::digest([seed, i as u8]).into() };
        HubAuth { key: core::array::from_fn(|i| chain(secret(i), MAX_DIGIT)), sig: core::array::from_fn(|i| chain(secret(i), digits(b)[i])) }
    }

    /// A return of `b` (as [`input`]'s, its root signed and anchored),
    /// and the hub's signature on `b`.
    fn fixed(b: u64) -> (FixedInput, Hash) {
        let (_, id) = input();
        (FixedInput { auth: auth(1, b as u32), withdraw: input_of(b) }, id)
    }

    #[test]
    fn the_journal_is_the_same_for_every_amount() {
        let (i, id) = fixed(9);
        let good = chain_journal(&i.withdraw, &id).to_bytes();
        let j = check(&i, &id, &mut |c| c == good).unwrap();
        assert_eq!(&j[..4], &42u32.to_le_bytes());
        assert_eq!(j[4..36], crate::check(&i.withdraw, &id, &mut |_| true).unwrap()[8..], "D, as the other journal's");
        assert_eq!(j[36..], key_digest(&i.auth.key));
        // another amount under the same contract and key: the same journal
        let (other, id2) = fixed(1000);
        assert_eq!(id, id2);
        assert_ne!(other.withdraw.note.value, i.withdraw.note.value);
        assert_eq!(check(&other, &id, &mut |_| true).unwrap(), j);
        // the encoding round-trips, and refuses a byte less
        assert_eq!(FixedInput::from_bytes(&i.to_bytes()).unwrap(), i);
        assert_eq!(FixedInput::from_bytes(&i.to_bytes()[1..]), Err(Reject::Encoding));
    }

    #[test]
    fn the_hub_signs_one_b() {
        let (i, id) = fixed(9);
        // the hub's signature on another b: the withdrawal's doesn't verify
        let mut wrong = i.clone();
        wrong.auth = auth(1, 10);
        assert_eq!(check(&wrong, &id, &mut |_| true), Err(Reject::HubAuth));
        // another key: another journal
        let mut key = i.clone();
        key.auth = auth(2, 9);
        assert_ne!(check(&key, &id, &mut |_| true).unwrap(), check(&i, &id, &mut |_| true).unwrap());
        // a digit raised by hashing on (anyone can): the checksum's
        // digits can't follow, so no other b verifies
        let mut forged = auth(1, 9);
        forged.sig[7] = chain(forged.sig[7], 1);
        assert!(!verify(&forged, 10) && !verify(&forged, 9));
        // the withdrawal's own checks still apply
        assert_eq!(check(&i, &id, &mut |_| false), Err(Reject::Chain));
    }

    #[test]
    fn digits_and_checksum() {
        assert_eq!(digits(0), [0, 0, 0, 0, 0, 0, 0, 0, 7, 8], "120 = 0x78");
        assert_eq!(digits(u32::MAX), [15, 15, 15, 15, 15, 15, 15, 15, 0, 0]);
        assert_eq!(digits(0x0102_0304), [0, 1, 0, 2, 0, 3, 0, 4, 6, 14], "120 − 10 = 0x6e");
    }
}
