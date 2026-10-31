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

use crate::exit::ExitInput;
use crate::{withdrawal, Hash, OutPoint, Reject, WithdrawInput};

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

// ----- with the exit: three ways for Alice to win -----
//
// The exit adds two branches to the return (docs/EXIT_PLAN.md, "Under
// BABE", and "Decided while building step 1"). `request` signs `b` and
// `E`; `respond` has two leaves, both comparing the hub's `b` and `E`
// with hers:
//
// - **plain:** the hub signs `b`, and `E` under `e_plain`; no counter;
// - **counter:** the hub signs `b`, `E` under `e_counter`, and `K`, the
//   counter's Groth16 seal (compressed, 128 bytes), under `k`.
//
// The hub signs `K` itself, not `H(K)`: the script can't tie a hash of
// the witness to signed digits (no `OP_CAT` to split it), so a signed
// `H(K)` would let the hub post other bytes and leave her no preimage.
// Which leaf ran is shown by which `E` key signed; each signs once.
//
// Alice wins if:
//
// - **return:** the hub signed `b` and a return of `b` with memo `c` is
//   anchored, as [`check`]. Whatever the mode: a return pays once;
// - **claim:** the hub signed `b` and `E` in the plain leaf, and her
//   claim of `b` with that `E` holds;
// - **counter:** the hub signed `E` and `K` in the counter leaf, and `K`
//   isn't a counter for `D ‖ E`.
//
// The journal is `c ‖ D ‖ H(pk_H ‖ O_D)`: every key the hub signs with
// in `respond`, and the deposit coin, which `E` names, and whose funding
// `request` spends (the claim's posting and the counter's cutoff read
// it).

/// A signature's digits on 32 bytes (`E`): 64, and 3 of checksum.
pub const E_DIGITS: usize = 67;

/// `K`: a compressed Groth16 seal (two G1 points, one G2).
pub const K_LEN: usize = 128;

/// A signature's digits on `K`: 256, and 3 of checksum.
pub const K_DIGITS: usize = 259;

/// `msg`'s digits as ln-gap signs them (`WotsParams::for_bytes`):
/// big-endian nibbles, then the checksum `Σ (15 − d)` big-endian in as
/// few nibbles as hold `15 · digits`.
pub fn digits_of(msg: &[u8]) -> Vec<u8> {
    let mut d: Vec<u8> = msg.iter().flat_map(|b| [b >> 4, b & 0xf]).collect();
    let most = u32::from(MAX_DIGIT) * d.len() as u32;
    let mut sum: u32 = d.iter().map(|x| u32::from(MAX_DIGIT - x)).sum();
    let n = (1..).find(|n| 16u64.pow(*n) > u64::from(most)).unwrap();
    let at = d.len();
    d.resize(at + n as usize, 0);
    for x in d[at..].iter_mut().rev() {
        *x = (sum % 16) as u8;
        sum /= 16;
    }
    d
}

/// Whether `sig` is a signature on `msg` under `key`.
pub fn verify_msg(key: &[Hash], sig: &[Hash], msg: &[u8]) -> bool {
    let d = digits_of(msg);
    key.len() == d.len() && sig.len() == d.len() && d.iter().zip(sig).zip(key).all(|((d, s), k)| chain(*s, MAX_DIGIT - d) == *k)
}

/// The hub's keys in `respond`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitKeys {
    pub b: [Hash; DIGITS],
    pub e_plain: [Hash; E_DIGITS],
    pub e_counter: [Hash; E_DIGITS],
    pub k: Vec<Hash>,
}

/// `pk_H ‖ O_D`, as the journal commits it.
pub fn exit_key_digest(keys: &ExitKeys, deposit: &OutPoint) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/babe/pk_H/exit");
    for k in keys.b.iter().chain(&keys.e_plain).chain(&keys.e_counter).chain(&keys.k) {
        h.update(k);
    }
    h.update(deposit.to_bytes());
    h.finalize().into()
}

/// The journal `c ‖ D ‖ H(pk_H ‖ O_D)`.
pub fn exit_journal(c: u32, d: &Hash, keys: &ExitKeys, deposit: &OutPoint) -> [u8; JOURNAL_LEN] {
    let mut journal = [0u8; JOURNAL_LEN];
    journal[..4].copy_from_slice(&c.to_le_bytes());
    journal[4..36].copy_from_slice(d);
    journal[36..].copy_from_slice(&exit_key_digest(keys, deposit));
    journal
}

/// How Alice wins, and the hub's signatures it rests on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Return { withdraw: WithdrawInput, b_sig: [Hash; DIGITS] },
    Claim { claim: ExitInput, b_sig: [Hash; DIGITS], e_sig: [Hash; E_DIGITS] },
    Counter { c: u32, d: Hash, e: Hash, k: Vec<u8>, e_sig: [Hash; E_DIGITS], k_sig: Vec<Hash> },
}

/// The statement's input: the hub's keys, the contract's deposit coin,
/// and the mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitStatement {
    pub keys: ExitKeys,
    pub deposit: OutPoint,
    pub mode: Mode,
}

/// The statement with the exit: check `input` against a chain receipt of
/// `chain_id` (`verify_chain`), and a counter's seal against its journal
/// `D ‖ E` (`verify_counter`, the counter guest's Groth16 verification);
/// on success, the journal `c ‖ D ‖ H(pk_H ‖ O_D)`.
pub fn check_exit(
    input: &ExitStatement,
    chain_id: &Hash,
    verify_chain: &mut dyn FnMut(&[u8]) -> bool,
    verify_counter: &mut dyn FnMut(&[u8], &[u8; 64]) -> bool,
) -> Result<[u8; JOURNAL_LEN], Reject> {
    let keys = &input.keys;
    let (c, d) = match &input.mode {
        Mode::Return { withdraw, b_sig } => {
            let (b, c, d) = withdrawal(withdraw, chain_id, verify_chain)?;
            if !verify(&HubAuth { key: keys.b, sig: *b_sig }, b) {
                return Err(Reject::HubAuth);
            }
            (c, d)
        }
        Mode::Claim { claim, b_sig, e_sig } => {
            if claim.deposit != input.deposit {
                return Err(Reject::Outpoint);
            }
            let cl = crate::exit::check(claim, chain_id, verify_chain)?;
            if !verify(&HubAuth { key: keys.b, sig: *b_sig }, cl.b) || !verify_msg(&keys.e_plain, e_sig, &cl.e) {
                return Err(Reject::HubAuth);
            }
            (cl.c, cl.d)
        }
        Mode::Counter { c, d, e, k, e_sig, k_sig } => {
            if !verify_msg(&keys.e_counter, e_sig, e) || k.len() != K_LEN || !verify_msg(&keys.k, k_sig, k) {
                return Err(Reject::HubAuth);
            }
            let mut journal = [0u8; 64];
            journal[..32].copy_from_slice(d);
            journal[32..].copy_from_slice(e);
            if verify_counter(k, &journal) {
                return Err(Reject::Countered);
            }
            (*c, *d)
        }
    };
    Ok(exit_journal(c, &d, keys, &input.deposit))
}

fn arr<const N: usize>(v: Vec<Hash>) -> Result<[Hash; N], Reject> {
    v.try_into().map_err(|_| Reject::Encoding)
}

impl ExitStatement {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = crate::exit::W(Vec::new());
        let k = &self.keys;
        w.list(&k.b);
        w.list(&k.e_plain);
        w.list(&k.e_counter);
        w.list(&k.k);
        w.put(&self.deposit.to_bytes());
        match &self.mode {
            Mode::Return { withdraw, b_sig } => {
                w.put(&[0]);
                w.list(b_sig);
                w.bytes(&withdraw.to_bytes());
            }
            Mode::Claim { claim, b_sig, e_sig } => {
                w.put(&[1]);
                w.list(b_sig);
                w.list(e_sig);
                w.bytes(&claim.to_bytes());
            }
            Mode::Counter { c, d, e, k, e_sig, k_sig } => {
                w.put(&[2]);
                w.put(&c.to_be_bytes());
                w.put(d);
                w.put(e);
                w.bytes(k);
                w.list(e_sig);
                w.list(k_sig);
            }
        }
        w.0
    }

    pub fn from_bytes(b: &[u8]) -> Result<ExitStatement, Reject> {
        let mut r = crate::exit::R(b);
        let keys = ExitKeys { b: arr(r.list()?)?, e_plain: arr(r.list()?)?, e_counter: arr(r.list()?)?, k: r.list()? };
        let deposit = OutPoint::from_bytes(&r.take()?);
        let mode = match r.take()? {
            [0] => Mode::Return { b_sig: arr(r.list()?)?, withdraw: WithdrawInput::from_bytes(&r.bytes()?)? },
            [1] => Mode::Claim { b_sig: arr(r.list()?)?, e_sig: arr(r.list()?)?, claim: ExitInput::from_bytes(&r.bytes()?)? },
            [2] => Mode::Counter { c: u32::from_be_bytes(r.take()?), d: r.take()?, e: r.take()?, k: r.bytes()?, e_sig: arr(r.list()?)?, k_sig: r.list()? },
            _ => return Err(Reject::Encoding),
        };
        if !r.0.is_empty() {
            return Err(Reject::Encoding);
        }
        Ok(ExitStatement { keys, deposit, mode })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
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

    /// A Winternitz key of `n` digits from `seed`, and its signature on
    /// `msg`.
    fn wots(seed: u8, n: usize) -> Vec<Hash> {
        (0..n).map(|i| chain(Sha256::digest([seed, i as u8, (i >> 8) as u8]).into(), MAX_DIGIT)).collect()
    }
    fn sign(seed: u8, msg: &[u8]) -> Vec<Hash> {
        digits_of(msg).iter().enumerate().map(|(i, d)| chain(Sha256::digest([seed, i as u8, (i >> 8) as u8]).into(), *d)).collect()
    }

    fn keys() -> ExitKeys {
        ExitKeys { b: wots(1, DIGITS).try_into().unwrap(), e_plain: wots(2, E_DIGITS).try_into().unwrap(), e_counter: wots(3, E_DIGITS).try_into().unwrap(), k: wots(4, K_DIGITS) }
    }

    /// Alice's claim (`exit`'s), the hub's plain leaf signed for it; and
    /// a chain id.
    fn claim() -> (ExitStatement, Hash) {
        claim_of(crate::exit::tests::input())
    }

    /// `claim`, of the claim `claim`.
    fn claim_of((claim, id): (ExitInput, Hash)) -> (ExitStatement, Hash) {
        let e = crate::exit::fingerprint(claim.c, &claim.deposit, claim.b, claim.state.height, &claim.state.root(&claim.tree), &crate::exit::nullifiers(&claim));
        let mode = Mode::Claim { b_sig: sign(1, &claim.b.to_be_bytes()).try_into().unwrap(), e_sig: sign(2, &e).try_into().unwrap(), claim: claim.clone() };
        (ExitStatement { keys: keys(), deposit: claim.deposit, mode }, id)
    }

    /// The hub's counter leaf on the claim's `D ‖ E`, with seal `k`.
    fn counter(k: Vec<u8>) -> (ExitStatement, Hash) {
        let (s, id) = claim();
        let Mode::Claim { claim, .. } = &s.mode else { unreachable!() };
        let cl = crate::exit::check(claim, &id, &mut |_| true).unwrap();
        let mode = Mode::Counter { c: cl.c, d: cl.d, e: cl.e, e_sig: sign(3, &cl.e).try_into().unwrap(), k_sig: sign(4, &k), k };
        (ExitStatement { mode, ..s }, id)
    }

    fn chain_ok(s: &ExitStatement, id: &Hash) -> impl FnMut(&[u8]) -> bool {
        let good = match &s.mode {
            Mode::Claim { claim, .. } => claim.state.chain_journal(id).to_bytes(),
            Mode::Return { withdraw, .. } => chain_journal(withdraw, id).to_bytes(),
            Mode::Counter { .. } => Vec::new(),
        };
        move |c: &[u8]| c == good
    }

    #[test]
    fn three_ways_to_win() {
        let never = &mut |_: &[u8], _: &[u8; 64]| false;
        // the claim, with no counter
        let (s, id) = claim();
        let j = check_exit(&s, &id, &mut chain_ok(&s, &id), never).unwrap();
        let Mode::Claim { claim, .. } = &s.mode else { unreachable!() };
        let cl = crate::exit::check(claim, &id, &mut |_| true).unwrap();
        assert_eq!(j, exit_journal(42, &cl.d, &s.keys, &claim.deposit));
        // a counter that doesn't verify: the same journal
        let (k, _) = counter(std::vec![7; K_LEN]);
        assert_eq!(check_exit(&k, &id, &mut |_| false, never), Ok(j));
        // one that does: none
        let mut seen = None;
        let r = check_exit(&k, &id, &mut |_| false, &mut |seal, journal| {
            seen = Some((seal.to_vec(), *journal));
            true
        });
        assert_eq!(r, Err(Reject::Countered));
        let (seal, journal) = seen.unwrap();
        assert_eq!((seal, &journal[..32], &journal[32..]), (std::vec![7; K_LEN], &cl.d[..], &cl.e[..]));
        // a refused return, under the same keys
        let withdraw = input_of(9);
        let r = ExitStatement { mode: Mode::Return { withdraw: withdraw.clone(), b_sig: sign(1, &9u32.to_be_bytes()).try_into().unwrap() }, ..s.clone() };
        let d = crate::check(&withdraw, &id, &mut |_| true).unwrap()[8..].try_into().unwrap();
        assert_eq!(check_exit(&r, &id, &mut chain_ok(&r, &id), never), Ok(exit_journal(42, &d, &s.keys, &s.deposit)));
        // each encodes and decodes
        for x in [&s, &k, &r] {
            assert_eq!(ExitStatement::from_bytes(&x.to_bytes()).as_ref(), Ok(x));
            assert_eq!(ExitStatement::from_bytes(&x.to_bytes()[1..]), Err(Reject::Encoding));
        }
    }

    #[test]
    fn what_the_hub_signed_decides() {
        let never = &mut |_: &[u8], _: &[u8; 64]| false;
        let (s, id) = claim();
        let run = |s: &ExitStatement| check_exit(s, &id, &mut chain_ok(s, &id), &mut |_, _| false);
        // the claim with E signed in the counter leaf: that leaf ran, so
        // the claim alone doesn't win
        let mut x = s.clone();
        let Mode::Claim { e_sig, claim, .. } = &mut x.mode else { unreachable!() };
        let e = crate::exit::check(claim, &id, &mut |_| true).unwrap().e;
        *e_sig = sign(3, &e).try_into().unwrap();
        assert_eq!(run(&x), Err(Reject::HubAuth));
        // another b signed than the claim's
        let mut x = s.clone();
        let Mode::Claim { b_sig, .. } = &mut x.mode else { unreachable!() };
        *b_sig = sign(1, &11u32.to_be_bytes()).try_into().unwrap();
        assert_eq!(run(&x), Err(Reject::HubAuth));
        // the claim's E naming another outpoint than the journal's
        let mut x = s.clone();
        x.deposit.vout += 1;
        assert_eq!(run(&x), Err(Reject::Outpoint));
        // a counter leaf's E signed under the plain key; K not the one
        // signed; K of another length
        let (k, _) = counter(std::vec![7; K_LEN]);
        let mut x = k.clone();
        let Mode::Counter { e_sig, e, .. } = &mut x.mode else { unreachable!() };
        *e_sig = sign(2, e).try_into().unwrap();
        assert_eq!(check_exit(&x, &id, &mut |_| false, never), Err(Reject::HubAuth));
        let mut x = k.clone();
        let Mode::Counter { k: seal, .. } = &mut x.mode else { unreachable!() };
        seal[0] ^= 1;
        assert_eq!(check_exit(&x, &id, &mut |_| false, never), Err(Reject::HubAuth));
        let (short, _) = counter(std::vec![7; K_LEN - 1]);
        assert_eq!(check_exit(&short, &id, &mut |_| false, never), Err(Reject::HubAuth));
        // another E than the one signed
        let mut x = k.clone();
        let Mode::Counter { e, .. } = &mut x.mode else { unreachable!() };
        e[0] ^= 1;
        assert_eq!(check_exit(&x, &id, &mut |_| false, never), Err(Reject::HubAuth));
        // the claim's own checks still apply
        let mut x = s.clone();
        let Mode::Claim { claim, .. } = &mut x.mode else { unreachable!() };
        claim.b += 1;
        assert_eq!(run(&x), Err(Reject::NotYours), "her signature is on the claim of 12");
    }

    #[test]
    fn digits_and_checksum() {
        assert_eq!(digits(0), [0, 0, 0, 0, 0, 0, 0, 0, 7, 8], "120 = 0x78");
        assert_eq!(digits(u32::MAX), [15, 15, 15, 15, 15, 15, 15, 15, 0, 0]);
        assert_eq!(digits(0x0102_0304), [0, 1, 0, 2, 0, 3, 0, 4, 6, 14], "120 − 10 = 0x6e");
        for b in [0, 9, 0x0102_0304, u32::MAX] {
            assert_eq!(digits_of(&b.to_be_bytes()), digits(b));
        }
        assert_eq!(digits_of(&[0; 32]).len(), E_DIGITS);
        assert_eq!(digits_of(&[0; 32])[64..], [3, 12, 0], "960 = 0x3c0");
        assert_eq!(digits_of(&[0; K_LEN]).len(), K_DIGITS);
    }

    /// The exit's inputs for counting the guests' cycles, written to
    /// `LICHEN_EXEC_DIR` (`lichen-r0 exec-babe-exit` and `exec-counter`,
    /// with no chain receipt, assume the chain journal they ask for):
    /// claims of 1 and of 8 transparent notes (8 the most a request
    /// posts), a failed counter whose `K` is a real BABE proof's points
    /// (crates/babe/tests/data), and a counter on each ground. With
    /// `LICHEN_EXEC_COUNTER`, a real counter's proof as `bitvmx-input`
    /// writes it, also the hub's countering leaf signed for it: a counter
    /// that holds, which the guest must refuse as a failed one.
    #[test]
    #[ignore]
    fn exec_inputs() {
        use crate::counter::{tests as ct, Counter};
        let dir = std::path::PathBuf::from(std::env::var("LICHEN_EXEC_DIR").expect("LICHEN_EXEC_DIR"));
        let unhex = |path: &str| -> Vec<u8> {
            let hex = std::fs::read_to_string(path).unwrap();
            (0..hex.trim().len()).step_by(2).map(|i| u8::from_str_radix(&hex.trim()[i..i + 2], 16).unwrap()).collect()
        };
        // BitVMX's input: the journal's length in words, the image id, the
        // points (a K), the journal
        let points = |input: &[u8]| input[36..36 + K_LEN].to_vec();
        let k = points(&unhex(concat!(env!("CARGO_MANIFEST_DIR"), "/../babe/tests/data/babe-60-42.hex")));
        if let Ok(path) = std::env::var("LICHEN_EXEC_COUNTER") {
            let real = unhex(&path);
            let (k, j) = (points(&real), &real[36 + K_LEN..]);
            let (d, e): (Hash, Hash) = (j[..32].try_into().unwrap(), j[32..].try_into().unwrap());
            let (s, _) = claim();
            let mode = Mode::Counter { c: 42, d, e, e_sig: sign(3, &e).try_into().unwrap(), k_sig: sign(4, &k), k };
            std::fs::write(dir.join("true-counter"), ExitStatement { mode, ..s }.to_bytes()).unwrap();
        }
        let checked = |(s, id): (ExitStatement, Hash)| {
            check_exit(&s, &id, &mut |_| true, &mut |_, _| false).unwrap();
            s.to_bytes()
        };
        for (name, b) in [
            ("claim-1", checked(claim_of(crate::exit::tests::transparent(1)))),
            ("claim-8", checked(claim_of(crate::exit::tests::transparent(crate::exit::MAX_NOTES)))),
            ("failed-counter", checked(counter(k))),
            ("counter-spend", Counter::Spent(ct::input().0).to_bytes()),
            ("counter-equivocation", Counter::Equivocation(ct::equivocation_input()).to_bytes()),
        ] {
            std::fs::write(dir.join(name), b).unwrap();
        }
    }
}
