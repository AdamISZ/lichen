//! The withdrawal statement with validity (docs/SHIELDED_PLAN.md, phase 2,
//! step 4). ln-gap's statement (`lngap-r0-core`'s `check`), unchanged: a
//! note owned by the hub, of value `b` and memo `c`, is in the commitment
//! tree of a state root `SR` the sequencer signed. And one more check: a
//! chain receipt ends at `SR`, at its height, under the same hub, so `SR`
//! ends a valid history from genesis (the chain statement of
//! `lichen-validity`). The caller checks the receipt (`verify_chain`:
//! `env::verify(CHAIN_ID, journal)` in the guest), whose journal is
//! rebuilt here from the input.
//!
//! The journal is ln-gap's, `b ‖ c ‖ D`, so a contract reads it as before;
//! only the image id it pins changes. The chain guest's image id is built
//! into the withdrawal guest, so that image id pins it too.
//!
//! Integers are big-endian in the encodings, as in the other statements;
//! the journal's `b` and `c` are little-endian, as ln-gap's.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use k256::schnorr::{Signature, VerifyingKey};
use lichen_validity::{state_root, ChainJournal, TNote};
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// The commitment tree's depth (the withdrawal statement's).
pub const TREE_DEPTH: usize = 16;

/// The journal's length in bytes: `b ‖ c ‖ D`.
pub const JOURNAL_LEN: usize = 40;

/// A deployment's id: its sequencer's and hub's keys (x-only), hashed
/// (`lngap-r0-core`'s `deployment_id`).
pub fn deployment_id(sequencer: &Hash, hub: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lngap/deployment");
    h.update(sequencer);
    h.update(hub);
    h.finalize().into()
}

/// The statement's input: ln-gap's (`lngap-r0-core`'s `WithdrawInput`),
/// and the recent roots' hash of the chain receipt at its height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithdrawInput {
    pub height: u64,
    /// The nullifier tree's root at that height.
    pub nullifiers: Hash,
    /// The sequencer's BIP340 signature on the state root.
    pub signature: [u8; 64],
    /// The return: a note owned by the hub, value `b`, memo `c`.
    pub note: TNote,
    pub index: u32,
    pub path: Vec<Hash>,
    /// The deployment: its sequencer's and hub's keys (x-only).
    pub sequencer: Hash,
    pub hub: Hash,
    /// The chain journal's `recent` at `height`.
    pub recent: Hash,
}

/// Why an input is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    NotTheHubs,
    PathLength,
    TooLarge,
    BadSignature,
    /// No chain receipt ends at the signed root.
    Chain,
    Encoding,
}

/// The root a leaf at `index` reaches through `path`, leaf level first.
fn root_from_path(leaf: Hash, index: u32, path: &[Hash]) -> Hash {
    let node = |l: &Hash, r: &Hash| -> Hash {
        let mut h = Sha256::new();
        h.update(l);
        h.update(r);
        h.finalize().into()
    };
    let mut h = leaf;
    for (level, sib) in path.iter().enumerate() {
        h = if (index >> level) & 1 == 1 { node(sib, &h) } else { node(&h, sib) };
    }
    h
}

/// The chain journal a receipt must have for `input`'s root, under the
/// chain guest `chain_id`.
pub fn chain_journal(input: &WithdrawInput, chain_id: &Hash) -> ChainJournal {
    let tree = root_from_path(input.note.commitment(), input.index, &input.path);
    ChainJournal { hub: input.hub, height: input.height, root: state_root(input.height, &tree, &input.nullifiers), recent: input.recent, chain_id: *chain_id }
}

/// The statement: check `input` against its deployment's keys and a chain
/// receipt of `chain_id`; on success, the journal `b ‖ c ‖ D`.
pub fn check(input: &WithdrawInput, chain_id: &Hash, verify_chain: &mut dyn FnMut(&[u8]) -> bool) -> Result<[u8; JOURNAL_LEN], Reject> {
    if input.note.owner != input.hub {
        return Err(Reject::NotTheHubs);
    }
    if input.path.len() != TREE_DEPTH {
        return Err(Reject::PathLength);
    }
    let b = u32::try_from(input.note.value).map_err(|_| Reject::TooLarge)?;
    let chain = chain_journal(input, chain_id);
    let key = VerifyingKey::from_bytes(&input.sequencer).map_err(|_| Reject::BadSignature)?;
    let sig = Signature::try_from(&input.signature[..]).map_err(|_| Reject::BadSignature)?;
    key.verify_raw(&chain.root, &sig).map_err(|_| Reject::BadSignature)?;
    if !verify_chain(&chain.to_bytes()) {
        return Err(Reject::Chain);
    }
    let mut journal = [0u8; JOURNAL_LEN];
    journal[..4].copy_from_slice(&b.to_le_bytes());
    journal[4..8].copy_from_slice(&input.note.memo.to_le_bytes());
    journal[8..].copy_from_slice(&deployment_id(&input.sequencer, &input.hub));
    Ok(journal)
}

// ----- the encoding: what the withdrawal guest reads -----

impl WithdrawInput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(320 + 32 * self.path.len());
        w.extend_from_slice(&self.height.to_be_bytes());
        w.extend_from_slice(&self.nullifiers);
        w.extend_from_slice(&self.signature);
        w.extend_from_slice(&self.note.owner);
        w.extend_from_slice(&self.note.value.to_be_bytes());
        w.extend_from_slice(&self.note.memo.to_be_bytes());
        w.extend_from_slice(&self.note.rho);
        w.extend_from_slice(&self.index.to_be_bytes());
        w.extend_from_slice(&(self.path.len() as u32).to_be_bytes());
        for h in &self.path {
            w.extend_from_slice(h);
        }
        w.extend_from_slice(&self.sequencer);
        w.extend_from_slice(&self.hub);
        w.extend_from_slice(&self.recent);
        w
    }

    pub fn from_bytes(b: &[u8]) -> Result<WithdrawInput, Reject> {
        let mut r = b;
        fn take<const N: usize>(r: &mut &[u8]) -> Result<[u8; N], Reject> {
            if r.len() < N {
                return Err(Reject::Encoding);
            }
            let (a, rest) = r.split_at(N);
            *r = rest;
            Ok(a.try_into().unwrap())
        }
        let height = u64::from_be_bytes(take(&mut r)?);
        let nullifiers = take(&mut r)?;
        let signature = take(&mut r)?;
        let note = TNote { owner: take(&mut r)?, value: u64::from_be_bytes(take(&mut r)?), memo: u32::from_be_bytes(take(&mut r)?), rho: take(&mut r)? };
        let index = u32::from_be_bytes(take(&mut r)?);
        let n = u32::from_be_bytes(take(&mut r)?) as usize;
        if n > r.len() / 32 {
            return Err(Reject::Encoding);
        }
        let path = (0..n).map(|_| take(&mut r)).collect::<Result<Vec<Hash>, _>>()?;
        let input = WithdrawInput { height, nullifiers, signature, note, index, path, sequencer: take(&mut r)?, hub: take(&mut r)?, recent: take(&mut r)? };
        if !r.is_empty() {
            return Err(Reject::Encoding);
        }
        Ok(input)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use k256::schnorr::SigningKey;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32]).unwrap()
    }

    fn xonly(k: &SigningKey) -> Hash {
        k.verifying_key().to_bytes().into()
    }

    /// A return of 9 with memo 42 alone in the tree (index 0, empty
    /// siblings), its root signed at height 3; a chain id.
    fn input() -> (WithdrawInput, Hash) {
        let (seq, hub) = (key(1), key(2));
        let note = TNote { owner: xonly(&hub), value: 9, memo: 42, rho: [7; 32] };
        let path = lichen_validity::tree_empties()[..TREE_DEPTH].to_vec();
        let nullifiers = [5; 32];
        let root = state_root(3, &root_from_path(note.commitment(), 0, &path), &nullifiers);
        let signature = seq.sign_raw(&root, &[0; 32]).unwrap().to_bytes();
        (WithdrawInput { height: 3, nullifiers, signature, note, index: 0, path, sequencer: xonly(&seq), hub: xonly(&hub), recent: [6; 32] }, [8; 32])
    }

    #[test]
    fn a_return_under_a_proven_root() {
        let (i, id) = input();
        let expected = chain_journal(&i, &id).to_bytes();
        let j = check(&i, &id, &mut |c| c == expected).unwrap();
        assert_eq!(&j[..4], &9u32.to_le_bytes());
        assert_eq!(&j[4..8], &42u32.to_le_bytes());
        assert_eq!(&j[8..], &deployment_id(&i.sequencer, &i.hub));
        // the chain journal is the chain guest's, at the signed root
        let c = chain_journal(&i, &id);
        assert_eq!((c.hub, c.height, c.recent, c.chain_id), (i.hub, 3, [6; 32], id));
        // the encoding round-trips, and refuses a byte more or less
        assert_eq!(WithdrawInput::from_bytes(&i.to_bytes()).unwrap(), i);
        assert_eq!(WithdrawInput::from_bytes(&i.to_bytes()[1..]), Err(Reject::Encoding));
        let mut long = i.to_bytes();
        long.push(0);
        assert_eq!(WithdrawInput::from_bytes(&long), Err(Reject::Encoding));
    }

    #[test]
    fn what_the_statement_refuses() {
        let (i, id) = input();
        let good = chain_journal(&i, &id).to_bytes();
        let mut ok = |c: &[u8]| c == good;
        // no chain receipt at the root, or one of another height, recent
        // roots, hub or chain guest
        assert_eq!(check(&i, &id, &mut |_| false), Err(Reject::Chain));
        let mut other = i.clone();
        other.recent = [0; 32];
        assert_eq!(check(&other, &id, &mut ok), Err(Reject::Chain));
        assert_eq!(check(&i, &[0; 32], &mut ok), Err(Reject::Chain));
        // a height the signature isn't on
        let mut h = i.clone();
        h.height = 4;
        assert_eq!(check(&h, &id, &mut |_| true), Err(Reject::BadSignature));
        // not the hub's note; a short path; a value over u32
        let mut n = i.clone();
        n.hub = [1; 32];
        assert_eq!(check(&n, &id, &mut |_| true), Err(Reject::NotTheHubs));
        let mut p = i.clone();
        p.path.pop();
        assert_eq!(check(&p, &id, &mut |_| true), Err(Reject::PathLength));
        let mut v = i.clone();
        v.note.value = 1 << 32;
        assert_eq!(check(&v, &id, &mut |_| true), Err(Reject::TooLarge));
        // another value under the same signature: not the signed root
        let mut b = i.clone();
        b.note.value = 10;
        assert_eq!(check(&b, &id, &mut |_| true), Err(Reject::BadSignature));
    }
}
