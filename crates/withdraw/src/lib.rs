//! The withdrawal statement with validity and anchoring
//! (docs/SHIELDED_PLAN.md, phase 2, step 4; docs/ANCHOR_PLAN.md).
//! ln-gap's statement (`lngap-r0-core`'s `check`): a note owned by the
//! hub, of value `b` and memo `c`, is in the commitment tree of a state
//! root `SR` the sequencer signed. And more:
//!
//! - `SR` is anchored on Bitcoin: a chain receipt (the chain statement of
//!   `lichen-validity`, so a valid history from genesis) whose anchoring
//!   state's last anchor committed `SR`, at its height;
//! - headers on top of that anchor's block, linked, each within its own
//!   target, whose work sums to at least the contract's `W`.
//!
//! The caller checks the receipt (`verify_chain`: `env::verify(CHAIN_ID,
//! journal)` in the guest), whose journal is rebuilt here from the input.
//!
//! The journal is ln-gap's, `b ‖ c ‖ D`, with `D` per contract:
//! [`contract_id`] of the deployment, the genesis seal and `W`. A contract
//! reads it as before; only the image id it pins changes. The chain
//! guest's image id is built into the withdrawal guest, so that image id
//! pins it too.
//!
//! Integers are big-endian in the encodings, as in the other statements;
//! the journal's `b` and `c` are little-endian, as ln-gap's.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use k256::schnorr::{Signature, VerifyingKey};
use lichen_validity::btc::{self, work, Header};
use lichen_validity::{state_root, AnchorState, ChainJournal, OutPoint, TNote};
use sha2::{Digest, Sha256};

pub mod counter;
pub mod exit;
pub mod fixed;

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

/// The journal's `D` for a contract: the deployment, the genesis seal its
/// anchors descend from, and the work `W` it asks on top of an anchor.
pub fn contract_id(deployment: &Hash, genesis: &OutPoint, work: u128) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/contract");
    h.update(deployment);
    h.update(genesis.to_bytes());
    h.update(work.to_be_bytes());
    h.finalize().into()
}

/// The statement's input: ln-gap's (`lngap-r0-core`'s `WithdrawInput`) at
/// the anchored height; the rest of the chain receipt's journal; the
/// headers on top of the anchor's block; the contract's `W`.
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
    /// The chain receipt's journal, but for what's rebuilt: its height,
    /// root, recent roots' hash, history hash and anchoring state.
    pub chain_height: u64,
    pub chain_root: Hash,
    pub recent: Hash,
    pub hist: Hash,
    pub anchor: AnchorState,
    /// Headers on top of the anchor's block, from the next.
    pub headers: Vec<[u8; 80]>,
    /// The work the contract asks on top of the anchor.
    pub work: u128,
}

/// An anchored state, as a statement proves it: the state root's height
/// and nullifier tree (the commitment tree's root is the statement's own),
/// the sequencer's signature on the root, the chain receipt's journal but
/// for what's rebuilt, the headers on top of the anchor's block, and the
/// work the contract asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchored {
    pub height: u64,
    pub nullifiers: Hash,
    pub signature: [u8; 64],
    pub sequencer: Hash,
    pub hub: Hash,
    pub chain_height: u64,
    pub chain_root: Hash,
    pub recent: Hash,
    pub hist: Hash,
    pub anchor: AnchorState,
    pub headers: Vec<[u8; 80]>,
    pub work: u128,
}

impl Anchored {
    /// The state root with commitment tree `tree`.
    pub fn root(&self, tree: &Hash) -> Hash {
        state_root(self.height, tree, &self.nullifiers)
    }

    /// The chain journal a receipt must have, under the chain guest
    /// `chain_id`.
    pub fn chain_journal(&self, chain_id: &Hash) -> ChainJournal {
        ChainJournal { hub: self.hub, height: self.chain_height, root: self.chain_root, recent: self.recent, chain_id: *chain_id, hist: self.hist, anchor: self.anchor }
    }

    /// Check the state with commitment tree `tree`: its root signed by the
    /// sequencer, the last one anchored in a chain receipt of `chain_id`,
    /// with the contract's work on top. On success, the contract's `D`.
    pub fn check(&self, tree: &Hash, chain_id: &Hash, verify_chain: &mut dyn FnMut(&[u8]) -> bool) -> Result<Hash, Reject> {
        let root = self.root(tree);
        let key = VerifyingKey::from_bytes(&self.sequencer).map_err(|_| Reject::BadSignature)?;
        let sig = Signature::try_from(&self.signature[..]).map_err(|_| Reject::BadSignature)?;
        key.verify_raw(&root, &sig).map_err(|_| Reject::BadSignature)?;
        let a = &self.anchor;
        if !a.anchored() || a.root != root || a.height != self.height || a.sequencer != self.sequencer {
            return Err(Reject::NotAnchored);
        }
        if !verify_chain(&self.chain_journal(chain_id).to_bytes()) {
            return Err(Reject::Chain);
        }
        if self.headers.is_empty() || work_on(&a.block, &self.headers).is_none_or(|w| w < self.work) {
            return Err(Reject::Depth);
        }
        Ok(contract_id(&deployment_id(&self.sequencer, &self.hub), &a.genesis, self.work))
    }

    /// Whether `header` is the anchor's block, or one of the headers on
    /// it with the contract's work from it on, so as costly to forge as
    /// the anchor's. (Any header would do for the chain, but one at the
    /// tip is cheap: its own bits set its work.) For a state that
    /// [`check`](Self::check) passed, whose headers link.
    pub fn deep(&self, header: &Header) -> bool {
        let h = header.hash();
        h == self.anchor.block
            || self.headers.iter().position(|x| Header(*x).hash() == h).is_some_and(|p| self.headers[p..].iter().fold(0u128, |s, x| s.saturating_add(work(Header(*x).bits()))) >= self.work)
    }
}

/// `request` in a block, with its witness: the transaction (witness
/// serialization), the block's header, the transaction's index and path
/// in the block's witness tree, and the block's coinbase (non-witness),
/// its path in the txid tree (which fixes the trees' depth) and its
/// witness reserved value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub tx: Vec<u8>,
    pub header: [u8; 80],
    pub index: u32,
    pub path: Vec<Hash>,
    pub coinbase: Vec<u8>,
    pub coinbase_path: Vec<Hash>,
    pub reserved: Hash,
}

impl Request {
    /// The witness of the input spending `funding`: none unless the
    /// transaction spends it and is in the header's block.
    pub fn spending(&self, funding: &OutPoint) -> Option<Vec<&[u8]>> {
        if !btc::witness_in_block(&self.tx, &Header(self.header), self.index, &self.path, &self.coinbase, &self.coinbase_path, &self.reserved) {
            return None;
        }
        let t = btc::parse_witness_tx(&self.tx)?;
        let i = t.tx.inputs.iter().position(|o| o == funding)?;
        t.witness.into_iter().nth(i)
    }

    pub(crate) fn write(&self, w: &mut exit::W) {
        w.bytes(&self.tx);
        w.put(&self.header);
        w.put(&self.index.to_be_bytes());
        w.list(&self.path);
        w.bytes(&self.coinbase);
        w.list(&self.coinbase_path);
        w.put(&self.reserved);
    }

    pub(crate) fn read(r: &mut exit::R) -> Result<Request, Reject> {
        Ok(Request { tx: r.bytes()?, header: r.take()?, index: u32::from_be_bytes(r.take()?), path: r.list()?, coinbase: r.bytes()?, coinbase_path: r.list()?, reserved: r.take()? })
    }
}

/// Why an input is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    NotTheHubs,
    PathLength,
    TooLarge,
    BadSignature,
    /// No chain receipt with the input's journal.
    Chain,
    /// The signed root isn't the one last anchored in that journal.
    NotAnchored,
    /// The headers don't follow the anchor's block, or their work falls
    /// short.
    Depth,
    /// The hub's signature on `b` doesn't verify (the fixed statement's,
    /// [`fixed`]).
    HubAuth,
    /// An exit claims no notes, or more than [`exit::MAX_NOTES`].
    Notes,
    /// An exit's nullifiers aren't in increasing order, so not distinct.
    Order,
    /// A claimed note isn't in the state's commitment tree.
    NotInTree,
    /// A claimed note was spent at the state.
    Spent,
    /// No authority over a claimed note: the owner's signature on the
    /// claim, for a transparent note. For an equivocation counter, the
    /// cited claim's signature (or a shielded note, which has none).
    NotYours,
    /// An exit claims more than its notes are worth.
    Short,
    /// A counter cites the contract's own return (of at least `b`), exit
    /// record, or signed claim.
    Own,
    /// A counter's spend isn't the leaf it names in the later state, or
    /// an equivocation cites a note the claim doesn't.
    NotSpent,
    /// A counter's later state isn't in the claim's history.
    History,
    /// A counter's spend isn't shown final before the request: no request
    /// spending the contract's outpoint in a block on the later state's
    /// anchor (the contract's work on it), or within the grace before it.
    Cutoff,
    /// An exit's `E` names another funding outpoint than the contract's.
    Outpoint,
    /// The hub's counter verifies: no way to win.
    Countered,
    /// A claim's `request` doesn't carry it: not in a block on the
    /// anchor's with the contract's work on it, not spending the
    /// contract's outpoint, or not posting the claim's notes and
    /// signatures (`exit::Posted`).
    Posted,
    Encoding,
}

/// The root a leaf at `index` reaches through `path`, leaf level first.
pub(crate) fn root_from_path(leaf: Hash, index: u32, path: &[Hash]) -> Hash {
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

/// The signed (and anchored) root `input`'s note and path reach.
pub fn signed_root(input: &WithdrawInput) -> Hash {
    input.anchored().root(&input.tree())
}

/// The chain journal a receipt must have for `input`, under the chain
/// guest `chain_id`.
pub fn chain_journal(input: &WithdrawInput, chain_id: &Hash) -> ChainJournal {
    input.anchored().chain_journal(chain_id)
}

/// The work of headers on top of block `from`, if each follows the last
/// and is within its own target.
pub fn work_on(from: &Hash, headers: &[[u8; 80]]) -> Option<u128> {
    let mut prev = *from;
    let mut sum = 0u128;
    for h in headers {
        let h = Header(*h);
        if h.prev() != prev || !h.pow_ok() {
            return None;
        }
        sum = sum.saturating_add(work(h.bits()));
        prev = h.hash();
    }
    Some(sum)
}

/// The statement: check `input` against its deployment's keys and a chain
/// receipt of `chain_id`; on success, the journal `b ‖ c ‖ D`.
pub fn check(input: &WithdrawInput, chain_id: &Hash, verify_chain: &mut dyn FnMut(&[u8]) -> bool) -> Result<[u8; JOURNAL_LEN], Reject> {
    let (b, c, d) = withdrawal(input, chain_id, verify_chain)?;
    let mut journal = [0u8; JOURNAL_LEN];
    journal[..4].copy_from_slice(&b.to_le_bytes());
    journal[4..8].copy_from_slice(&c.to_le_bytes());
    journal[8..].copy_from_slice(&d);
    Ok(journal)
}

/// The withdrawal `input` proves, checked as [`check`] does: its `b`, `c`
/// and `D`.
pub fn withdrawal(input: &WithdrawInput, chain_id: &Hash, verify_chain: &mut dyn FnMut(&[u8]) -> bool) -> Result<(u32, u32, Hash), Reject> {
    if input.note.owner != input.hub {
        return Err(Reject::NotTheHubs);
    }
    if input.path.len() != TREE_DEPTH {
        return Err(Reject::PathLength);
    }
    let b = u32::try_from(input.note.value).map_err(|_| Reject::TooLarge)?;
    let d = input.anchored().check(&input.tree(), chain_id, verify_chain)?;
    Ok((b, input.note.memo, d))
}

// ----- the encoding: what the withdrawal guest reads -----

impl WithdrawInput {
    /// The commitment tree's root its note and path reach.
    pub fn tree(&self) -> Hash {
        root_from_path(self.note.commitment(), self.index, &self.path)
    }

    /// The anchored state it proves the return in.
    pub fn anchored(&self) -> Anchored {
        Anchored {
            height: self.height,
            nullifiers: self.nullifiers,
            signature: self.signature,
            sequencer: self.sequencer,
            hub: self.hub,
            chain_height: self.chain_height,
            chain_root: self.chain_root,
            recent: self.recent,
            hist: self.hist,
            anchor: self.anchor,
            headers: self.headers.clone(),
            work: self.work,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(600 + 32 * self.path.len() + 80 * self.headers.len());
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
        w.extend_from_slice(&self.chain_height.to_be_bytes());
        w.extend_from_slice(&self.chain_root);
        w.extend_from_slice(&self.recent);
        w.extend_from_slice(&self.hist);
        w.extend_from_slice(&self.anchor.to_bytes());
        w.extend_from_slice(&(self.headers.len() as u32).to_be_bytes());
        for h in &self.headers {
            w.extend_from_slice(h);
        }
        w.extend_from_slice(&self.work.to_be_bytes());
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
        fn list<const N: usize>(r: &mut &[u8]) -> Result<Vec<[u8; N]>, Reject> {
            let n = u32::from_be_bytes(take(r)?) as usize;
            if n > r.len() / N {
                return Err(Reject::Encoding);
            }
            (0..n).map(|_| take(r)).collect()
        }
        let height = u64::from_be_bytes(take(&mut r)?);
        let nullifiers = take(&mut r)?;
        let signature = take(&mut r)?;
        let note = TNote { owner: take(&mut r)?, value: u64::from_be_bytes(take(&mut r)?), memo: u32::from_be_bytes(take(&mut r)?), rho: take(&mut r)? };
        let index = u32::from_be_bytes(take(&mut r)?);
        let path = list::<32>(&mut r)?;
        let (sequencer, hub) = (take(&mut r)?, take(&mut r)?);
        let chain_height = u64::from_be_bytes(take(&mut r)?);
        let (chain_root, recent, hist) = (take(&mut r)?, take(&mut r)?, take(&mut r)?);
        let anchor = AnchorState::from_bytes(&take::<176>(&mut r)?).map_err(|_| Reject::Encoding)?;
        let headers = list::<80>(&mut r)?;
        let work = u128::from_be_bytes(take(&mut r)?);
        if !r.is_empty() {
            return Err(Reject::Encoding);
        }
        Ok(WithdrawInput { height, nullifiers, signature, note, index, path, sequencer, hub, chain_height, chain_root, recent, hist, anchor, headers, work })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use k256::schnorr::SigningKey;
    use lichen_validity::btc::sha256d;

    pub(crate) fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32]).unwrap()
    }

    pub(crate) fn xonly(k: &SigningKey) -> Hash {
        k.verifying_key().to_bytes().into()
    }

    fn varint(n: usize) -> Vec<u8> {
        if n < 0xfd {
            std::vec![n as u8]
        } else {
            [&[0xfd][..], &(n as u16).to_le_bytes()].concat()
        }
    }

    /// A transaction spending `op` with the witness `items`: its witness
    /// serialization, and its txid.
    pub(crate) fn tx_spending(op: &OutPoint, items: &[&[u8]]) -> (Vec<u8>, Hash) {
        let mut body = std::vec![1];
        body.extend_from_slice(&op.to_bytes());
        body.extend_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 1]);
        body.extend_from_slice(&1000u64.to_le_bytes());
        body.extend_from_slice(&[1, 0x51]);
        let mut witness = varint(items.len());
        for i in items {
            witness.extend(varint(i.len()));
            witness.extend_from_slice(i);
        }
        let (version, lock) = ([2u8, 0, 0, 0], [0u8; 4]);
        (std::vec![&version[..], &[0, 1], &body, &witness, &lock].concat(), sha256d(&[&version[..], &body, &lock].concat()))
    }

    /// A coinbase (non-witness) committing `commitment`, with a script of
    /// two bytes.
    fn coinbase(commitment: &Hash) -> Vec<u8> {
        let mut c = std::vec![2, 0, 0, 0, 1];
        c.extend_from_slice(&OutPoint { txid: [0; 32], vout: u32::MAX }.to_bytes());
        c.extend_from_slice(&[2, 1, 7, 0xff, 0xff, 0xff, 0xff, 1]);
        c.extend_from_slice(&0u64.to_le_bytes());
        c.extend_from_slice(&[38, 0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
        c.extend_from_slice(commitment);
        c.extend_from_slice(&[0; 4]);
        c
    }

    fn pair(a: &Hash, b: &Hash) -> Hash {
        sha256d(&[&a[..], b].concat())
    }

    /// A block on `prev` of a coinbase and `tx` (its witness serialization
    /// and txid): its header, and `tx` in it as a [`Request`].
    pub(crate) fn block_with(prev: &Hash, (tx, txid): (Vec<u8>, Hash)) -> ([u8; 80], Request) {
        let reserved = [0x5a; 32];
        let wtxid = sha256d(&tx);
        let cb = coinbase(&pair(&pair(&[0; 32], &wtxid), &reserved));
        let cb_id = sha256d(&cb);
        let header = header_with(prev, &pair(&cb_id, &txid));
        (header, Request { tx, header, index: 1, path: std::vec![[0; 32]], coinbase: cb, coinbase_path: std::vec![txid], reserved })
    }

    /// A header on `prev` at regtest's difficulty (work 2), its nonce
    /// ground until it is within its target.
    fn header_on(prev: &Hash) -> [u8; 80] {
        header_with(prev, &[0; 32])
    }

    /// As [`header_on`], its block's Merkle root `merkle`.
    pub(crate) fn header_with(prev: &Hash, merkle: &Hash) -> [u8; 80] {
        let mut h = [0u8; 80];
        h[4..36].copy_from_slice(prev);
        h[36..68].copy_from_slice(merkle);
        h[72..76].copy_from_slice(&0x207fffffu32.to_le_bytes());
        for n in 0u32.. {
            h[76..].copy_from_slice(&n.to_le_bytes());
            if Header(h).pow_ok() {
                return h;
            }
        }
        unreachable!()
    }

    pub(crate) fn headers_on(from: &Hash, n: usize) -> Vec<[u8; 80]> {
        let mut out: Vec<[u8; 80]> = Vec::new();
        for _ in 0..n {
            let prev = out.last().map_or(*from, |h| sha256d(h));
            out.push(header_on(&prev));
        }
        out
    }

    /// A return of 9 with memo 42 alone in the tree (index 0, empty
    /// siblings), its root signed at height 3 and anchored, the chain
    /// receipt at height 5; ten headers on the anchor's block, the
    /// contract asking for the work of ten; a chain id.
    pub(crate) fn input() -> (WithdrawInput, Hash) {
        (input_of(9), [8; 32])
    }

    /// As [`input`], a return of `value`.
    pub(crate) fn input_of(value: u64) -> WithdrawInput {
        let (seq, hub) = (key(1), key(2));
        let note = TNote { owner: xonly(&hub), value, memo: 42, rho: [7; 32] };
        let path = lichen_validity::tree_empties()[..TREE_DEPTH].to_vec();
        let nullifiers = [5; 32];
        let root = state_root(3, &root_from_path(note.commitment(), 0, &path), &nullifiers);
        let signature = seq.sign_raw(&root, &[0; 32]).unwrap().to_bytes();
        let genesis = OutPoint { txid: [3; 32], vout: 1 };
        let anchor = AnchorState { genesis, sequencer: xonly(&seq), seal: OutPoint { txid: [4; 32], vout: 0 }, height: 3, root, block: [9; 32] };
        let headers = headers_on(&anchor.block, 10);
        WithdrawInput { height: 3, nullifiers, signature, note, index: 0, path, sequencer: xonly(&seq), hub: xonly(&hub), chain_height: 5, chain_root: [8; 32], recent: [6; 32], hist: [10; 32], anchor, headers, work: 10 * work(0x207fffff) }
    }

    #[test]
    fn a_return_under_an_anchored_root() {
        let (i, id) = input();
        let expected = chain_journal(&i, &id).to_bytes();
        let j = check(&i, &id, &mut |c| c == expected).unwrap();
        assert_eq!(&j[..4], &9u32.to_le_bytes());
        assert_eq!(&j[4..8], &42u32.to_le_bytes());
        assert_eq!(&j[8..], &contract_id(&deployment_id(&i.sequencer, &i.hub), &i.anchor.genesis, i.work));
        // the chain journal is the chain guest's, its anchor the input's
        let c = chain_journal(&i, &id);
        assert_eq!((c.hub, c.height, c.recent, c.chain_id, c.anchor), (i.hub, 5, [6; 32], id, i.anchor));
        // the encoding round-trips, and refuses a byte more or less
        assert_eq!(WithdrawInput::from_bytes(&i.to_bytes()).unwrap(), i);
        assert_eq!(WithdrawInput::from_bytes(&i.to_bytes()[1..]), Err(Reject::Encoding));
        let mut long = i.to_bytes();
        long.push(0);
        assert_eq!(WithdrawInput::from_bytes(&long), Err(Reject::Encoding));
        // D is the contract's: another W, another genesis, another D
        let mut w = i.clone();
        w.work -= 1;
        assert_ne!(check(&w, &id, &mut |_| true).unwrap()[8..], j[8..]);
    }

    #[test]
    fn what_the_statement_refuses() {
        let (i, id) = input();
        let good = chain_journal(&i, &id).to_bytes();
        let mut ok = |c: &[u8]| c == good;
        // no chain receipt with the journal, or one of another height,
        // recent roots, history, hub or chain guest
        assert_eq!(check(&i, &id, &mut |_| false), Err(Reject::Chain));
        for f in [|i: &mut WithdrawInput| i.recent = [0; 32], |i: &mut WithdrawInput| i.chain_height = 6, |i: &mut WithdrawInput| i.hist = [0; 32]] {
            let mut other = i.clone();
            f(&mut other);
            assert_eq!(check(&other, &id, &mut ok), Err(Reject::Chain));
        }
        assert_eq!(check(&i, &[0; 32], &mut ok), Err(Reject::Chain));
        // a height the signature isn't on
        let mut h = i.clone();
        h.height = 4;
        assert_eq!(check(&h, &id, &mut |_| true), Err(Reject::BadSignature));
        // a signed root that isn't the anchored one: another root, no
        // anchor yet, another sequencer's anchors
        let mut a = i.clone();
        a.anchor.root = [0; 32];
        assert_eq!(check(&a, &id, &mut |_| true), Err(Reject::NotAnchored));
        let mut a = i.clone();
        a.anchor.height = 0;
        assert_eq!(check(&a, &id, &mut |_| true), Err(Reject::NotAnchored));
        let mut a = i.clone();
        a.anchor.sequencer = [1; 32];
        assert_eq!(check(&a, &id, &mut |_| true), Err(Reject::NotAnchored));
        // headers: too little work, none, not on the anchor's block, not
        // linked, not within their target
        let mut d = i.clone();
        d.headers.pop();
        assert_eq!(check(&d, &id, &mut |_| true), Err(Reject::Depth));
        let mut d = i.clone();
        d.headers.clear();
        d.work = 0;
        assert_eq!(check(&d, &id, &mut |_| true), Err(Reject::Depth));
        let mut d = i.clone();
        d.headers = headers_on(&[1; 32], 10);
        assert_eq!(check(&d, &id, &mut |_| true), Err(Reject::Depth));
        let mut d = i.clone();
        d.headers.remove(4);
        d.work = 0;
        assert_eq!(check(&d, &id, &mut |_| true), Err(Reject::Depth));
        let mut d = i.clone();
        let mut hard = d.headers[9];
        hard[72..76].copy_from_slice(&0x1d00ffffu32.to_le_bytes());
        d.headers[9] = hard;
        assert_eq!(check(&d, &id, &mut |_| true), Err(Reject::Depth), "a header claiming mainnet's work without it");
        // the work is a sum: more headers of less work each would do too
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

    #[test]
    fn work_and_targets() {
        // regtest's bits: target 0x7fffff · 256^29, work 2
        assert_eq!(work(0x207fffff), 2);
        let t = lichen_validity::btc::target(0x207fffff).unwrap();
        assert_eq!((t[0], t[1], t[2], t[3]), (0x7f, 0xff, 0xff, 0));
        // mainnet's genesis: 0x1d00ffff, work 2^32 + 2^16 + 1 (about 2^32)
        assert_eq!(work(0x1d00ffff), (1u128 << 48) / 0xffff);
        assert_eq!(work(0x1d00ffff), 4295032833);
        // no target: negative, zero
        assert_eq!(work(0x1d800000), 0);
        assert_eq!(work(0x1d000000), 0);
        assert!(lichen_validity::btc::target(0x22010000).is_none(), "beyond 256 bits");
    }
}
