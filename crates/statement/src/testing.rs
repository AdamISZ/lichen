//! Fixtures for an L2's tests (feature `testing`): blocks at regtest's
//! difficulty, the exit's transactions in them, and an exit as the hub
//! shows it. Signatures and scripts are faked: the statement reads only
//! what Bitcoin's checks would leave it (digits, inclusions, work).

use alloc::{vec, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};

use crate::btc::{self, sha256d, work, Header, OutPoint};
use crate::{claim_script, checksum_digits, Checkpoint, Contract, Exit, Hash, Request, Respond, SlotSpend, SLOT_VOUT};

fn varint(n: usize) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else {
        [&[0xfd][..], &(n as u16).to_le_bytes()].concat()
    }
}

fn pair(a: &Hash, b: &Hash) -> Hash {
    sha256d(&[&a[..], b].concat())
}

/// A coinbase (non-witness) committing `commitment`, with a script of
/// two bytes.
fn coinbase(commitment: &Hash) -> Vec<u8> {
    let mut c = vec![2, 0, 0, 0, 1];
    c.extend_from_slice(&OutPoint { txid: [0; 32], vout: u32::MAX }.to_bytes());
    c.extend_from_slice(&[2, 1, 7, 0xff, 0xff, 0xff, 0xff, 1]);
    c.extend_from_slice(&0u64.to_le_bytes());
    c.extend_from_slice(&[38, 0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
    c.extend_from_slice(commitment);
    c.extend_from_slice(&[0; 4]);
    c
}

/// A transaction spending `op` with `witness`: its witness serialization,
/// and its txid.
pub fn tx_spending(op: &OutPoint, witness: &[Vec<u8>]) -> (Vec<u8>, Hash) {
    let mut body = vec![1];
    body.extend_from_slice(&op.to_bytes());
    body.extend_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 1]);
    body.extend_from_slice(&1000u64.to_le_bytes());
    body.extend_from_slice(&[1, 0x51]);
    let mut items = varint(witness.len());
    for i in witness {
        items.extend(varint(i.len()));
        items.extend_from_slice(i);
    }
    let (version, lock) = ([2u8, 0, 0, 0], [0u8; 4]);
    ([&version[..], &[0, 1], &body, &items, &lock].concat(), sha256d(&[&version[..], &body, &lock].concat()))
}

/// A transaction (non-witness) spending `op`.
pub fn spend_of(op: &OutPoint) -> Vec<u8> {
    let mut t = vec![2, 0, 0, 0, 1];
    t.extend_from_slice(&op.to_bytes());
    t.extend_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 1]);
    t.extend_from_slice(&900u64.to_le_bytes());
    t.extend_from_slice(&[1, 0x51, 0, 0, 0, 0]);
    t
}

/// A funding transaction spending `deposit` (non-witness), and its
/// output 0.
pub fn funding_of(deposit: &OutPoint) -> (Vec<u8>, OutPoint) {
    let mut f = vec![2, 0, 0, 0, 1];
    f.extend_from_slice(&deposit.to_bytes());
    f.extend_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 1]);
    f.extend_from_slice(&5000u64.to_le_bytes());
    f.extend_from_slice(&[1, 0x51, 0, 0, 0, 0]);
    let o = OutPoint { txid: sha256d(&f), vout: 0 };
    (f, o)
}

/// The time of the next header: each later than the last, as Bitcoin's
/// median-time rule wants of a chain an L2 checks in full.
static TIME: AtomicU32 = AtomicU32::new(1_700_000_000);

/// A header on `prev` of a block whose Merkle root is `merkle`, at
/// regtest's difficulty (work 2), its nonce ground until it is within
/// its target. Its version is BIP9's and its time later than any header
/// before it, so that a chain of them is one Bitcoin accepts.
pub fn header_with(prev: &Hash, merkle: &Hash) -> [u8; 80] {
    let mut h = [0u8; 80];
    h[..4].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    h[4..36].copy_from_slice(prev);
    h[68..72].copy_from_slice(&TIME.fetch_add(600, Ordering::Relaxed).to_le_bytes());
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

/// `n` empty headers on block `from`.
pub fn headers_on(from: &Hash, n: usize) -> Vec<[u8; 80]> {
    let mut out: Vec<[u8; 80]> = Vec::new();
    for _ in 0..n {
        let prev = out.last().map_or(*from, |h| sha256d(h));
        out.push(header_with(&prev, &[0; 32]));
    }
    out
}

/// A block on `prev` of a coinbase and `tx` (its witness serialization
/// and txid): its header, and `tx` in it as a [`Request`] of no funding.
pub fn block_with(prev: &Hash, (tx, txid): (Vec<u8>, Hash)) -> ([u8; 80], Request) {
    let reserved = [0x5a; 32];
    let wtxid = sha256d(&tx);
    let cb = coinbase(&pair(&pair(&[0; 32], &wtxid), &reserved));
    let cb_id = sha256d(&cb);
    let header = header_with(prev, &pair(&cb_id, &txid));
    (header, Request { funding: vec![], tx, header, index: 1, path: vec![[0; 32]], coinbase: cb, coinbase_path: vec![txid], reserved })
}

/// A request: a transaction spending the funding of `deposit` with
/// `witness`, in a block on `prev`.
pub fn request_on(prev: &Hash, deposit: &OutPoint, witness: &[Vec<u8>]) -> ([u8; 80], Request) {
    let (f, o) = funding_of(deposit);
    let (header, r) = block_with(prev, tx_spending(&o, witness));
    (header, Request { funding: f, ..r })
}

fn scriptnum(d: u8) -> Vec<u8> {
    if d == 0 {
        vec![]
    } else {
        vec![d]
    }
}

/// A Winternitz signature's witness items on `msg` (hashes faked: only
/// the digits are read), bottom first.
pub fn wots_items(msg: &[u8]) -> Vec<Vec<u8>> {
    let mut digits: Vec<u8> = msg.iter().flat_map(|b| [b >> 4, b & 0xf]).collect();
    let n = checksum_digits(msg.len());
    let mut sum: u32 = digits.iter().map(|d| 15 - u32::from(*d)).sum();
    let at = digits.len();
    digits.resize(at + n, 0);
    for x in digits[at..].iter_mut().rev() {
        *x = (sum % 16) as u8;
        sum /= 16;
    }
    digits.iter().flat_map(|d| [vec![0x11; 20], scriptnum(*d)]).collect()
}

/// The 2-of-2's signatures, the script and the control block, on top of
/// a link's witness.
fn tapscript_top() -> [Vec<u8>; 4] {
    [vec![1; 64], vec![2; 64], vec![0x51], vec![0xc0; 33]]
}

/// `request`'s witness of `b` with `E` `e`.
pub fn request_witness(e: &Hash, b: u32) -> Vec<Vec<u8>> {
    let mut w = wots_items(e);
    w.extend(wots_items(&b.to_be_bytes()));
    w.extend(tapscript_top());
    w
}

/// `respond`'s witness of `b′`, `extra` items below it.
pub fn respond_witness(b: u32, extra: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut w = extra.to_vec();
    w.extend(wots_items(&b.to_be_bytes()));
    w.extend(tapscript_top());
    w
}

/// A spend of `op` (non-witness) whose only output carries `bytes` in
/// nulldata ([`claim_script`]).
pub fn publication(op: &OutPoint, bytes: &[u8]) -> Vec<u8> {
    let mut t = spend_of(op);
    t.truncate(t.len() - 6); // Replace the output script and locktime.
    let script = claim_script(bytes).unwrap();
    t.extend(varint(script.len()));
    t.extend(script);
    t.extend_from_slice(&[0; 4]);
    t
}

/// `tx` (non-witness) in a block on `prev`, as a [`SlotSpend`].
pub fn slot_spend_on(prev: &Hash, tx: Vec<u8>) -> SlotSpend {
    let (header, p) = block_with(prev, (tx.clone(), sha256d(&tx)));
    SlotSpend { tx, header, index: p.index, path: vec![sha256d(&p.coinbase)], coinbase: p.coinbase, coinbase_path: p.coinbase_path }
}

/// The spend of `slot` carrying `bytes`, in a block on `prev`.
pub fn published(prev: &Hash, slot: &OutPoint, bytes: &[u8]) -> SlotSpend {
    slot_spend_on(prev, publication(slot, bytes))
}

/// A spend of `op` with `witness` in a block on `prev`: its header, and
/// it as a [`Respond`].
pub fn respond_spending(prev: &Hash, op: &OutPoint, witness: &[Vec<u8>]) -> ([u8; 80], Respond) {
    let (h, r) = block_with(prev, tx_spending(op, witness));
    (h, Respond { tx: r.tx, header: h, index: r.index, path: r.path, coinbase: r.coinbase, coinbase_path: r.coinbase_path, reserved: r.reserved })
}

/// The hub's `respond` of `b′` to `request` (witness serialization) in a
/// block on `prev`.
pub fn respond_block(prev: &Hash, request: &[u8], b2: u32) -> ([u8; 80], Respond) {
    let op = OutPoint { txid: sha256d(&btc::bare_tx(request).unwrap()), vout: 0 };
    respond_spending(prev, &op, &respond_witness(b2, &[]))
}

/// A contract and its exit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X {
    pub contract: Contract,
    pub exit: Exit,
}

/// An exit of contract 1007 (checkpoint at height 100, `W` ten regtest
/// blocks): `request` with `witness` in the first block on the
/// checkpoint, her publication `publish(prev, slot)` in the next (`prev`
/// the request's block, `slot` its slot), ten more, the hub's `respond`
/// of `b′`, ten more.
pub fn exit_publishing(witness: &[Vec<u8>], publish: impl FnOnce(&Hash, &OutPoint) -> SlotSpend, b2: u32) -> X {
    let checkpoint = Checkpoint { height: 100, hash: [0x0c; 32] };
    let deposit = OutPoint { txid: [0xd0; 32], vout: 1 };
    let (rh, request) = request_on(&checkpoint.hash, &deposit, witness);
    let slot = OutPoint { txid: request.txid().unwrap(), vout: SLOT_VOUT };
    let publish = publish(&sha256d(&rh), &slot);
    let mut headers = vec![rh, publish.header];
    headers.extend(headers_on(&sha256d(&publish.header), 10));
    let (h, respond) = respond_block(&sha256d(headers.last().unwrap()), &request.tx, b2);
    headers.push(h);
    headers.extend(headers_on(&sha256d(&h), 10));
    let contract = Contract { c: 1007, d: [0xdd; 32], deposit, checkpoint, work: 10 * work(0x207fffff) };
    X { contract, exit: Exit { headers, request, publish, respond, disclosure: None } }
}

/// [`exit_publishing`] her publication carrying `claim`.
pub fn exit_with(witness: &[Vec<u8>], claim: &[u8], b2: u32) -> X {
    exit_publishing(witness, |prev, slot| published(prev, slot, claim), b2)
}

/// [`exit_with`] her request of `b` with `E` `e`.
pub fn exit(b: u32, e: Hash, claim: &[u8], b2: u32) -> X {
    exit_with(&request_witness(&e, b), claim, b2)
}

impl X {
    /// `respond`'s slot.
    pub fn disclose_slot(&self) -> OutPoint {
        OutPoint { txid: sha256d(&btc::bare_tx(&self.exit.respond.tx).unwrap()), vout: SLOT_VOUT }
    }

    /// The hub discloses `bytes`, spending `slot`, in a block on the last
    /// header; ten headers on it.
    pub fn disclose_from(&mut self, slot: &OutPoint, bytes: &[u8]) {
        let d = published(&sha256d(self.exit.headers.last().unwrap()), slot, bytes);
        self.exit.headers.push(d.header);
        self.exit.headers.extend(headers_on(&sha256d(&d.header), 10));
        self.exit.disclosure = Some(d);
    }

    /// The hub discloses `bytes`, spending `respond`'s slot.
    pub fn disclose(&mut self, bytes: &[u8]) {
        self.disclose_from(&self.disclose_slot(), bytes);
    }
}
