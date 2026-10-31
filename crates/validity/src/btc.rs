//! What the statements read of Bitcoin (docs/ANCHOR_PLAN.md): a
//! transaction's non-witness serialization (its txid's), a block header,
//! a Merkle path from a txid to the header's root, and proof of work;
//! and, for what a transaction carries in its witness, its witness
//! serialization and a path in the block's witness tree (BIP141).
//! Hashes in Bitcoin's internal byte order, as they are hashed (a txid or
//! block hash displayed is this reversed).

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::Hash;

pub fn sha256d(data: &[u8]) -> Hash {
    Sha256::digest(Sha256::digest(data)).into()
}

/// An outpoint: a txid (internal order) and an output's index.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutPoint {
    pub txid: Hash,
    pub vout: u32,
}

impl OutPoint {
    /// As a transaction's input names it: the txid, then the index (LE).
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut b = [0u8; 36];
        b[..32].copy_from_slice(&self.txid);
        b[32..].copy_from_slice(&self.vout.to_le_bytes());
        b
    }
    pub fn from_bytes(b: &[u8; 36]) -> OutPoint {
        OutPoint { txid: b[..32].try_into().unwrap(), vout: u32::from_le_bytes(b[32..].try_into().unwrap()) }
    }
}

/// A block header, 80 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header(pub [u8; 80]);

impl Header {
    pub fn hash(&self) -> Hash {
        sha256d(&self.0)
    }
    pub fn prev(&self) -> Hash {
        self.0[4..36].try_into().unwrap()
    }
    pub fn merkle_root(&self) -> Hash {
        self.0[36..68].try_into().unwrap()
    }
    pub fn bits(&self) -> u32 {
        u32::from_le_bytes(self.0[72..76].try_into().unwrap())
    }
    /// Its hash is within the target its bits claim.
    pub fn pow_ok(&self) -> bool {
        let Some(target) = target(self.bits()) else { return false };
        let mut h = self.hash();
        h.reverse();
        h <= target
    }
}

/// The target of compact bits, big-endian; none if negative, zero or
/// beyond 256 bits.
pub fn target(bits: u32) -> Option<[u8; 32]> {
    let (e, m) = ((bits >> 24) as usize, bits & 0x00ff_ffff);
    if m == 0 || m & 0x0080_0000 != 0 {
        return None;
    }
    let mut t = [0u8; 32];
    let m = m.to_be_bytes(); // [0, m2, m1, m0]
    for (k, &byte) in m[1..].iter().enumerate() {
        // byte k of the mantissa is worth 256^(e - 1 - k)
        let p = e.checked_sub(1 + k);
        match p {
            Some(p) if p < 32 => t[31 - p] = byte,
            Some(_) if byte != 0 => return None,
            _ => {}
        }
    }
    (t != [0; 32]).then_some(t)
}

/// The work a block of these bits proves, about `2^256 / target`: for a
/// target `m · 256^(e-3)`, `2^(256 - 8(e-3)) / m`, saturating (far beyond
/// any difficulty yet). Zero for bits that are no target.
pub fn work(bits: u32) -> u128 {
    if target(bits).is_none() {
        return 0;
    }
    let (e, m) = ((bits >> 24) as i32, (bits & 0x00ff_ffff) as u128);
    let shift = 256 - 8 * (e - 3);
    if shift >= 128 {
        return u128::MAX;
    }
    if shift < 0 {
        return 0;
    }
    (1u128 << shift) / m
}

/// The root a txid at `index` reaches through `path` (siblings from the
/// leaves up).
pub fn merkle_root(txid: &Hash, mut index: u32, path: &[Hash]) -> Hash {
    let mut h = *txid;
    let mut b = [0u8; 64];
    for s in path {
        if index & 1 == 1 {
            b[..32].copy_from_slice(s);
            b[32..].copy_from_slice(&h);
        } else {
            b[..32].copy_from_slice(&h);
            b[32..].copy_from_slice(s);
        }
        h = sha256d(&b);
        index >>= 1;
    }
    h
}

/// Whether `tx` (a non-witness serialization) is in the block of
/// `header`, at `index` by `path`: its path as long as the coinbase's
/// (index 0), which can't pass for a node of the tree (it isn't 64 bytes,
/// and it is a coinbase), so the tree's real depth. A shorter or longer
/// path could pass a forged transaction off as half of a real 64-byte
/// one, or as a node (CVE-2017-12842); and a 64-byte transaction could
/// pass for a node itself.
pub fn in_block(tx: &[u8], header: &Header, index: u32, path: &[Hash], coinbase: &[u8], coinbase_path: &[Hash]) -> bool {
    let depth = coinbase_path.len();
    tx.len() != 64
        && coinbase.len() != 64
        && is_coinbase(coinbase)
        && merkle_root(&sha256d(coinbase), 0, coinbase_path) == header.merkle_root()
        && path.len() == depth
        && depth < 32
        && index >> depth == 0
        && index != 0
        && merkle_root(&sha256d(tx), index, path) == header.merkle_root()
}

/// Whether `b` (a non-witness serialization) is a coinbase: one input,
/// spending the null outpoint.
pub fn is_coinbase(b: &[u8]) -> bool {
    parse_tx(b).is_some_and(|t| t.inputs.len() == 1 && t.inputs[0] == OutPoint { txid: [0; 32], vout: u32::MAX })
}

/// A transaction's inputs (each spend's outpoint) and outputs (value,
/// script), read from its non-witness serialization.
pub struct Tx<'a> {
    pub inputs: Vec<OutPoint>,
    pub outputs: Vec<(u64, &'a [u8])>,
}

struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn varint(&mut self) -> Option<usize> {
        let n = match self.take(1)?[0] {
            0xfd => u16::from_le_bytes(self.take(2)?.try_into().ok()?) as u64,
            0xfe => u32::from_le_bytes(self.take(4)?.try_into().ok()?) as u64,
            0xff => u64::from_le_bytes(self.take(8)?.try_into().ok()?),
            n => n as u64,
        };
        let n = usize::try_from(n).ok()?;
        (n <= self.0.len()).then_some(n)
    }
}

/// Parse a transaction serialized without witnesses; none if it isn't
/// one (or carries a witness marker).
pub fn parse_tx(b: &[u8]) -> Option<Tx<'_>> {
    let mut r = Rd(b);
    r.take(4)?;
    let tx = body(&mut r)?;
    r.take(4)?;
    r.0.is_empty().then_some(tx)
}

/// A transaction read from its witness serialization: its inputs and
/// outputs, and each input's witness stack.
pub struct WitnessTx<'a> {
    pub tx: Tx<'a>,
    pub witness: Vec<Vec<&'a [u8]>>,
}

/// Parse a transaction serialized with its witnesses (the marker and flag
/// `00 01`); none if it isn't one.
pub fn parse_witness_tx(b: &[u8]) -> Option<WitnessTx<'_>> {
    let mut r = Rd(b);
    r.take(4)?;
    if r.take(2)? != [0, 1] {
        return None;
    }
    let tx = body(&mut r)?;
    let mut witness = Vec::with_capacity(tx.inputs.len());
    for _ in 0..tx.inputs.len() {
        let n = r.varint()?;
        let mut items = Vec::with_capacity(n);
        for _ in 0..n {
            let s = r.varint()?;
            items.push(r.take(s)?);
        }
        witness.push(items);
    }
    r.take(4)?;
    r.0.is_empty().then_some(WitnessTx { tx, witness })
}

/// The witness commitment a coinbase (non-witness) carries: its last
/// output whose script starts `OP_RETURN 0x24 aa21a9ed`, 38 bytes at
/// least (BIP141).
pub fn witness_commitment(coinbase: &[u8]) -> Option<Hash> {
    let tx = parse_tx(coinbase)?;
    let (_, s) = tx.outputs.iter().rev().find(|(_, s)| s.len() >= 38 && s[..6] == [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed])?;
    s[6..38].try_into().ok()
}

/// Whether `tx` (a witness serialization) is in the block of `header`
/// with its witness: at `index` by `path` in the block's witness tree,
/// whose root the coinbase (non-witness, at index 0 by `coinbase_path` in
/// the txid tree) commits with `reserved`, the coinbase's witness value.
/// The trees have the same leaves, so the path is as long as the
/// coinbase's, for the reasons [`in_block`] gives.
pub fn witness_in_block(tx: &[u8], header: &Header, index: u32, path: &[Hash], coinbase: &[u8], coinbase_path: &[Hash], reserved: &Hash) -> bool {
    let depth = coinbase_path.len();
    let Some(commitment) = witness_commitment(coinbase) else {
        return false;
    };
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(&merkle_root(&sha256d(tx), index, path));
    b[32..].copy_from_slice(reserved);
    tx.len() != 64
        && coinbase.len() != 64
        && is_coinbase(coinbase)
        && merkle_root(&sha256d(coinbase), 0, coinbase_path) == header.merkle_root()
        && path.len() == depth
        && depth < 32
        && index >> depth == 0
        && index != 0
        && parse_witness_tx(tx).is_some()
        && sha256d(&b) == commitment
}

/// The inputs and outputs, after the version (and any witness marker).
fn body<'a>(r: &mut Rd<'a>) -> Option<Tx<'a>> {
    let n = r.varint()?;
    if n == 0 {
        return None; // a witness marker, or no inputs
    }
    let mut inputs = Vec::with_capacity(n);
    for _ in 0..n {
        inputs.push(OutPoint::from_bytes(r.take(36)?.try_into().ok()?));
        let s = r.varint()?;
        r.take(s)?;
        r.take(4)?;
    }
    let n = r.varint()?;
    let mut outputs = Vec::with_capacity(n);
    for _ in 0..n {
        let v = u64::from_le_bytes(r.take(8)?.try_into().ok()?);
        let s = r.varint()?;
        outputs.push((v, r.take(s)?));
    }
    Some(Tx { inputs, outputs })
}
