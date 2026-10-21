//! What the statements read of Bitcoin (docs/ANCHOR_PLAN.md): a
//! transaction's non-witness serialization (its txid's), a block header,
//! a Merkle path from a txid to the header's root, and proof of work.
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
    r.take(4)?;
    r.0.is_empty().then_some(Tx { inputs, outputs })
}
