//! The statements' inputs' encoding: big-endian integers, lists and
//! byte strings with a 4-byte count.

use alloc::vec::Vec;

use crate::{Anchored, Reject};

pub(crate) struct W(pub(crate) Vec<u8>);

impl W {
    pub(crate) fn put(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    pub(crate) fn list<const N: usize>(&mut self, items: &[[u8; N]]) {
        self.put(&(items.len() as u32).to_be_bytes());
        for i in items {
            self.put(i);
        }
    }
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.put(&(b.len() as u32).to_be_bytes());
        self.put(b);
    }
}

pub(crate) struct R<'a>(pub(crate) &'a [u8]);

impl R<'_> {
    pub(crate) fn take<const N: usize>(&mut self) -> Result<[u8; N], Reject> {
        if self.0.len() < N {
            return Err(Reject::Encoding);
        }
        let (a, rest) = self.0.split_at(N);
        self.0 = rest;
        Ok(a.try_into().unwrap())
    }
    pub(crate) fn list<const N: usize>(&mut self) -> Result<Vec<[u8; N]>, Reject> {
        let n = u32::from_be_bytes(self.take()?) as usize;
        if n > self.0.len() / N {
            return Err(Reject::Encoding);
        }
        (0..n).map(|_| self.take()).collect()
    }
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>, Reject> {
        let n = u32::from_be_bytes(self.take()?) as usize;
        if n > self.0.len() {
            return Err(Reject::Encoding);
        }
        let (a, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(a.to_vec())
    }
}

impl Anchored {
    pub(crate) fn write(&self, w: &mut W) {
        w.put(&self.height.to_be_bytes());
        w.put(&self.nullifiers);
        w.put(&self.signature);
        w.put(&self.sequencer);
        w.put(&self.hub);
        w.put(&self.chain_height.to_be_bytes());
        w.put(&self.chain_root);
        w.put(&self.recent);
        w.put(&self.hist);
        w.put(&self.anchor.to_bytes());
        w.list(&self.headers);
        w.put(&self.work.to_be_bytes());
        w.put(&self.unit.to_be_bytes());
    }
    pub(crate) fn read(r: &mut R) -> Result<Anchored, Reject> {
        Ok(Anchored {
            height: u64::from_be_bytes(r.take()?),
            nullifiers: r.take()?,
            signature: r.take()?,
            sequencer: r.take()?,
            hub: r.take()?,
            chain_height: u64::from_be_bytes(r.take()?),
            chain_root: r.take()?,
            recent: r.take()?,
            hist: r.take()?,
            anchor: lichen_validity::AnchorState::from_bytes(&r.take::<176>()?).map_err(|_| Reject::Encoding)?,
            headers: r.list()?,
            work: u128::from_be_bytes(r.take()?),
            unit: u64::from_be_bytes(r.take()?),
        })
    }
}
