//! The statements' inputs' encoding: big-endian integers, lists and
//! byte strings with a 4-byte count.

use alloc::vec::Vec;

use crate::Reject;

/// A writer.
#[derive(Default)]
pub struct W(pub Vec<u8>);

impl W {
    pub fn put(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    pub fn list<const N: usize>(&mut self, items: &[[u8; N]]) {
        self.put(&(items.len() as u32).to_be_bytes());
        for i in items {
            self.put(i);
        }
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.put(&(b.len() as u32).to_be_bytes());
        self.put(b);
    }
}

/// A reader of what [`W`] wrote.
pub struct R<'a>(pub &'a [u8]);

impl R<'_> {
    pub fn take<const N: usize>(&mut self) -> Result<[u8; N], Reject> {
        if self.0.len() < N {
            return Err(Reject::Encoding);
        }
        let (a, rest) = self.0.split_at(N);
        self.0 = rest;
        Ok(a.try_into().unwrap())
    }
    pub fn list<const N: usize>(&mut self) -> Result<Vec<[u8; N]>, Reject> {
        let n = u32::from_be_bytes(self.take()?) as usize;
        if n > self.0.len() / N {
            return Err(Reject::Encoding);
        }
        (0..n).map(|_| self.take()).collect()
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>, Reject> {
        let n = u32::from_be_bytes(self.take()?) as usize;
        if n > self.0.len() {
            return Err(Reject::Encoding);
        }
        let (a, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(a.to_vec())
    }
    /// Nothing left, as the end of an input must be.
    pub fn end(&self) -> Result<(), Reject> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Reject::Encoding)
        }
    }
}
