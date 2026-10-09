//! The user's wallet: a key, the notes it owns on the L2, transfers, and
//! returns to the hub (the first step of a withdrawal).
//!
//! The ledger is transparent, so the wallet finds its notes by reading the
//! sequencer's state; it checks every sealed root's signature, and builds a
//! withdrawal's input itself, checked against the statement.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use lichen_ledger::k256::schnorr::SigningKey;
use lichen_ledger::{fresh_rho, note, sign, xonly, Hash, Note, Spend, Transfer, Tx, WithdrawInput, HUB_KEY};
use lichen_sequencer::{Client, State};
use serde::{Deserialize, Serialize};

/// What the wallet keeps on disk.
#[derive(Serialize, Deserialize)]
struct Stored {
    /// The secret key, hex.
    secret: String,
    /// This wallet's returns to the hub: (memo, note index).
    returns: Vec<(u32, u32)>,
}

pub struct Wallet {
    key: SigningKey,
    path: PathBuf,
    returns: Vec<(u32, u32)>,
    pub sequencer: Client,
}

/// An unspent note of ours.
#[derive(Clone, Copy, Debug)]
pub struct Owned {
    pub note: Note,
    pub index: u32,
}

impl Wallet {
    /// Create a wallet at `path` with a fresh key.
    pub fn create(path: &Path, sequencer: &str) -> Result<Wallet> {
        if path.exists() {
            bail!("{} already exists", path.display());
        }
        let key = SigningKey::from_bytes(&fresh_rho()).context("a key")?;
        let w = Wallet { key, path: path.to_path_buf(), returns: vec![], sequencer: Client::new(sequencer) };
        w.save()?;
        Ok(w)
    }
    pub fn open(path: &Path, sequencer: &str) -> Result<Wallet> {
        let s: Stored = serde_json::from_slice(&std::fs::read(path).with_context(|| format!("no wallet at {}", path.display()))?)?;
        let key = SigningKey::from_bytes(&hex::decode(&s.secret)?).context("the wallet's key")?;
        Ok(Wallet { key, path: path.to_path_buf(), returns: s.returns, sequencer: Client::new(sequencer) })
    }
    fn save(&self) -> Result<()> {
        let s = Stored { secret: hex::encode(self.key.to_bytes()), returns: self.returns.clone() };
        if let Some(d) = self.path.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(&self.path, serde_json::to_vec_pretty(&s)?)?;
        Ok(())
    }
    /// The wallet's L2 address: its x-only public key.
    pub fn address(&self) -> Hash {
        xonly(&self.key)
    }
    /// Our unspent notes.
    pub fn notes(&self, state: &State) -> Vec<Owned> {
        let me = self.address();
        state.notes.iter().enumerate().filter(|(_, n)| n.owner == me && !state.is_spent(n)).map(|(i, n)| Owned { note: *n, index: i as u32 }).collect()
    }
    pub fn balance(&self) -> Result<u64> {
        Ok(self.notes(&self.sequencer.state()?).iter().map(|o| o.note.value).sum())
    }
    /// Pay `amount` to `to` with `memo`; the new notes' indices (the
    /// payment's first, then our change if any).
    pub fn send(&mut self, to: Hash, amount: u64, memo: u32) -> Result<Vec<u32>> {
        anyhow::ensure!(amount > 0, "nothing to send");
        let state = self.sequencer.state()?;
        let mut mine = self.notes(&state);
        mine.sort_by_key(|o| std::cmp::Reverse(o.note.value));
        let (mut spends, mut total) = (vec![], 0u64);
        for o in mine {
            if total >= amount {
                break;
            }
            total += o.note.value;
            spends.push(Spend { note: o.note, index: o.index });
        }
        if total < amount {
            bail!("the balance is {total}, short of {amount}");
        }
        let mut outputs = vec![note(to, amount, memo)];
        if total > amount {
            outputs.push(note(self.address(), total - amount, 0));
        }
        let digest = Transfer::digest(&spends, &outputs);
        let sigs = spends.iter().map(|_| sign(&self.key, &digest)).collect();
        self.sequencer.submit(&Tx::Transfer(Transfer { spends, outputs, sigs }))
    }
    /// Return `b` to the hub with the contract's memo `c`: a withdrawal's
    /// first step. The return's note index.
    pub fn return_to_hub(&mut self, b: u64, c: u32) -> Result<u32> {
        let idx = self.send(HUB_KEY, b, c)?[0];
        self.returns.push((c, idx));
        self.save()?;
        Ok(idx)
    }
    /// The withdrawal statement's input for our return with memo `c`, once
    /// it is sealed.
    pub fn withdraw_input(&self, c: u32) -> Result<WithdrawInput> {
        let &(_, idx) = self.returns.iter().find(|r| r.0 == c).with_context(|| format!("no return with memo {c}"))?;
        self.sequencer.state()?.withdraw_input(idx)
    }
}
