//! Acknowledging our spends (docs/HUB_PROVES_PLAN.md, "Data
//! availability: sender acknowledgment"): a spend of ours counts against
//! us, and its outputs unlock, only once we acknowledge it, which we do
//! only once an anchor checked on Bitcoin holds it and we hold its data
//! (the sequencer's state, checked against its signed roots). The
//! acknowledgment is kept with the spend's record before it goes, so a
//! claim of its locked outputs can carry it.

use anyhow::{Context, Result};
use lichen_chain::Chain;
use lichen_ledger::lichen_validity::ack;
use lichen_ledger::{xonly, Ack, Tx};

use crate::Wallet;

/// How long a wallet waits for its spends to be acknowledged before it
/// gives up (s): an acknowledgment waits for an anchor at or above the
/// spend, recorded once it is the margin deep (20 blocks on Mutinynet,
/// some minutes; 6 on mainnet, an hour or more).
pub const ACK_PATIENCE: u64 = 6 * 3600;

impl Wallet {
    /// Acknowledge each spend of ours the sequencer has sealed and an
    /// anchor checked on `chain` holds; how many are still waiting (not
    /// sealed, not anchored yet, or refused for now).
    pub fn acknowledge(&mut self, chain: &Chain) -> Result<usize> {
        let state = self.state()?;
        if self.sequencer.deployment.seal.is_none() {
            // an unanchored deployment locks nothing
            for s in &mut self.signed {
                s.done = true;
            }
            self.save()?;
            return Ok(0);
        }
        let anchors = self.checked_anchors(&state, chain)?;
        let hists = crate::finality::hists(&state);
        let mut waiting = 0;
        for k in 0..self.signed.len() {
            let s = &self.signed[k];
            if s.done {
                continue;
            }
            let Some(nf0) = s.nullifiers.first().copied() else { continue };
            let txid = state.leaf(&nf0);
            if txid == [0; 32] {
                // never sequenced: the sequencer applies a transaction as
                // it takes it, so one not in the state was refused
                self.signed[k].done = true;
                continue;
            }
            let pending = state.leaf(&ack::tx_key(&txid));
            if pending == [0; 32] || state.spent(&ack::acked_key(&txid)) || state.spent(&ack::void_key(&txid)) {
                // not a pending spend (an exit's), acknowledged, or void
                self.signed[k].done = true;
                continue;
            }
            let key = self.ak_key(&nf0);
            let ak = xonly(&key);
            let Some(h) = state.sealed.iter().map(|r| r.height).find(|h| ack::pending(&ak, *h) == pending) else {
                waiting += 1;
                continue;
            };
            let a = match &s.ack {
                Some(a) if anchors.iter().any(|c| c.height == a.a) => a.clone(),
                _ => match anchors.iter().find(|c| c.height >= h) {
                    Some(c) => Ack::new(&key, txid, h, c.height, *hists.get(c.height as usize).context("an anchor's height not sealed")?),
                    None => {
                        waiting += 1;
                        continue;
                    }
                },
            };
            // kept before it goes: a claim of the outputs carries it
            self.signed[k].ack = Some(a.clone());
            self.save()?;
            if self.acks_unsent {
                self.signed[k].done = true;
                continue;
            }
            match self.sequencer.submit(&Tx::Ack(a)) {
                Ok(_) => self.signed[k].done = true,
                Err(e) => {
                    self.say(format!("acknowledging a spend: {e:#}"));
                    waiting += 1;
                }
            }
        }
        self.save()?;
        Ok(waiting)
    }

    /// [`Wallet::acknowledge`] until nothing waits, sealing as we go (a
    /// test's sequencer, or one that seals on demand), for at most `secs`.
    pub fn acknowledge_all(&mut self, chain: &Chain, secs: u64) -> Result<()> {
        let start = std::time::Instant::now();
        loop {
            if self.acknowledge(chain)? == 0 {
                return Ok(());
            }
            anyhow::ensure!(start.elapsed() < std::time::Duration::from_secs(secs), "spends still unacknowledged after {secs} s: not sealed or not anchored");
            let _ = self.sequencer.seal();
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
    }
}
