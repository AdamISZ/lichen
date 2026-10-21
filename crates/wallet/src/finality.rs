//! How final the wallet's notes are (docs/ANCHOR_PLAN.md): sealed only
//! (final if you trust the sequencer), anchored on Bitcoin (and how deep),
//! or final: [`lichen_proto::ANCHOR_DEPTH`] blocks deep, so that a history
//! without them would take a branch of Bitcoin that long.
//!
//! The anchors aren't taken from the sequencer: each is checked on
//! Bitcoin. It spends the last seal, from the deployment's genesis seal on;
//! keeps the seal's script; commits the history hash that the wallet
//! computes from the roots it has checked and recorded; and is confirmed in
//! the block it names.

use anyhow::{ensure, Context, Result};
use bitcoin::hashes::Hash as _;
use lichen_chain::Chain;
use lichen_l2::State;
use lichen_ledger::lichen_validity::{commitment_script, seal_script};
use lichen_ledger::Hash;

use crate::Wallet;

/// An anchor checked on Bitcoin: the L2 height it commits, and its
/// confirmations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checked {
    pub height: u64,
    pub confirmations: u32,
}

/// The wallet's holdings by how final they are, in sats.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Finality {
    /// Sealed (or pending) but not anchored yet.
    pub sealed: u64,
    /// Anchored, fewer than the depth's blocks on it.
    pub anchored: u64,
    /// Anchored at least the depth deep.
    pub fin: u64,
    /// The last anchor checked: its height and confirmations.
    pub last: Option<Checked>,
}

/// The history hash at each sealed height of `state`, from `hist_0 = 0`.
fn hists(state: &State) -> Vec<Hash> {
    let mut h = [0u8; 32];
    std::iter::once(h)
        .chain(state.sealed.iter().map(|s| {
            h = lichen_ledger::lichen_validity::hist_next(&h, &s.root());
            h
        }))
        .collect()
}

impl Wallet {
    /// The sequencer's anchors, each checked on `chain`, in order. An error
    /// names the first that doesn't check.
    pub fn checked_anchors(&self, state: &State, chain: &Chain) -> Result<Vec<Checked>> {
        let d = self.sequencer.deployment;
        let genesis = d.seal.context("this deployment doesn't anchor its history")?;
        let hist = hists(state);
        let seal_spk = bitcoin::ScriptBuf::from_bytes(seal_script(&d.sequencer).to_vec());
        // the anchors checked before, while the state still names them
        let mut cache = self.anchors_checked.lock().unwrap();
        let keep = cache.iter().zip(&state.anchors).take_while(|(c, a)| c.anchor == a.anchor && hist.get(c.anchor.height as usize) == Some(&c.hist)).count();
        cache.truncate(keep);
        let mut prev = match cache.last() {
            Some(c) => bitcoin::OutPoint { txid: bitcoin::Txid::from_byte_array(c.anchor.seal.txid), vout: 0 },
            None => bitcoin::OutPoint { txid: bitcoin::Txid::from_byte_array(genesis.txid), vout: genesis.vout },
        };
        for a in &state.anchors[keep..] {
            let s = &a.anchor;
            let txid = bitcoin::Txid::from_byte_array(s.seal.txid);
            let at = s.height;
            let what = || format!("the anchor of height {at} ({txid})");
            let tx = chain.get_tx(&txid).with_context(|| format!("{}: not found on Bitcoin", what()))?;
            ensure!(tx.input.first().map(|i| i.previous_output) == Some(prev), "{}: doesn't spend the last seal", what());
            ensure!(tx.output.first().map(|o| &o.script_pubkey) == Some(&seal_spk) && s.seal.vout == 0, "{}: the seal isn't the sequencer's", what());
            let h = hist.get(at as usize).with_context(|| format!("{}: of a height not sealed here", what()))?;
            ensure!(tx.output.get(1).map(|o| o.script_pubkey.as_bytes()) == Some(&commitment_script(at, h)[..]), "{}: commits another history than the roots this wallet checked", what());
            ensure!(state.sealed.get(at as usize - 1).map(|r| r.root()) == Some(s.root), "{}: of another root than the one signed there", what());
            let block = chain.block_of(&txid)?.with_context(|| format!("{}: not confirmed", what()))?;
            ensure!(block.to_byte_array() == s.block, "{}: confirmed in another block than recorded", what());
            let height = chain.block_height(&block)?.with_context(|| format!("{}: its block isn't on the best chain", what()))?;
            cache.push(crate::AnchorChecked { anchor: *s, hist: *h, block_height: height });
            prev = bitcoin::OutPoint { txid, vout: 0 };
        }
        let tip = chain.height()?;
        Ok(cache.iter().map(|c| Checked { height: c.anchor.height, confirmations: (tip + 1).saturating_sub(c.block_height) }).collect())
    }

    /// The wallet's holdings by how final they are, the anchors checked on
    /// `chain`: each note under the first anchor at or after the height
    /// that sealed it.
    pub fn finality(&self, chain: &Chain) -> Result<Finality> {
        let state = self.state()?;
        let anchors = self.checked_anchors(&state, chain)?;
        let depth = lichen_proto::ANCHOR_DEPTH as u32;
        let mut f = Finality { last: anchors.last().copied(), ..Default::default() };
        let notes = self.notes(&state).into_iter().map(|o| (o.index, o.note.value)).chain(self.shielded_notes(&state).into_iter().map(|o| (o.index, o.value)));
        for (index, value) in notes {
            let sealed = state.sealed.iter().find(|s| s.size > index).map(|s| s.height);
            match sealed.and_then(|h| anchors.iter().find(|a| a.height >= h)) {
                Some(a) if a.confirmations >= depth => f.fin += value,
                Some(_) => f.anchored += value,
                None => f.sealed += value,
            }
        }
        Ok(f)
    }
}
