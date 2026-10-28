//! The hub's side of a dispute, run by its watcher, one step per tick.
//!
//! The play is the contract's gadget's ([`bitvmx`]: BitVMX's search). What
//! every gadget shares is here: the tick that drives each contract, and
//! the end of a dispute the user won, when the hub collects its bit
//! outputs of the payout (those of the bits clear in her `b`) and closes.
//! Also the chain's plumbing a gadget's play uses: posting the hub's
//! links, its own spends.
//!
//! Nothing of a dispute is kept but the contract: after a restart the hub
//! reads it again from the chain.

use anyhow::{Context, Result};
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxOut, Txid};
use lichen_chain::NodeWallet;
use lichen_proto::{anchor_vout, sign_anchor, Built, Gadget, Record};
use lngap_btc::sighash::sign_tapscript;
use lngap_btc::taptree::TapTree;
use lngap_btc::tx::build_spend;
use lngap_btc::witness::tapscript_witness;
use lngap_sessions::session::bit_tree;

use crate::{contract_keys, Inner};

pub(crate) mod babe;
pub(crate) mod bitvmx;

/// A dispute's state at the hub.
pub(crate) enum State {
    /// In play, the gadget's.
    BitVmx(bitvmx::State),
    Babe(babe::State),
    /// The user won and the payout is posted, spending the output of
    /// `link` (first seen spent at `since`): the hub collects its bit
    /// outputs, those of the bits clear in `b`, then closes.
    Collect { link: Txid, since: u32 },
    Done,
}

/// The hub's bit outputs of a payout.
enum Bits {
    /// Every bit of the claim is set: none are the hub's.
    None,
    /// Not on chain (the payout unconfirmed, or already swept).
    NotYet,
    /// Swept: the transaction, how many, their value less the fee.
    Swept(Txid, usize, Amount),
}

/// The height `txid` confirmed at, if it has.
pub(crate) fn confirmed_at(inner: &Inner, txid: &Txid) -> Result<Option<u32>> {
    let c = inner.chain.confirmations(txid)?;
    (c > 0).then(|| inner.chain.height().map(|h| h + 1 - c)).transpose()
}

impl Inner {
    /// Advance every dispute by what the chain shows now.
    pub(crate) fn disputes_tick(&self) -> Result<()> {
        self.check_closings()?;
        // contracts closed before the hub collected its bit outputs, once
        let leave = self.leave_bits.load(std::sync::atomic::Ordering::Relaxed);
        let uncollected: Vec<_> = self.open.lock().unwrap().values().filter(|o| o.closed.is_some() && !o.collected && !leave).map(|o| o.record.clone()).collect();
        for record in uncollected {
            // (never at the expense of the disputes in play: tried again next tick)
            if let Err(e) = self.collect_closed(&record) {
                let once = format!("contract {}: collecting what its dispute left failed: {e:#}", record.cid());
                if !self.log.lock().unwrap().contains(&once) {
                    self.note(once);
                }
            }
        }
        let open: Vec<_> = self.open.lock().unwrap().values().filter(|o| o.closed.is_none()).map(|o| o.record.clone()).collect();
        for record in open {
            let cid = record.cid();
            let state = self.disputes.lock().unwrap().remove(&cid);
            let next = match state {
                None => match record.gadget() {
                    Gadget::BitVmx => self.bitvmx_start(&record),
                    Gadget::Babe => self.babe_start(&record),
                },
                Some(State::BitVmx(s)) => self.bitvmx_tick(&record, s),
                Some(State::Babe(s)) => self.babe_tick(&record, s),
                Some(State::Collect { link, since }) => self.collect(&record, link, since),
                Some(State::Done) => Ok(Some(State::Done)),
            };
            // one contract's error never stops the others: its dispute is
            // read again from the chain at the next tick
            match next {
                Ok(Some(s)) => {
                    self.disputes.lock().unwrap().insert(cid, s);
                }
                Ok(None) => {}
                Err(e) => self.note_once(format!("contract {cid}: {e:#}")),
            }
        }
        Ok(())
    }

    /// The contract, built by its gadget.
    pub(crate) fn built(&self, record: &Record) -> Result<Built> {
        record.build(&self.cfg.statement, self.program.as_ref())
    }

    /// The payout of a dispute the user won (spending `link`'s output):
    /// sweep the hub's bit outputs once it confirms. They appear only
    /// then, so until they do the hub waits, for a while, before closing
    /// with nothing collected.
    fn collect(&self, record: &Record, link: Txid, since: u32) -> Result<Option<State>> {
        let cid = record.cid();
        if self.leave_bits.load(std::sync::atomic::Ordering::Relaxed) {
            self.close(cid, link)?;
            self.set_collected(cid, false)?;
            return Ok(Some(State::Done));
        }
        match self.sweep_bits(record)? {
            Bits::None => self.note(format!("contract {cid}: no bit outputs of the hub's (every bit of the claim is set)")),
            Bits::Swept(txid, n, value) => self.note(format!("contract {cid}: collected the hub's {n} bit outputs, {} sats: {txid}", value.to_sat())),
            Bits::NotYet if self.chain.height()? < since + 4 * self.cfg.network.patience_blocks() => return Ok(Some(State::Collect { link, since })),
            Bits::NotYet => self.note(format!("contract {cid}: no bit outputs of the hub's appeared; closed without collecting")),
        }
        self.close(cid, link)?;
        Ok(Some(State::Done))
    }

    /// A contract closed before the hub collected its bit outputs: if a
    /// dispute the user won is what closed it, sweep them now. Looked at
    /// once.
    fn collect_closed(&self, record: &Record) -> Result<()> {
        let cid = record.cid();
        let disputed = match record.gadget() {
            Gadget::BitVmx => self.bitvmx_escalated(record)?,
            Gadget::Babe => self.babe_requested(record)?,
        };
        if disputed {
            if let Bits::Swept(txid, n, value) = self.sweep_bits(record)? {
                self.note(format!("contract {cid}: collected the hub's {n} bit outputs left from its dispute, {} sats: {txid}", value.to_sat()));
            }
        }
        self.set_collected(cid, true)
    }

    /// Alice's signed `b`, as her claim put it on chain: its value and her
    /// signature as a witness wire (the gadget's).
    fn claimed_b(&self, record: &Record) -> Result<(u32, Vec<Vec<u8>>)> {
        match record.gadget() {
            Gadget::BitVmx => self.bitvmx_claimed_b(record),
            Gadget::Babe => self.babe_claimed_b(record),
        }
    }

    /// Sweep to the hub's wallet its bit outputs of a payout: for each bit
    /// clear in Alice's signed `b`, the output of `u 2^i`, by its leaf
    /// `hub_bit_i` (her signature on `b`, as her claim posted it, and the
    /// hub's).
    fn sweep_bits(&self, record: &Record) -> Result<Bits> {
        let cid = record.cid();
        let (b, b_wire) = self.claimed_b(record)?;
        let built = self.built(record)?;
        let (core, b_key) = (built.core(), built.b_key());
        let (t, ctx) = (core.terms, core.ctx());
        let mut trees = vec![];
        for i in (t.low_bits..t.bits).filter(|i| (b >> i) & 1 == 0) {
            let tree = bit_tree(&ctx, i, b_key)?;
            trees.push((tree.script_pubkey(), tree, format!("hub_bit_{i}")));
        }
        if trees.is_empty() {
            return Ok(Bits::None);
        }
        let spks: Vec<_> = trees.iter().map(|t| t.0.clone()).collect();
        let coins = self.chain.scan_utxos(&spks)?;
        if coins.is_empty() {
            return Ok(Bits::NotYet);
        }
        let ins: Vec<_> = coins.iter().map(|(op, out, _)| (*op, out.clone(), trees.iter().find(|t| t.0 == out.script_pubkey).expect("a scanned script"))).collect();
        let kp = contract_keys(&self.cfg.seed, cid).payment;
        let to = self.chain.new_spk()?;
        let total: Amount = ins.iter().map(|i| i.1.value).sum();
        let prevouts: Vec<TxOut> = ins.iter().map(|i| i.1.clone()).collect();
        let seqs: Vec<(OutPoint, Sequence)> = ins.iter().map(|i| (i.0, Sequence::ENABLE_RBF_NO_LOCKTIME)).collect();
        let build = |fee: Amount| -> Result<Transaction> {
            let out = TxOut { value: total.checked_sub(fee).context("the bit outputs can't pay the sweep's fee")?, script_pubkey: to.clone() };
            let mut sweep = lngap_btc::tx::build_tx(&seqs, vec![out], bitcoin::absolute::LockTime::ZERO);
            for (n, (_, _, (_, tree, name))) in ins.iter().enumerate() {
                let leaf = tree.leaf(name)?;
                let mut w = b_wire.clone();
                w.push(sign_tapscript(&kp, &sweep, n, &prevouts, &leaf.script)?.as_ref().to_vec());
                sweep.input[n].witness = tapscript_witness(&w, &leaf.script, &tree.control_block(name)?);
            }
            Ok(sweep)
        };
        // sized once at no fee, then paid
        let vsize = build(Amount::ZERO)?.vsize() as u64;
        let fee = Amount::from_sat((vsize + 2) * lichen_proto::feerate(self.cfg.network));
        let txid = self.chain.broadcast(&build(fee)?).context("sweeping the hub's bit outputs")?;
        Ok(Bits::Swept(txid, ins.len(), total - fee))
    }

    /// The hub's own spend of `(op, out)` under `tree`'s leaf `leaf_name`,
    /// `wire` below its signature, to its wallet at the network's feerate.
    pub(crate) fn spend_leaf(&self, cid: u32, tree: &TapTree, leaf_name: &str, op: OutPoint, out: &TxOut, wire: Vec<Vec<u8>>) -> Result<Transaction> {
        let leaf = tree.leaf(leaf_name)?;
        let kp = contract_keys(&self.cfg.seed, cid).payment;
        let to = self.chain.new_spk()?;
        let build = |fee: Amount| -> Result<Transaction> {
            let mut spend = build_spend(op, &leaf.timelock, vec![TxOut { value: out.value.checked_sub(fee).context("the output can't pay the fee")?, script_pubkey: to.clone() }]);
            let mut w = wire.clone();
            w.push(sign_tapscript(&kp, &spend, 0, std::slice::from_ref(out), &leaf.script)?.as_ref().to_vec());
            spend.input[0].witness = tapscript_witness(&w, &leaf.script, &tree.control_block(leaf_name)?);
            Ok(spend)
        };
        // sized once at no fee, then paid
        let vsize = build(Amount::ZERO)?.vsize() as u64;
        build(Amount::from_sat((vsize + 10) * lichen_proto::feerate(self.cfg.network)))
    }

    /// Post one of the hub's links (unless it is already there: replayed,
    /// checked to be the same), its child paying from the hub's anchor;
    /// its confirmation height.
    pub(crate) fn post(&self, cid: u32, tx: &Transaction) -> Result<u32> {
        let txid = tx.compute_txid();
        match self.chain.get_tx(&txid) {
            None => {
                let kp = contract_keys(&self.cfg.seed, cid).payment;
                let anchor = anchor_vout(tx, &kp.x_only_public_key().0)?;
                self.chain.post_link(tx, anchor, lichen_proto::feerate(self.cfg.network), &|c, p| sign_anchor(&kp, c, p), &NodeWallet)?;
            }
            Some(posted) => anyhow::ensure!(posted.input.iter().zip(&tx.input).all(|(a, b)| a.witness == b.witness), "{txid} on chain is not the link replayed"),
        }
        let patience = lichen_proto::Patience::new(self.chain.height()?, self.cfg.network);
        loop {
            if let Some(h) = confirmed_at(self, &txid)? {
                return Ok(h);
            }
            anyhow::ensure!(!patience.expired(self.chain.height()?), "{txid} never confirmed");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

impl State {
    pub(crate) fn describe(&self) -> String {
        match self {
            State::BitVmx(s) => s.describe(),
            State::Babe(s) => s.describe(),
            State::Collect { .. } => "the user won: collecting the hub's bit outputs".into(),
            State::Done => "settled".into(),
        }
    }
}
