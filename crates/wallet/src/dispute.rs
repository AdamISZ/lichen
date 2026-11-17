//! The wallet's side of a dispute, its exit: [`crate::engine`] over the
//! wallet's own keys and contract record, then, on a win, the sweep of her
//! bit outputs and the reserves (less the links' floors) to her payout
//! address.

use std::time::Duration;

use anyhow::{ensure, Context, Result};
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxOut, Txid};
use lichen_chain::{Chain, Fees};
use lichen_proto::{anchor_vout, Built, Statement};

use lichen_contract::{anchor_tree_for, Presign};
use lichen_btc::sighash::sign_tapscript;
use lichen_btc::witness::tapscript_witness;

pub use crate::engine::Outcome;
use crate::engine::{wait_confirmed, Engine, Options, Store, WalletSigner};
use crate::{Wallet, WalletL2};

/// Her winnings swept to her payout address, with her anchors and the fee
/// budget's rest: the sweep's txid and what it pays.
pub type Swept = Option<(Txid, Amount)>;

struct HeldStore<'a, L: WalletL2> {
    w: &'a mut Wallet<L>,
    k: usize,
}

impl<L: WalletL2> Store for HeldStore<'_, L> {
    fn payout(&self) -> Option<Outcome> {
        self.w.contracts[self.k].payout.clone()
    }
    fn set_payout(&mut self, outcome: &Outcome) -> Result<()> {
        self.w.contracts[self.k].payout = Some(outcome.clone());
        self.w.save()
    }
    fn set_lost(&mut self, txid: Txid) -> Result<()> {
        self.w.contracts[self.k].closed = Some(txid);
        self.w.save()
    }
    fn exit(&self) -> Option<serde_json::Value> {
        self.w.contracts[self.k].exit.clone()
    }
    fn unlocked(&mut self, z: &[u8]) -> Result<Option<u64>> {
        L::unlocked(self.w, self.k, z)
    }
}

impl<L: WalletL2> Wallet<L> {
    /// Contract `k` is still open: no closing transaction, or one named
    /// (the hub's answer to a fold) that never reached the chain, which
    /// is then forgotten.
    pub(crate) fn ensure_open(&mut self, chain: &Chain, k: usize) -> Result<()> {
        if let Some(t) = self.contracts[k].closed {
            ensure!(chain.get_tx(&t).is_none(), "contract {} is closed ({t})", self.contracts[k].record.cid());
            self.contracts[k].closed = None;
            self.save()?;
        }
        Ok(())
    }

    pub(crate) fn step(&self, msg: String) {
        if let Some(f) = &self.progress {
            f(msg);
        }
    }

    /// Exit contract `cid`: post the claim kept (made and kept now, if
    /// none) and play the dispute to its end; on a win, sweep the payout.
    pub fn exit(&mut self, chain: &Chain, statement: &Statement, cid: u32) -> Result<(Outcome, Swept)> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let plan = match self.contracts[k].exit.clone() {
            Some(p) => p,
            None => {
                let p = L::exit_plan(self, chain, cid)?;
                self.contracts[k].exit = Some(p.clone());
                self.save()?;
                p
            }
        };
        let b = L::plan_b(&plan)?;
        let out = self.play(chain, statement, cid, b)?;
        L::exited(self, cid)?;
        Ok(out)
    }

    /// Play contract `cid`'s exit, a claim of `b` (the plan kept with the
    /// contract, [`Wallet::exit`]). Blocks until the dispute ends; on a
    /// win, sweeps her winnings to her payout address.
    ///
    /// Resumable: what is already on chain is replayed, not posted again.
    pub(crate) fn play(&mut self, chain: &Chain, statement: &Statement, cid: u32, b: u32) -> Result<(Outcome, Swept)> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        self.ensure_open(chain, k)?;
        let held = self.contracts[k].clone();
        let signer = WalletSigner { secrets: self.secrets(&held.nonce), network: held.record.network };
        let opts = Options { progress: self.progress.clone(), pause_after: self.pause_after, unchecked_claims: self.unchecked_claims, contest: self.contest };
        let layer = self.l2.clone();
        let outcome = Engine { signer: &signer, store: &mut HeldStore { w: self, k }, opts }.run(chain, &held.record, statement, &layer, b)?;
        if outcome.payout().is_none() {
            return Ok((outcome, None));
        }
        self.won(chain, statement, k, b, outcome)
    }

    /// Contract `k`'s graph and its pre-signed set (both signatures
    /// checked).
    fn presigned(&self, k: usize, statement: &Statement) -> Result<(Built, Vec<Presign>)> {
        let record = &self.contracts[k].record;
        let c = record.build(statement, &self.l2)?;
        let set = record.presigned(&c)?;
        Ok((c, set))
    }

    /// She won: once the payout confirms and her outputs' delay passes,
    /// sweep to her payout address her bit outputs and the reserves, and
    /// what else of the contract's is hers: the anchors of her links (left
    /// unspent where no fee child was needed) and the fee budget's rest.
    fn won(&mut self, chain: &Chain, statement: &Statement, k: usize, b: u32, outcome: Outcome) -> Result<(Outcome, Swept)> {
        let txid = outcome.payout().context("not a win")?;
        let at = wait_confirmed(chain, &txid)?;
        let payout = chain.get_tx(&txid).context("the payout")?;
        let held = self.contracts[k].clone();
        let (c, set) = self.presigned(k, statement)?;
        let _ = &c;
        let kp = self.contract_keys(&held.nonce).payment;
        let (mut ins, b_wire, wait) = L::payout_inputs(self, chain, &held, statement, &outcome, &payout, b)?;
        let winnings: Amount = ins.iter().map(|i| i.1.value).sum();
        // her links' anchors (a link of the set with an anchor of hers is
        // hers), where they are unspent
        let mine = kp.x_only_public_key().0;
        let anchor = anchor_tree_for(&mine)?;
        let mut links: Vec<&Presign> = set.iter().filter(|p| p.link).collect();
        links.sort_by(|a, b| a.name.cmp(&b.name));
        for p in links {
            let id = p.tx.compute_txid();
            let Some(tx) = chain.get_tx(&id) else { continue };
            let Ok(vout) = anchor_vout(&tx, &mine) else { continue };
            let op = OutPoint { txid: id, vout };
            if chain.unspent(&op)? {
                ins.push((op, tx.output[op.vout as usize].clone(), Sequence::ENABLE_RBF_NO_LOCKTIME, Some((anchor.clone(), "fee".to_string(), false))));
            }
        }
        let anchors: Amount = ins.iter().map(|i| i.1.value).sum::<Amount>() - winnings;
        // the fee budget's rest
        let fees = self.fees_for(held.record.cid())?;
        for (op, out, _) in chain.coins_of(&fees.spk())? {
            ins.push((op, out, Sequence::ENABLE_RBF_NO_LOCKTIME, None));
        }
        let total: Amount = ins.iter().map(|i| i.1.value).sum();
        let budget = total - winnings - anchors;
        self.step(format!("the payout confirmed at {at}: the user's outputs can be swept from block {}", at + u32::from(wait)));
        while chain.height()? < at + u32::from(wait) {
            std::thread::sleep(Duration::from_millis(100));
        }
        let prevouts: Vec<TxOut> = ins.iter().map(|i| i.1.clone()).collect();
        let pairs: Vec<(OutPoint, TxOut)> = ins.iter().map(|i| (i.0, i.1.clone())).collect();
        let seqs: Vec<(OutPoint, Sequence)> = ins.iter().map(|i| (i.0, i.2)).collect();
        let build = |fee: Amount| -> Result<Transaction> {
            let out = TxOut { value: total.checked_sub(fee).context("the sweep can't pay its fee")?, script_pubkey: held.record.pubs[0].payout_spk.clone() };
            let mut sweep = lichen_btc::tx::build_tx(&seqs, vec![out], bitcoin::absolute::LockTime::ZERO);
            for (n, i) in ins.iter().enumerate() {
                if let Some((tree, name, with_b)) = &i.3 {
                    let leaf = tree.leaf(name)?;
                    let mut w = if *with_b { b_wire.clone() } else { vec![] };
                    w.push(sign_tapscript(&kp, &sweep, n, &prevouts, &leaf.script)?.as_ref().to_vec());
                    sweep.input[n].witness = tapscript_witness(&w, &leaf.script, &tree.control_block(name)?);
                }
            }
            // the budget's coins, by its key
            fees.sign(chain, &sweep, &pairs)
        };
        // sized once at no fee, then paid
        let vsize = build(Amount::ZERO)?.vsize() as u64;
        let fee = Amount::from_sat((vsize + 2) * lichen_proto::feerate(chain.network));
        let swept = chain.broadcast(&build(fee)?).context("sweeping the winnings")?;
        // the parts that came to nothing (on regtest the anchors often went
        // to fee bumps) are left out
        let parts: Vec<String> = [("the payout's bits and reserves", winnings), ("the anchors", anchors), ("the fee budget's rest", budget)]
            .into_iter()
            .filter(|(_, v)| *v > Amount::ZERO)
            .map(|(name, v)| format!("{name} {}", v.to_sat()))
            .collect();
        self.step(format!("swept {} sats to the payout address, {swept}: {}, less the fee {}", (total - fee).to_sat(), parts.join(", "), fee.to_sat()));
        self.contracts[k].closed = Some(txid);
        self.save()?;
        Ok((outcome, Some((swept, total - fee))))
    }
}
