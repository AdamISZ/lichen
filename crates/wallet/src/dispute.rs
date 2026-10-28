//! The wallet's side of a dispute: [`crate::engine`] over the wallet's own
//! keys and contract record, then, on a win, the sweep of her bit outputs
//! and the reserves (less the links' floors) to her payout address, which
//! takes her payment key and so stays here. A tower plays the same engine
//! from a package (`crate::tower`); the wallet sweeps what it won
//! ([`Wallet::sweep_dispute`]).

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxOut, Txid};
use lichen_chain::{Chain, Fees};
use lichen_proto::{anchor_vout, Built, Gadget, Statement};
use lngap_btc::taptree::TapTree;
use lngap_sessions::contract::{anchor_tree_for, Presign};
use lngap_btc::sighash::sign_tapscript;
use lngap_btc::witness::tapscript_witness;
use lngap_sessions::session::{bit_tree, reserve_tree};

pub use crate::engine::Outcome;
use crate::engine::{wait_confirmed, Engine, Options, Store, WalletSigner};
use crate::Wallet;

/// Her winnings swept to her payout address, with her anchors and the fee
/// budget's rest: the sweep's txid and what it pays.
pub type Swept = Option<(Txid, Amount)>;

/// An input of the sweep: its outpoint, prevout and sequence, and its leaf
/// (and whether the witness carries `b`'s signature), or none for a coin
/// of the fee budget (its key path).
type SweepIn = (OutPoint, TxOut, Sequence, Option<(TapTree, String, bool)>);

/// The wallet's contract `k` as a dispute's store.
struct HeldStore<'a> {
    w: &'a mut Wallet,
    k: usize,
}

impl Store for HeldStore<'_> {
    fn claim(&self) -> Option<(u32, String)> {
        self.w.contracts[self.k].claim.clone()
    }
    fn set_claim(&mut self, b: u32, input: &[u8]) -> Result<()> {
        self.w.contracts[self.k].claim = Some((b, hex::encode(input)));
        self.w.save()
    }
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
}

impl Wallet {
    /// Contract `k` is still open: no closing transaction, or one named
    /// (the hub's answer to a fold) that never reached the chain, which
    /// is then forgotten.
    fn ensure_open(&mut self, chain: &Chain, k: usize) -> Result<()> {
        if let Some(t) = self.contracts[k].closed {
            ensure!(chain.get_tx(&t).is_none(), "contract {} is closed ({t})", self.contracts[k].record.cid());
            self.contracts[k].closed = None;
            self.save()?;
        }
        Ok(())
    }

    fn step(&self, msg: String) {
        if let Some(f) = &self.progress {
            f(msg);
        }
    }

    /// Enforce a withdrawal of `b` from contract `cid` on Bitcoin, the
    /// claim's `input` the statement program's (for the mock, `(b, c)`;
    /// for Groth16, the verifier's input for her proof). Blocks until the
    /// dispute ends; on a win, sweeps her winnings to her payout address.
    ///
    /// Resumable: the claim is kept with the contract, and what is
    /// already on chain is replayed, not posted again.
    pub fn dispute(&mut self, chain: &Chain, statement: &Statement, dir: &Path, cid: u32, b: u32, input: &[u8]) -> Result<(Outcome, Swept)> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        self.ensure_open(chain, k)?;
        let held = self.contracts[k].clone();
        let signer = WalletSigner { secrets: self.secrets(&held.nonce), network: held.record.network };
        let opts = Options { progress: self.progress.clone(), pause_after: self.pause_after, unchecked_claims: self.unchecked_claims, lie: self.lie.clone() };
        let outcome = Engine { signer: &signer, store: &mut HeldStore { w: self, k }, opts }.run(chain, &held.record, statement, dir, b, input)?;
        if outcome.payout().is_none() {
            return Ok((outcome, None));
        }
        self.won(chain, statement, dir, k, b, outcome)
    }

    /// A tower played contract `cid`'s dispute (the claim of `b`) and was
    /// paid by `outcome`'s payout: keep it with the contract, and sweep.
    pub fn sweep_dispute(&mut self, chain: &Chain, statement: &Statement, dir: &Path, cid: u32, b: u32, outcome: Outcome) -> Result<(Outcome, Swept)> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        self.ensure_open(chain, k)?;
        let payout = outcome.payout().context("the tower's dispute wasn't won")?;
        let tx = chain.get_tx(&payout).with_context(|| format!("the payout {payout} is not on chain"))?;
        // a terminal of this contract's dispute (one of its links' outputs
        // spent), with the outputs a payout has, checked before it is kept
        let (_, set) = self.presigned(k, statement, dir)?;
        let links: std::collections::HashSet<_> = set.iter().map(|p| p.tx.compute_txid()).collect();
        ensure!(tx.input.first().is_some_and(|i| links.contains(&i.previous_output.txid)), "{payout} is no terminal of contract {cid}'s dispute");
        let t = &self.contracts[k].record.terms;
        ensure!(tx.output.len() as u32 > t.bits - t.low_bits, "{payout} hasn't a payout's outputs");
        self.contracts[k].payout = Some(outcome.clone());
        self.save()?;
        self.won(chain, statement, dir, k, b, outcome)
    }

    /// Contract `k`, built by its gadget, and its pre-signed set (both
    /// signatures checked).
    fn presigned(&self, k: usize, statement: &Statement, dir: &Path) -> Result<(Built, Vec<Presign>)> {
        let record = &self.contracts[k].record;
        let c = record.build(statement, statement.program_if(dir)?.as_ref())?;
        let set = record.presigned(&c)?;
        Ok((c, set))
    }

    /// Her signature on `b`, as the payout's leaves take it (the gadget's
    /// key for it).
    fn b_wire(&self, k: usize, statement: &Statement, b: u32) -> Result<Vec<Vec<u8>>> {
        let held = &self.contracts[k];
        match held.record.gadget() {
            Gadget::BitVmx => crate::engine::bitvmx::b_wire(&self.secrets(&held.nonce), &held.record, statement, b),
            Gadget::Babe => crate::engine::babe::b_wire(&self.secrets(&held.nonce), b),
        }
    }

    /// She won: once the payout confirms and her outputs' delay passes,
    /// sweep to her payout address her bit outputs and the reserves, and
    /// what else of the contract's is hers: the anchors of her links (left
    /// unspent where no fee child was needed) and the fee budget's rest.
    fn won(&mut self, chain: &Chain, statement: &Statement, dir: &Path, k: usize, b: u32, outcome: Outcome) -> Result<(Outcome, Swept)> {
        let txid = match &outcome {
            Outcome::HubTimedOut(t) | Outcome::Proved(t) | Outcome::PathRefuted(t) | Outcome::Unchallenged(t) | Outcome::Answered(t) => *t,
            Outcome::Lost | Outcome::Paused => bail!("not a win"),
        };
        let at = wait_confirmed(chain, &txid)?;
        let payout = chain.get_tx(&txid).context("the payout")?;
        let held = self.contracts[k].clone();
        let (c, set) = self.presigned(k, statement, dir)?;
        let core = c.core();
        let (t, ctx) = (core.terms, core.ctx());
        let b_key = c.b_key().clone();
        let b_wire = self.b_wire(k, statement, b)?;
        let kp = self.contract_keys(&held.nonce).payment;
        let delta = core.params.delta;
        let mut ins: Vec<SweepIn> = vec![];
        // her outputs: the bits set in b, then the reserves
        let at_delta = Sequence::from_height(delta);
        for i in t.low_bits..t.bits {
            if (b >> i) & 1 == 1 {
                let vout = i - t.low_bits;
                ins.push((OutPoint { txid, vout }, payout.output[vout as usize].clone(), at_delta, Some((bit_tree(&ctx, i, &b_key)?, format!("alice_bit_{i}"), true))));
            }
        }
        let vout = t.bits - t.low_bits;
        ins.push((OutPoint { txid, vout }, payout.output[vout as usize].clone(), at_delta, Some((reserve_tree(&ctx, t, &b_key)?, "alice_reserve".to_string(), false))));
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
        self.step(format!("the payout confirmed at {at}: the user's outputs can be swept from block {}", at + u32::from(delta)));
        while chain.height()? < at + u32::from(delta) {
            std::thread::sleep(Duration::from_millis(100));
        }
        let prevouts: Vec<TxOut> = ins.iter().map(|i| i.1.clone()).collect();
        let pairs: Vec<(OutPoint, TxOut)> = ins.iter().map(|i| (i.0, i.1.clone())).collect();
        let seqs: Vec<(OutPoint, Sequence)> = ins.iter().map(|i| (i.0, i.2)).collect();
        let build = |fee: Amount| -> Result<Transaction> {
            let out = TxOut { value: total.checked_sub(fee).context("the sweep can't pay its fee")?, script_pubkey: held.record.pubs[0].payout_spk.clone() };
            let mut sweep = lngap_btc::tx::build_tx(&seqs, vec![out], bitcoin::absolute::LockTime::ZERO);
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
        let parts: Vec<String> = [("b's bits and the reserves", winnings), ("the anchors", anchors), ("the fee budget's rest", budget)]
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
