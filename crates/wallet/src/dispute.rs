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
use lichen_proto::{anchor_vout, Disputed, Statement};
use lngap_btc::taptree::TapTree;
use lngap_channel::Role;
use lngap_sessions::contract::anchor_tree_for;
use lngap_btc::sighash::sign_tapscript;
use lngap_btc::witness::tapscript_witness;
use lngap_ladder::script::wots_wire;
use lngap_sessions::session::{bit_tree, reserve_tree};
use lngap_zk::final_d60::input_message;

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
        ensure!(self.contracts[k].closed.is_none(), "contract {cid} is closed");
        let held = self.contracts[k].clone();
        let signer = WalletSigner { secrets: self.secrets(&held.nonce), network: held.record.network };
        let opts = Options { progress: self.progress.clone(), pause_after: self.pause_after, unchecked_claims: self.unchecked_claims, lie: self.lie.clone() };
        let outcome = Engine { signer: &signer, store: &mut HeldStore { w: self, k }, opts }.run(chain, &held.record, statement, dir, b, input)?;
        if outcome.payout().is_none() {
            return Ok((outcome, None));
        }
        let d = Disputed::new(&held.record, statement, dir)?;
        self.won(chain, &d, k, b, outcome)
    }

    /// A tower played contract `cid`'s dispute (the claim of `b`) and was
    /// paid by `outcome`'s payout: keep it with the contract, and sweep.
    pub fn sweep_dispute(&mut self, chain: &Chain, statement: &Statement, dir: &Path, cid: u32, b: u32, outcome: Outcome) -> Result<(Outcome, Swept)> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        ensure!(self.contracts[k].closed.is_none(), "contract {cid} is closed");
        let payout = outcome.payout().context("the tower's dispute wasn't won")?;
        ensure!(chain.get_tx(&payout).is_some(), "the payout {payout} is not on chain");
        self.contracts[k].payout = Some(outcome.clone());
        self.save()?;
        let d = Disputed::new(&self.contracts[k].record, statement, dir)?;
        self.won(chain, &d, k, b, outcome)
    }

    /// She won: once the payout confirms and her outputs' delay passes,
    /// sweep to her payout address her bit outputs and the reserves, and
    /// what else of the contract's is hers: the anchors of her links (left
    /// unspent where no fee child was needed) and the fee budget's rest.
    fn won(&mut self, chain: &Chain, d: &Disputed, k: usize, b: u32, outcome: Outcome) -> Result<(Outcome, Swept)> {
        let txid = match &outcome {
            Outcome::HubTimedOut(t) | Outcome::Proved(t) | Outcome::PathRefuted(t) => *t,
            Outcome::Lost | Outcome::Paused => bail!("not a win"),
        };
        let at = wait_confirmed(chain, &txid)?;
        let payout = chain.get_tx(&txid).context("the payout")?;
        let held = self.contracts[k].clone();
        let t = &d.contract.spec.terms;
        let ctx = d.contract.ctx();
        let b_key = d.contract.b_key().clone();
        let b_sig = self.input_secret(&held.nonce, d.contract.spec.b_word).sign(&input_message(b))?;
        let kp = self.contract_keys(&held.nonce).payment;
        let delta = d.contract.spec.params.delta;
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
        // her links' anchors, where they are unspent
        let mine = kp.x_only_public_key().0;
        let anchor = anchor_tree_for(&mine)?;
        let link = |n: &str| n == "escalate" || n == "inputs" || n.starts_with("move_") || n.starts_with("hop_");
        let mut names: Vec<&String> = d.set.keys().filter(|n| link(n) && d.contract.poster(n) == Role::User).collect();
        names.sort();
        for name in names {
            let id = d.txid(name);
            let Some(tx) = chain.get_tx(&id) else { continue };
            let op = OutPoint { txid: id, vout: anchor_vout(&tx, &mine)? };
            if chain.unspent(&op)? {
                ins.push((op, tx.output[op.vout as usize].clone(), Sequence::ENABLE_RBF_NO_LOCKTIME, Some((anchor.clone(), "fee".to_string(), false))));
            }
        }
        let anchors: Amount = ins.iter().map(|i| i.1.value).sum::<Amount>() - winnings;
        // the fee budget's rest
        let fees = self.fees_for(d.contract.spec.cid)?;
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
                    let mut w = if *with_b { wots_wire(&b_sig) } else { vec![] };
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
