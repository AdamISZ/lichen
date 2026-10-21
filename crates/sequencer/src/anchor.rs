//! Anchoring the history on Bitcoin (docs/ANCHOR_PLAN.md): the genesis
//! seal, then, while sealed heights are newer than the last anchored and
//! no anchor is in flight, an anchor of the last sealed height; once it
//! has its confirmations, its record applied to the ledger as an L2
//! transaction, which the next block carries to the chain prover.
//!
//! An anchor spends the seal (P2TR, the sequencer's key untweaked: a key
//! path spend signed here) and a coin of the sequencer's bitcoind wallet
//! for the fee; its outputs are the next seal, the commitment
//! (`OP_RETURN "lichen" ‖ at ‖ hist_at`) and the change. The anchor in
//! flight is kept beside the ledger (`<ledger>.anchor.json`), so a restart
//! picks it up.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{absolute, transaction, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use lichen_chain::Chain;
use lichen_l2::Event;
use lichen_ledger::lichen_validity::{commitment_script, seal_script};
use lichen_ledger::{files, OutPoint, Tx};

use crate::Shared;
use serde::{Deserialize, Serialize};

/// What the seal output holds (it moves from anchor to anchor).
pub const SEAL_VALUE: Amount = Amount::from_sat(1_000);

/// How a sequencer anchors.
#[derive(Clone, Debug)]
pub struct Anchoring {
    /// Confirmations before an anchor's record is applied.
    pub confirmations: u32,
    /// How often to look.
    pub every: Duration,
    /// The anchor's fee rate, sat/vB.
    pub feerate: u64,
}

impl Default for Anchoring {
    fn default() -> Anchoring {
        Anchoring { confirmations: 1, every: Duration::from_secs(5), feerate: 2 }
    }
}

/// An anchor signed (and broadcast, or about to be), not yet recorded:
/// kept before it is broadcast, so a crash never loses track of a spend
/// of the seal.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct InFlight {
    txid: Txid,
    at: u64,
    /// The signed transaction (hex), to broadcast again if it went
    /// missing.
    #[serde(default)]
    raw: Option<String>,
}

fn to_bitcoin(o: &OutPoint) -> bitcoin::OutPoint {
    bitcoin::OutPoint { txid: Txid::from_byte_array(o.txid), vout: o.vout }
}

pub fn seal_spk(sequencer: &[u8; 32]) -> ScriptBuf {
    ScriptBuf::from_bytes(seal_script(sequencer).to_vec())
}

/// Make the genesis seal: pay [`SEAL_VALUE`] to the seal's script from
/// the wallet; its outpoint (unconfirmed: the first anchor may spend it
/// at once).
pub fn genesis_seal(chain: &Chain, sequencer: &[u8; 32]) -> Result<OutPoint> {
    let spk = seal_spk(sequencer);
    let txid = chain.pay(&spk, SEAL_VALUE)?;
    let tx = chain.get_tx(&txid).context("the genesis seal's transaction")?;
    let vout = tx.output.iter().position(|o| o.script_pubkey == spk).context("the seal output")?;
    Ok(OutPoint { txid: txid.to_byte_array(), vout: vout as u32 })
}

/// An anchor's virtual size: the key path spend of the seal, the seal,
/// the commitment and the change (269 vB measured on Mutinynet with one
/// P2TR wallet coin), and 68 vB for each further coin (P2WPKH's, the
/// larger).
fn anchor_vsize(coins: usize) -> u64 {
    270 + 68 * coins.saturating_sub(1) as u64
}

/// The anchoring thread's shared state.
pub(crate) struct Anchorer {
    pub shared: Arc<Shared>,
    pub chain: Chain,
    pub opts: Anchoring,
}

impl Anchorer {
    fn flight_file(&self) -> Option<PathBuf> {
        self.shared.path.as_ref().map(|p| in_flight_file(p))
    }
    fn in_flight(&self) -> Option<InFlight> {
        std::fs::read(self.flight_file()?).ok().and_then(|b| serde_json::from_slice(&b).ok())
    }
    fn set_in_flight(&self, f: Option<&InFlight>) -> Result<()> {
        if let Some(p) = self.flight_file() {
            match f {
                Some(f) => files::write_atomic(&p, &serde_json::to_vec(f)?)?,
                None => match std::fs::remove_file(&p) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                    _ => {}
                },
            }
        }
        Ok(())
    }

    pub fn run(self, stop: Arc<AtomicBool>) {
        let mut flight = self.in_flight();
        while !stop.load(Ordering::Relaxed) {
            match self.step(&mut flight) {
                Ok(Some(m)) => println!("anchor: {m}"),
                Ok(None) => {}
                Err(e) => eprintln!("anchor: {e:#}"),
            }
            // sleep in short steps, to stop soon when asked
            let until = std::time::Instant::now() + self.opts.every;
            while std::time::Instant::now() < until && !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    /// One look: record the anchor in flight once confirmed, or send one
    /// if there's a newer sealed height. What happened, if anything.
    fn step(&self, flight: &mut Option<InFlight>) -> Result<Option<String>> {
        ensure!(!self.shared.poisoned.load(Ordering::SeqCst), "the ledger couldn't be saved: anchoring stopped");
        if let Some(f) = flight.clone() {
            // recorded already (a crash after the record was saved, before
            // the flight was cleared)
            if self.shared.ledger.lock().unwrap().anchor.seal.txid == f.txid.to_byte_array() {
                *flight = None;
                self.set_in_flight(None)?;
                return Ok(Some(format!("height {} already recorded ({})", f.at, f.txid)));
            }
            let Some(tx) = self.chain.get_tx(&f.txid) else {
                return self.missing(flight, &f);
            };
            if self.chain.confirmations(&f.txid)? < self.opts.confirmations {
                return Ok(None);
            }
            let block = self.chain.block_of(&f.txid)?.context("a confirmed anchor's block")?;
            let header = self.chain.header(&block)?;
            let txids = self.chain.block_txids(&block)?;
            let index = txids.iter().position(|t| *t == f.txid).context("the anchor among its block's transactions")?;
            let leaves: Vec<[u8; 32]> = txids.iter().map(|t| t.to_byte_array()).collect();
            let path = merkle_path(&leaves, index);
            // the block's coinbase and its path: they fix the tree's depth
            // for the statement
            let coinbase = self.chain.get_tx(&txids[0]).context("the anchor's block's coinbase")?;
            let bare = |t: &Transaction| {
                let mut t = t.clone();
                for i in &mut t.input {
                    i.witness = Witness::new();
                }
                bitcoin::consensus::serialize(&t)
            };
            let mut l = self.shared.ledger.lock().unwrap();
            let rec = l.anchor_record(bare(&tx), header, index as u32, path, bare(&coinbase), merkle_path(&leaves, 0))?;
            let t = Tx::Anchor(rec.to_bytes());
            l.apply(&t).context("the anchor's record")?;
            self.shared.save(&l)?;
            self.shared.events.lock().unwrap().push(Event::of(&t));
            drop(l);
            *flight = None;
            self.set_in_flight(None)?;
            return Ok(Some(format!("height {} anchored in {} (block {block}), recorded", f.at, f.txid)));
        }
        let (seal, at, hist, news) = {
            let l = self.shared.ledger.lock().unwrap();
            let Some(last) = l.sealed.last() else { return Ok(None) };
            // something new since the last anchor's height, not only the
            // record of an anchor (else each record would be anchored in
            // turn, for ever)
            let news = match l.anchor.height {
                0 => true,
                h => l.sealed.get(h as usize - 1).is_some_and(|a| a.height < last.height && (a.size, a.nullifiers) != (last.size, last.nullifiers)),
            };
            (l.anchor.seal, last.height, l.hist_at(last.height), news)
        };
        ensure!(seal.txid != [0; 32], "this deployment has no genesis seal: it can't be anchored");
        if !news {
            return Ok(None);
        }
        let (tx, coins) = self.sign(&seal, at, &hist)?;
        let f = InFlight { txid: tx.compute_txid(), at, raw: Some(bitcoin::consensus::encode::serialize_hex(&tx)) };
        if let Err(e) = self.set_in_flight(Some(&f)) {
            let _ = self.chain.unlock(&coins);
            return Err(e.context("keeping the anchor in flight"));
        }
        *flight = Some(f.clone());
        // a broadcast that fails, or whose answer is lost, is settled at
        // the next look: found, broadcast again, or given up
        self.chain.broadcast(&tx).with_context(|| format!("broadcasting the anchor {} of height {at}", f.txid))?;
        Ok(Some(format!("height {at} sent for anchoring: {}", f.txid)))
    }

    /// The anchor in flight isn't found. It is gone only if the seal is
    /// unspent: then broadcast it again, or, if that fails, give it up
    /// (its coins freed) so the next look sends another. If the seal is
    /// spent, by this anchor unseen or by anything else, wait: sending
    /// another would spend it twice.
    fn missing(&self, flight: &mut Option<InFlight>, f: &InFlight) -> Result<Option<String>> {
        let seal = to_bitcoin(&self.shared.ledger.lock().unwrap().anchor.seal);
        if !self.chain.unspent(&seal)? {
            bail!("the anchor {} of height {} isn't found, but the seal {seal} is spent: waiting", f.txid, f.at);
        }
        let raw = f.raw.as_deref().and_then(|h| bitcoin::consensus::encode::deserialize_hex::<Transaction>(h).ok());
        if let Some(tx) = &raw {
            if self.chain.broadcast(tx).is_ok() {
                return Ok(Some(format!("the anchor {} of height {} broadcast again", f.txid, f.at)));
            }
            let _ = self.chain.unlock(&tx.input.iter().skip(1).map(|i| i.previous_output).collect::<Vec<_>>());
        }
        *flight = None;
        self.set_in_flight(None)?;
        bail!("the anchor {} of height {} is gone; sending another", f.txid, f.at)
    }

    /// Build and sign an anchor of height `at` spending `seal`, and the
    /// wallet coins it locked for its fee.
    fn sign(&self, seal: &OutPoint, at: u64, hist: &[u8; 32]) -> Result<(Transaction, Vec<bitcoin::OutPoint>)> {
        let seal = to_bitcoin(seal);
        let prev = self.chain.get_tx(&seal.txid).context("the seal's transaction")?;
        let seal_out = prev.output.get(seal.vout as usize).context("the seal output")?.clone();
        let sequencer = self.shared.key.verifying_key().to_bytes();
        ensure!(seal_out.script_pubkey == seal_spk(&sequencer.into()), "the seal isn't this sequencer's");
        // the change script before any coin is locked
        let change = self.chain.new_spk()?;
        // enough for an anchor with up to three coins; its fee then from
        // the coins chosen
        let coins = self.chain.select(Amount::from_sat(anchor_vsize(3) * self.opts.feerate + 330))?;
        let locked: Vec<bitcoin::OutPoint> = coins.iter().map(|c| c.0).collect();
        let r = (|| -> Result<Transaction> {
            let fee = Amount::from_sat(anchor_vsize(coins.len()) * self.opts.feerate);
            let total: Amount = coins.iter().map(|c| c.1.value).sum();
            ensure!(total >= fee + Amount::from_sat(330), "the coins chosen don't pay the anchor's fee");
            let tx = Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: std::iter::once(seal).chain(coins.iter().map(|c| c.0)).map(|o| TxIn { previous_output: o, script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, witness: Witness::new() }).collect(),
                output: vec![
                    TxOut { value: seal_out.value, script_pubkey: seal_out.script_pubkey.clone() },
                    TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(commitment_script(at, hist).to_vec()) },
                    TxOut { value: total - fee, script_pubkey: change },
                ],
            };
            let prevouts: Vec<(bitcoin::OutPoint, TxOut)> = std::iter::once((seal, seal_out)).chain(coins.iter().cloned()).collect();
            let mut signed = self.chain.sign_mine(&tx, &prevouts)?;
            let outs: Vec<TxOut> = prevouts.iter().map(|p| p.1.clone()).collect();
            let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(0, &Prevouts::All(&outs), TapSighashType::Default)?;
            let secp = Secp256k1::new();
            let keypair = Keypair::from_seckey_slice(&secp, &self.shared.key.to_bytes())?;
            let sig = secp.sign_schnorr(&Message::from_digest(sighash.to_byte_array()), &keypair);
            signed.input[0].witness = Witness::from_slice(&[sig.as_ref()]);
            Ok(signed)
        })();
        match r {
            Ok(tx) => Ok((tx, locked)),
            Err(e) => {
                let _ = self.chain.unlock(&locked);
                Err(e)
            }
        }
    }
}

/// The Merkle path of the txid at `index` among `txids` (internal order),
/// siblings from the leaves up; a level's odd last node pairs with itself.
pub fn merkle_path(txids: &[[u8; 32]], mut index: usize) -> Vec<[u8; 32]> {
    let mut level = txids.to_vec();
    let mut path = vec![];
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        path.push(level[index ^ 1]);
        level = level.chunks(2).map(|p| lichen_ledger::lichen_validity::btc::sha256d(&[p[0], p[1]].concat())).collect();
        index /= 2;
    }
    path
}

/// The anchor in flight beside the ledger at `p`, for a reader (tests).
pub fn in_flight_file(p: &Path) -> PathBuf {
    p.with_extension("anchor.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_ledger::lichen_validity::btc;

    /// Every index's path, for 1 to 9 transactions (odd levels pair their
    /// last node with itself), leads to the root Bitcoin computes.
    #[test]
    fn merkle_paths_lead_to_bitcoins_root() {
        for n in 1..=9u8 {
            let txids: Vec<[u8; 32]> = (0..n).map(|i| btc::sha256d(&[i, n])).collect();
            let root = bitcoin::merkle_tree::calculate_root(txids.iter().map(|t| Txid::from_byte_array(*t))).unwrap();
            for i in 0..n as usize {
                let path = merkle_path(&txids, i);
                assert_eq!(btc::merkle_root(&txids[i], i as u32, &path), root.to_byte_array(), "{n} transactions, index {i}");
            }
        }
    }

    #[test]
    fn an_anchors_size_grows_with_its_coins() {
        assert_eq!(anchor_vsize(1), 270);
        assert_eq!(anchor_vsize(3), 270 + 2 * 68);
    }
}
