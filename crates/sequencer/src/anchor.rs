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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{absolute, transaction, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use lichen_chain::Chain;
use lichen_l2::Event;
use lichen_ledger::k256::schnorr::SigningKey;
use lichen_ledger::lichen_validity::{commitment_script, seal_script};
use lichen_ledger::{Ledger, OutPoint, Tx};
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

/// An anchor broadcast, not yet recorded.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct InFlight {
    txid: Txid,
    at: u64,
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

/// The anchoring thread's shared state.
pub(crate) struct Anchorer {
    pub ledger: Arc<Mutex<Ledger>>,
    pub events: Arc<Mutex<Vec<Event>>>,
    pub path: Option<PathBuf>,
    pub key: SigningKey,
    pub chain: Chain,
    pub opts: Anchoring,
}

impl Anchorer {
    fn flight_file(&self) -> Option<PathBuf> {
        self.path.as_ref().map(|p| p.with_extension("anchor.json"))
    }
    fn in_flight(&self) -> Option<InFlight> {
        std::fs::read(self.flight_file()?).ok().and_then(|b| serde_json::from_slice(&b).ok())
    }
    fn set_in_flight(&self, f: Option<&InFlight>) -> Result<()> {
        if let Some(p) = self.flight_file() {
            match f {
                Some(f) => std::fs::write(p, serde_json::to_vec(f)?)?,
                None => {
                    let _ = std::fs::remove_file(p);
                }
            }
        }
        Ok(())
    }
    fn save(&self, l: &Ledger) {
        if let Some(p) = &self.path {
            let _ = std::fs::write(p, serde_json::to_vec(l).unwrap());
        }
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
        if let Some(f) = flight.clone() {
            let Some(tx) = self.chain.get_tx(&f.txid) else {
                // gone (never relayed, or replaced): the seal is unspent
                // again, so send another
                *flight = None;
                self.set_in_flight(None)?;
                bail!("the anchor {} of height {} is gone; sending another", f.txid, f.at);
            };
            if self.chain.confirmations(&f.txid)? < self.opts.confirmations {
                return Ok(None);
            }
            let block = self.chain.block_of(&f.txid)?.context("a confirmed anchor's block")?;
            let header = self.chain.header(&block)?;
            let txids = self.chain.block_txids(&block)?;
            let index = txids.iter().position(|t| *t == f.txid).context("the anchor among its block's transactions")?;
            let path = merkle_path(&txids.iter().map(|t| t.to_byte_array()).collect::<Vec<_>>(), index);
            let mut bare = tx.clone();
            for i in &mut bare.input {
                i.witness = Witness::new();
            }
            let bytes = bitcoin::consensus::serialize(&bare);
            let mut l = self.ledger.lock().unwrap();
            let rec = l.anchor_record(bytes, header, index as u32, path)?;
            let t = Tx::Anchor(rec.to_bytes());
            l.apply(&t).context("the anchor's record")?;
            self.events.lock().unwrap().push(Event::of(&t));
            self.save(&l);
            drop(l);
            *flight = None;
            self.set_in_flight(None)?;
            return Ok(Some(format!("height {} anchored in {} (block {block}), recorded", f.at, f.txid)));
        }
        let (seal, at, hist, news) = {
            let l = self.ledger.lock().unwrap();
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
        let txid = self.send(&seal, at, &hist)?;
        let f = InFlight { txid, at };
        self.set_in_flight(Some(&f))?;
        *flight = Some(f);
        Ok(Some(format!("height {at} sent for anchoring: {txid}")))
    }

    /// Build, sign and broadcast an anchor of height `at` spending `seal`.
    fn send(&self, seal: &OutPoint, at: u64, hist: &[u8; 32]) -> Result<Txid> {
        let seal = to_bitcoin(seal);
        let prev = self.chain.get_tx(&seal.txid).context("the seal's transaction")?;
        let seal_out = prev.output.get(seal.vout as usize).context("the seal output")?.clone();
        let sequencer = self.key.verifying_key().to_bytes();
        ensure!(seal_out.script_pubkey == seal_spk(&sequencer.into()), "the seal isn't this sequencer's");
        // about 220 vB: the key path spend, a P2TR wallet input, three outputs
        let fee = Amount::from_sat(220 * self.opts.feerate);
        let coins = self.chain.select(fee + Amount::from_sat(330))?;
        let total: Amount = coins.iter().map(|c| c.1.value).sum();
        let change = self.chain.new_spk()?;
        let mut tx = Transaction {
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
        let r = (|| -> Result<Txid> {
            let mut signed = self.chain.sign_mine(&tx, &prevouts)?;
            let outs: Vec<TxOut> = prevouts.iter().map(|p| p.1.clone()).collect();
            let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(0, &Prevouts::All(&outs), TapSighashType::Default)?;
            let secp = Secp256k1::new();
            let keypair = Keypair::from_seckey_slice(&secp, &self.key.to_bytes())?;
            let sig = secp.sign_schnorr(&Message::from_digest(sighash.to_byte_array()), &keypair);
            signed.input[0].witness = Witness::from_slice(&[sig.as_ref()]);
            tx = signed;
            self.chain.broadcast(&tx)
        })();
        if r.is_err() {
            let _ = self.chain.unlock(&coins.iter().map(|c| c.0).collect::<Vec<_>>());
        }
        r
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
