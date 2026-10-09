//! The user's wallet: a key, the notes it owns on the L2, transfers,
//! returns to the hub (the first step of a withdrawal), and its contracts
//! with the hub (opening: [`Wallet::open_contract`]).
//!
//! The ledger is transparent, so the wallet finds its notes by reading the
//! sequencer's state; it checks every sealed root's signature, and builds a
//! withdrawal's input itself, checked against the statement.

pub mod dispute;

use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use lichen_ledger::k256::schnorr::SigningKey;
use lichen_ledger::{fresh_rho, note, sign, xonly, Hash, Note, Spend, Transfer, Tx, WithdrawInput, HUB_KEY};
use lichen_chain::Chain;
use lichen_proto::{all_moves, check_funding, contributions, terms, Accept, FoldRequest, Folded, Info, OpenOffer, OpenRequest, Opened, Record, Statement, FEE_SHARE, FOLD_FEE};
use lichen_sequencer::{Client, State};
use lngap_btc::keys::Seed;
use lngap_channel::{PartyKeys, Role};
use lngap_lamport::winternitz::{WotsParams, WotsSecret};
use lngap_sessions::contract::{move_bytes, sign_all};
use serde::{Deserialize, Serialize};

/// What the wallet keeps on disk.
#[derive(Serialize, Deserialize)]
struct Stored {
    /// The secret key, hex.
    secret: String,
    /// This wallet's returns to the hub: (memo, note index).
    returns: Vec<(u32, u32)>,
    /// Its contracts: each one's nonce (from which its keys derive) and
    /// record.
    #[serde(default)]
    contracts: Vec<Held>,
}

/// A contract the wallet holds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Held {
    pub nonce: String,
    pub record: Record,
    /// The fold's txid, once withdrawn cooperatively.
    #[serde(default)]
    pub closed: Option<bitcoin::Txid>,
}

pub struct Wallet {
    key: SigningKey,
    path: PathBuf,
    returns: Vec<(u32, u32)>,
    pub contracts: Vec<Held>,
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
        let w = Wallet { key, path: path.to_path_buf(), returns: vec![], contracts: vec![], sequencer: Client::new(sequencer) };
        w.save()?;
        Ok(w)
    }
    pub fn open(path: &Path, sequencer: &str) -> Result<Wallet> {
        let s: Stored = serde_json::from_slice(&std::fs::read(path).with_context(|| format!("no wallet at {}", path.display()))?)?;
        let key = SigningKey::from_bytes(&hex::decode(&s.secret)?).context("the wallet's key")?;
        Ok(Wallet { key, path: path.to_path_buf(), returns: s.returns, contracts: s.contracts, sequencer: Client::new(sequencer) })
    }
    pub(crate) fn save(&self) -> Result<()> {
        let s = Stored { secret: hex::encode(self.key.to_bytes()), returns: self.returns.clone(), contracts: self.contracts.clone() };
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

/// What Alice asks for in a contract: her deposit `D`, a cap of
/// `2^bits - 1` sats, her reserve `r_A`.
#[derive(Clone, Copy, Debug)]
pub struct Ask {
    pub deposit: u64,
    pub bits: u32,
    pub reserve: u64,
}

/// A request to the hub, its error passed through.
fn hub_call<T: for<'de> Deserialize<'de>>(url: &str, body: Option<String>) -> Result<T> {
    let r = match body {
        Some(b) => ureq::post(url).set("Content-Type", "application/json").send_string(&b),
        None => ureq::get(url).call(),
    };
    match r {
        Ok(r) => Ok(r.into_json()?),
        Err(ureq::Error::Status(_, r)) => {
            let v: serde_json::Value = r.into_json().unwrap_or_default();
            bail!("the hub refused: {}", v.get("error").and_then(|e| e.as_str()).unwrap_or("?"))
        }
        Err(e) => bail!("{url}: {e}"),
    }
}

impl Wallet {
    /// The seed of the contract with `nonce`.
    fn contract_seed(&self, nonce: &str) -> String {
        format!("{}/contract/{nonce}", hex::encode(self.key.to_bytes()))
    }
    /// Alice's keys for a contract.
    pub fn contract_keys(&self, nonce: &str) -> PartyKeys {
        PartyKeys::from_seed(Role::User, Seed::from_label(&self.contract_seed(nonce)))
    }
    /// Alice's move key for depth `d` (of `m`) of a contract.
    pub fn move_secret(&self, nonce: &str, d: u32, m: u32) -> WotsSecret {
        WotsSecret::from_entropy(WotsParams::for_bytes(move_bytes(d, m)), Seed::from_label(&format!("{}/move/{d}", self.contract_seed(nonce))).derive_bytes("wots"))
    }
    /// Alice's key for input word `j` of a contract.
    pub fn input_secret(&self, nonce: &str, j: usize) -> WotsSecret {
        WotsSecret::from_entropy(lngap_zk::final_d60::input_key_params(), Seed::from_label(&format!("{}/input/{j}", self.contract_seed(nonce))).derive_bytes("wots"))
    }

    /// Open a contract with the hub at `hub` on the terms `ask`. Funds from
    /// `chain`; runs
    /// `statement` (programs built under `dir`). Checks the hub's offer and
    /// every signature in it before signing anything; returns once the
    /// funding is broadcast. The hub mints the deposit when it confirms.
    pub fn open_contract(&mut self, hub: &str, chain: &Chain, statement: &Statement, dir: &Path, ask: Ask) -> Result<Held> {
        let Ask { deposit, bits, reserve } = ask;
        let info: Info = hub_call(&format!("{hub}/info"), None)?;
        ensure!(info.statement == statement.id(), "the hub runs {}, this wallet {}", info.statement, statement.id());
        let program = statement.program(dir)?;
        let m = program.depths();
        ensure!(info.depths == m, "the hub's statement has {} depths, ours {m}", info.depths);
        let nonce = hex::encode(fresh_rho());
        let keys = self.contract_keys(&nonce);
        let mut alice = keys.public();
        alice.payout_spk = chain.new_spk()?;
        let moves: Vec<_> = (1..=m).filter(|d| d % 2 == 1).map(|d| self.move_secret(&nonce, d, m).public()).collect();
        let inputs: Vec<_> = (0..program.info.input_words).map(|j| self.input_secret(&nonce, j).public()).collect();
        let need = bitcoin::Amount::from_sat(deposit + reserve);
        let coins = chain.select(need + FEE_SHARE + bitcoin::Amount::from_sat(10_000))?;
        let spent: bitcoin::Amount = coins.iter().map(|c| c.1.value).sum();
        let change = bitcoin::TxOut { value: spent - need - FEE_SHARE, script_pubkey: chain.new_spk()? };
        let req = OpenRequest { alice, l2_address: self.address(), deposit, bits, reserve, moves: moves.clone(), inputs: inputs.clone(), coins: coins.clone(), change: change.clone() };
        let offer: OpenOffer = hub_call(&format!("{hub}/open"), Some(serde_json::to_string(&req)?))?;
        // the contract as the offer makes it, checked before signing
        let t = terms(offer.cid, &req, offer.t_close, offer.reserve_hub)?;
        ensure!(offer.t_close > chain.height()?, "T_close is past");
        let mut record = Record {
            statement: statement.id().to_string(),
            terms: t,
            pubs: [req.alice.clone(), offer.hub.clone()],
            moves: all_moves(&moves, &offer.moves),
            inputs,
            l2_address: self.address(),
            funding: bitcoin::OutPoint { txid: offer.funding.compute_txid(), vout: 0 },
            hub_sigs: offer.hub_sigs.clone(),
            alice_sigs: Default::default(),
        };
        let c = record.contract(statement, &program)?;
        check_funding(&offer.funding, &c, &coins, &change, contributions(&t).0)?;
        let set = c.presign(record.funding)?;
        for p in &set {
            let s = record.hub_sigs.get(&p.name).with_context(|| format!("the hub didn't sign {}", p.name))?;
            p.verify(&record.pubs[1].payment, s)?;
        }
        record.alice_sigs = sign_all(&set, &keys.payment)?;
        let prevouts: Vec<_> = coins.iter().chain(&offer.hub_coins).cloned().collect();
        let funding = chain.sign_mine(&offer.funding, &prevouts)?;
        let accept = Accept { cid: offer.cid, alice_sigs: record.alice_sigs.clone(), funding };
        let _: Opened = hub_call(&format!("{hub}/accept"), Some(serde_json::to_string(&accept)?))?;
        let held = Held { nonce, record, closed: None };
        self.contracts.push(held.clone());
        self.save()?;
        Ok(held)
    }

    /// Withdraw `b` sats from contract `cid` cooperatively: return `b` to
    /// the hub on the L2 with the contract's memo, wait until a sealed
    /// height includes it, then sign the fold (Alice `b + r_A`, the hub the
    /// rest) and ask the hub to close. Returns the fold's txid.
    pub fn withdraw(&mut self, hub: &str, statement: &Statement, dir: &Path, cid: u32, b: u64) -> Result<bitcoin::Txid> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let held = self.contracts[k].clone();
        ensure!(held.closed.is_none(), "contract {cid} is closed");
        ensure!(bitcoin::Amount::from_sat(b) <= held.record.terms.v_max(), "{b} sats is above the cap");
        let index = self.return_to_hub(b, cid)?;
        let start = std::time::Instant::now();
        while self.sequencer.state()?.withdraw_input(index).is_err() {
            ensure!(start.elapsed() < std::time::Duration::from_secs(120), "the return was never sealed");
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let program = statement.program(dir)?;
        let c = held.record.contract(statement, &program)?;
        let fold = c.fold(held.record.funding, bitcoin::Amount::from_sat(b), FOLD_FEE)?;
        let alice_sig = fold.sign(&self.contract_keys(&held.nonce).payment)?;
        let req = FoldRequest { cid, index, b, alice_sig };
        let done: Folded = hub_call(&format!("{hub}/fold"), Some(serde_json::to_string(&req)?))?;
        self.contracts[k].closed = Some(done.txid);
        self.save()?;
        Ok(done.txid)
    }
}
