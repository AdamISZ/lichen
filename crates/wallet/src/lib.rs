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
use lichen_ledger::{fresh_rho, note, sign, xonly, Deployment, Hash, Note, Spend, Transfer, Tx, WithdrawInput};
use lichen_chain::{Chain, KeyFees};
use lichen_proto::{all_moves, check_deposit_funding, deposit_tree, fee_budget_of, tail_keys, terms, Accept, DepositOffer, DepositRequest, FoldRequest, Folded, Info, OpenOffer, OpenRequest, Opened, Record, Statement, DEPOSIT_OPEN, DEPOSIT_REFUND, FEE_SHARE, FOLD_FEE};
use lichen_sequencer::{Client, State};
use lngap_btc::keys::Seed;
use lngap_channel::{PartyKeys, Role};
use lngap_lamport::winternitz::{WotsParams, WotsSecret};
use lngap_sessions::contract::{sign_all, Program};
use serde::{Deserialize, Serialize};

/// What the wallet keeps on disk.
#[derive(Serialize, Deserialize)]
struct Stored {
    /// The secret key, hex.
    secret: String,
    /// The L2 deployment, pinned when the wallet was made (an older file
    /// without it pins it on first open).
    #[serde(default)]
    deployment: Option<Deployment>,
    /// This wallet's returns to the hub: (memo, note index).
    returns: Vec<(u32, u32)>,
    /// Its contracts: each one's nonce (from which its keys derive) and
    /// record.
    #[serde(default)]
    contracts: Vec<Held>,
    /// Deposits paid (or to be paid) for contracts not yet open.
    #[serde(default)]
    deposits: Vec<Deposit>,
}

/// A deposit for a contract not yet open: kept from before it is paid,
/// so that it can always be refunded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Deposit {
    /// The contract's nonce (its keys derive from it) and number.
    pub nonce: String,
    pub cid: u32,
    /// The hub's key in the tree, and the refund's timeout.
    pub hub: bitcoin::XOnlyPublicKey,
    pub timeout: u16,
    /// Where a refund goes.
    pub payout: bitcoin::ScriptBuf,
}

/// A contract the wallet holds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Held {
    pub nonce: String,
    pub record: Record,
    /// How it ended: the fold's txid, or the dispute's payout (or the
    /// spend that took it).
    #[serde(default)]
    pub closed: Option<bitcoin::Txid>,
    /// A dispute in progress: the claim (`b` and the statement's input,
    /// hex), so that it can be resumed; and the payout once posted.
    #[serde(default)]
    pub claim: Option<(u32, String)>,
    #[serde(default)]
    pub payout: Option<dispute::Outcome>,
}

pub struct Wallet {
    /// For tests: stop a dispute after posting this move (it resumes
    /// from the chain when run again).
    pub pause_after: Option<u32>,
    /// For tests: escalate a claim even if it breaks one of the contract's
    /// checks (as a careless or dishonest wallet would).
    pub unchecked_claims: bool,
    /// For tests: lie in the dispute's execution (BitVMX's fault
    /// injection: a read's value, a long jump's hash).
    pub lie: Option<emulator::executor::utils::FailConfiguration>,
    /// Told each step of a dispute, in words (for a front end).
    pub progress: Option<std::sync::Arc<dyn Fn(String) + Send + Sync>>,
    key: SigningKey,
    path: PathBuf,
    returns: Vec<(u32, u32)>,
    pub contracts: Vec<Held>,
    pub deposits: Vec<Deposit>,
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
        // the deployment the sequencer announces, kept from now on
        let w = Wallet { pause_after: None, unchecked_claims: false, lie: None, progress: None, key, path: path.to_path_buf(), returns: vec![], contracts: vec![], deposits: vec![], sequencer: Client::new(sequencer)? };
        w.save()?;
        Ok(w)
    }
    pub fn open(path: &Path, sequencer: &str) -> Result<Wallet> {
        let s: Stored = serde_json::from_slice(&std::fs::read(path).with_context(|| format!("no wallet at {}", path.display()))?)?;
        let key = SigningKey::from_bytes(&hex::decode(&s.secret)?).context("the wallet's key")?;
        let client = match s.deployment {
            Some(d) => Client::pinned(sequencer, d),
            None => Client::new(sequencer)?,
        };
        let w = Wallet { pause_after: None, unchecked_claims: false, lie: None, progress: None, key, path: path.to_path_buf(), returns: s.returns, contracts: s.contracts, deposits: s.deposits, sequencer: client };
        if s.deployment.is_none() {
            w.save()?;
        }
        Ok(w)
    }
    pub(crate) fn save(&self) -> Result<()> {
        let s = Stored { secret: hex::encode(self.key.to_bytes()), deployment: Some(self.sequencer.deployment), returns: self.returns.clone(), contracts: self.contracts.clone(), deposits: self.deposits.clone() };
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
        let idx = self.send(self.sequencer.deployment.hub, b, c)?[0];
        self.returns.push((c, idx));
        self.save()?;
        Ok(idx)
    }
    /// The withdrawal statement's input for our return with memo `c`, once
    /// it is sealed.
    pub fn withdraw_input(&self, c: u32) -> Result<WithdrawInput> {
        let &(_, idx) = self.returns.iter().find(|r| r.0 == c).with_context(|| format!("no return with memo {c}"))?;
        self.sequencer.state()?.withdraw_input(idx, &self.sequencer.deployment)
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
    /// Alice's move keys for depth `d` of a contract, one per field.
    pub fn move_secrets(&self, nonce: &str, program: &Program, d: u32) -> Vec<WotsSecret> {
        let at = |f: usize, n: u32| WotsSecret::from_entropy(WotsParams::for_bytes(n), Seed::from_label(&format!("{}/move/{d}/{f}", self.contract_seed(nonce))).derive_bytes("wots"));
        program.field_bytes(d).into_iter().enumerate().map(|(f, n)| at(f, n)).collect()
    }
    /// Alice's key for her choice of hop against the hub's path of `k`
    /// chunks (under a jump list).
    pub fn hop_secret(&self, nonce: &str, k: usize) -> WotsSecret {
        WotsSecret::from_entropy(WotsParams::for_bytes(1), Seed::from_label(&format!("{}/hop/{k}", self.contract_seed(nonce))).derive_bytes("wots"))
    }
    /// Alice's key in a contract's deposit tree.
    pub fn deposit_key(&self, nonce: &str) -> bitcoin::key::Keypair {
        Seed::from_label(&self.contract_seed(nonce)).keypair("deposit")
    }
    /// A contract's fee budget, on `net`: one key's coins.
    pub fn fees(&self, nonce: &str, net: lichen_chain::Net) -> KeyFees {
        KeyFees { keypair: Seed::from_label(&self.contract_seed(nonce)).keypair("fee"), feerate: lichen_proto::feerate(net) }
    }
    /// The fee budget of contract `cid`.
    pub fn fees_for(&self, cid: u32) -> Result<KeyFees> {
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        Ok(self.fees(&h.nonce, h.record.network))
    }
    /// Alice's key for input word `j` of a contract.
    pub fn input_secret(&self, nonce: &str, j: usize) -> WotsSecret {
        WotsSecret::from_entropy(lngap_zk::final_d60::input_key_params(), Seed::from_label(&format!("{}/input/{j}", self.contract_seed(nonce))).derive_bytes("wots"))
    }

    /// The amount a deposit for `ask` on `net` must carry: `D + r_A`, the
    /// funding fee's share, and the fee budget.
    pub fn deposit_amount(ask: &Ask, net: lichen_chain::Net) -> bitcoin::Amount {
        bitcoin::Amount::from_sat(ask.deposit + ask.reserve) + FEE_SHARE + lichen_proto::fee_budget(net)
    }

    /// Open a contract with the hub at `hub` on the terms `ask`, running
    /// `statement` (programs built under `dir`). No wallet of the user's:
    /// the hub gives a deposit address, which `pay` is asked to pay (from
    /// anywhere: a wallet, a faucet), and every payout goes to `payout`.
    /// Waits for the deposit to confirm, then checks the hub's offer and
    /// every signature in it before signing anything; returns once the
    /// funding is broadcast. The hub mints the deposit when it confirms.
    /// The deposit is kept from before it is paid ([`Wallet::refund`]).
    pub fn open_contract(&mut self, hub: &str, chain: &Chain, statement: &Statement, dir: &Path, ask: Ask, payout: bitcoin::ScriptBuf, pay: &dyn Fn(&bitcoin::Address, bitcoin::Amount) -> Result<()>) -> Result<Held> {
        let Ask { deposit, bits, reserve } = ask;
        let info: Info = hub_call(&format!("{hub}/info"), None)?;
        let net = chain.network;
        ensure!(info.network == net, "the hub is on {}, this wallet's coins on {net}", info.network);
        let d = self.sequencer.deployment;
        ensure!(info.deployment == d, "the hub is in another deployment (sequencer {}, hub {}) than this wallet's (sequencer {}, hub {})", hex::encode(info.deployment.sequencer), hex::encode(info.deployment.hub), hex::encode(d.sequencer), hex::encode(d.hub));
        ensure!(info.statement == statement.id(), "the hub runs {}, this wallet {}", info.statement, statement.id());
        let program = statement.program(dir)?;
        let m = program.depths();
        ensure!(info.depths == m, "the hub's statement has {} depths, ours {m}", info.depths);
        bitcoin::Address::from_script(&payout, net.bitcoin()).with_context(|| format!("the payout address isn't a {net} address"))?;

        // the deposit: an address of the hub's and ours, paid, confirmed
        let nonce = hex::encode(fresh_rho());
        let dep_kp = self.deposit_key(&nonce);
        let offer: DepositOffer = hub_call(&format!("{hub}/deposit"), Some(serde_json::to_string(&DepositRequest { alice: dep_kp.x_only_public_key().0 })?))?;
        let dep = Deposit { nonce: nonce.clone(), cid: offer.cid, hub: offer.hub, timeout: offer.timeout, payout: payout.clone() };
        self.deposits.push(dep.clone());
        self.save()?;
        let dep_tree = deposit_tree(&dep_kp.x_only_public_key().0, &dep.hub, dep.timeout)?;
        let dep_spk = dep_tree.script_pubkey();
        chain.watch(&dep_spk)?;
        let amount = Wallet::deposit_amount(&ask, net);
        pay(&bitcoin::Address::from_script(&dep_spk, net.bitcoin())?, amount)?;
        let coin = self.wait_deposit(chain, &dep_spk, amount)?;

        let keys = self.contract_keys(&nonce);
        let mut alice = keys.public();
        alice.payout_spk = payout;
        let pub_of = |ks: Vec<WotsSecret>| ks.iter().map(|k| k.public()).collect::<Vec<_>>();
        let moves: Vec<_> = (1..=m).filter(|d| d % 2 == 1).map(|d| pub_of(self.move_secrets(&nonce, &program, d))).collect();
        let hops: Vec<_> = if program.schedule.jump.is_some() { (1..=lngap_ladder::tail::CHUNKS).map(|k| self.hop_secret(&nonce, k).public()).collect() } else { vec![] };
        let inputs: Vec<_> = (0..program.info.input_words).map(|j| self.input_secret(&nonce, j).public()).collect();
        let fees = self.fees(&nonce, net);
        let req = OpenRequest { alice, l2_address: self.address(), deposit, bits, reserve, moves: moves.clone(), inputs: inputs.clone(), hops: hops.clone(), cid: dep.cid, deposit_coin: coin.clone(), fee_spk: fees.spk() };
        let offer: OpenOffer = hub_call(&format!("{hub}/open"), Some(serde_json::to_string(&req)?))?;
        // the contract as the offer makes it, checked before signing
        ensure!(offer.cid == dep.cid, "the offer is for contract {}, the deposit for {}", offer.cid, dep.cid);
        let t = terms(offer.cid, &req, offer.t_close, offer.reserve_hub)?;
        ensure!(offer.t_close > chain.height()?, "T_close is past");
        let mut record = Record {
            statement: statement.id().to_string(),
            network: net,
            deployment: d.id(),
            terms: t,
            pubs: [req.alice.clone(), offer.hub.clone()],
            moves: all_moves(&moves, &offer.moves),
            inputs,
            tail: tail_keys(&program, &offer.path, &hops)?,
            l2_address: self.address(),
            funding: bitcoin::OutPoint { txid: offer.funding.compute_txid(), vout: 0 },
            hub_sigs: offer.hub_sigs.clone(),
            alice_sigs: Default::default(),
        };
        let c = record.contract(statement, &program)?;
        let fee_out = bitcoin::TxOut { value: fee_budget_of(coin.1.value, &t)?, script_pubkey: fees.spk() };
        check_deposit_funding(&offer.funding, &c, &coin.0, &fee_out)?;
        let set = c.presign(record.funding)?;
        for p in &set {
            for i in 0..p.inputs() {
                let n = lngap_sessions::contract::sig_name(&p.name, i);
                let s = record.hub_sigs.get(&n).with_context(|| format!("the hub didn't sign {n}"))?;
                p.verify_input(&record.pubs[1].payment, i, s)?;
            }
        }
        record.alice_sigs = sign_all(&set, &keys.payment)?;
        // our signature on the funding's deposit input (taproot signs every
        // input's prevout: ours and the hub's coins)
        let known: Vec<(bitcoin::OutPoint, bitcoin::TxOut)> = std::iter::once(coin.clone()).chain(offer.hub_coins.iter().cloned()).collect();
        let prevouts: Vec<bitcoin::TxOut> = offer.funding.input.iter().map(|i| known.iter().find(|k| k.0 == i.previous_output).map(|k| k.1.clone()).context("an input of the funding not offered")).collect::<Result<_>>()?;
        let dep_in = offer.funding.input.iter().position(|i| i.previous_output == coin.0).context("the deposit input")?;
        let deposit_sig = lngap_btc::sighash::sign_tapscript(&dep_kp, &offer.funding, dep_in, &prevouts, &dep_tree.leaf(DEPOSIT_OPEN)?.script)?.as_ref().to_vec();
        chain.watch(&fees.spk())?;
        let accept = Accept { cid: offer.cid, alice_sigs: record.alice_sigs.clone(), deposit_sig };
        let _: Opened = hub_call(&format!("{hub}/accept"), Some(serde_json::to_string(&accept)?))?;
        let held = Held { nonce, record, closed: None, claim: None, payout: None };
        self.contracts.push(held.clone());
        self.deposits.retain(|x| x.cid != dep.cid);
        self.save()?;
        Ok(held)
    }

    /// Send what is left of contract `cid`'s fee budget to its payout
    /// address, less `fee`. Only once the contract is closed (a dispute
    /// may still need it), unless `force`.
    pub fn sweep_fees(&self, chain: &Chain, cid: u32, fee: bitcoin::Amount, force: bool) -> Result<bitcoin::Txid> {
        use lichen_chain::Fees;
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        ensure!(force || h.closed.is_some(), "contract {cid} is open: its fee budget may still be needed (force to sweep anyway)");
        let fees = self.fees(&h.nonce, h.record.network);
        let coins = chain.coins_of(&fees.spk())?;
        ensure!(!coins.is_empty(), "contract {cid}'s fee budget is empty");
        let total: bitcoin::Amount = coins.iter().map(|c| c.1.value).sum();
        let ins: Vec<(bitcoin::OutPoint, bitcoin::Sequence)> = coins.iter().map(|c| (c.0, bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME)).collect();
        let out = bitcoin::TxOut { value: total.checked_sub(fee).context("the budget can't pay the fee")?, script_pubkey: h.record.pubs[0].payout_spk.clone() };
        let tx = lngap_btc::tx::build_tx(&ins, vec![out], bitcoin::absolute::LockTime::ZERO);
        let prevouts: Vec<_> = coins.into_iter().map(|c| (c.0, c.1)).collect();
        let tx = fees.sign(chain, &tx, &prevouts)?;
        chain.broadcast(&tx).context("the sweep of the fee budget")
    }

    /// Wait for a confirmed coin of at least `amount` to `spk` (a deposit).
    fn wait_deposit(&self, chain: &Chain, spk: &bitcoin::Script, amount: bitcoin::Amount) -> Result<(bitcoin::OutPoint, bitcoin::TxOut)> {
        let mut stall = lichen_chain::Stall::new(chain.height()?, chain.network);
        loop {
            if let Some(c) = chain.coins_of(spk)?.into_iter().find(|c| c.2.is_some() && c.1.value >= amount) {
                return Ok((c.0, c.1));
            }
            ensure!(!stall.stalled(chain.height()?), "the chain stalled before the deposit confirmed");
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
    }

    /// Take back the deposit for contract `cid`, never opened, once its
    /// timeout has passed: to the payout address given, less `fee`.
    pub fn refund(&mut self, chain: &Chain, cid: u32, fee: bitcoin::Amount) -> Result<bitcoin::Txid> {
        let dep = self.deposits.iter().find(|x| x.cid == cid).cloned().with_context(|| format!("no deposit for contract {cid}"))?;
        let kp = self.deposit_key(&dep.nonce);
        let tree = deposit_tree(&kp.x_only_public_key().0, &dep.hub, dep.timeout)?;
        let coins = chain.coins_of(&tree.script_pubkey())?;
        let (op, out, at) = coins.into_iter().next().with_context(|| format!("the deposit for contract {cid} is not there (spent, or never paid)"))?;
        let at = at.context("the deposit is not confirmed")?;
        let ready = at + u32::from(dep.timeout) - 1;
        ensure!(chain.height()? >= ready, "the deposit can be refunded from height {ready} (now {})", chain.height()?);
        let leaf = tree.leaf(DEPOSIT_REFUND)?;
        let mut tx = lngap_btc::tx::build_spend(op, &leaf.timelock, vec![bitcoin::TxOut { value: out.value.checked_sub(fee).context("the deposit can't pay the fee")?, script_pubkey: dep.payout.clone() }]);
        let sig = lngap_btc::sighash::sign_tapscript(&kp, &tx, 0, std::slice::from_ref(&out), &leaf.script)?;
        tx.input[0].witness = lngap_btc::witness::tapscript_witness(&[sig.as_ref().to_vec()], &leaf.script, &tree.control_block(DEPOSIT_REFUND)?);
        let txid = chain.broadcast(&tx).context("the refund")?;
        self.deposits.retain(|x| x.cid != cid);
        self.save()?;
        Ok(txid)
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
        while self.sequencer.state()?.withdraw_input(index, &self.sequencer.deployment).is_err() {
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
