//! What the wallet and the hub exchange to open a contract, and the record
//! each keeps of it.
//!
//! Opening (the wallet asks, the hub answers):
//! 1. [`OpenRequest`]: Alice's keys (her move keys for the odd depths, her
//!    input-word keys), her deposit `D`, cap and reserve, the coins she
//!    funds with and her change;
//! 2. [`OpenOffer`]: the contract's number (its memo `c`), `T_close`, the
//!    hub's reserve and keys, the funding transaction (unsigned) and the
//!    hub's signatures on the whole pre-signed set;
//! 3. [`Accept`]: having checked the offer and every signature in it,
//!    Alice's signatures on the set and her inputs of the funding
//!    transaction signed; the hub checks hers, signs its inputs and
//!    broadcasts. Neither side signs the funding before holding the
//!    other's pre-signed set.
//!
//! Then, once the funding confirms, the hub mints `D` to Alice's L2
//! address. Amounts are in sats.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use bitcoin::{Amount, OutPoint, Transaction, TxOut, Txid};
use lngap_channel::{ChannelParams, PartyPubKeys};
use lngap_lamport::winternitz::WotsPublic;
use lngap_sessions::contract::{Check, Contract, Presign, Program, Signed, Spec};
use lngap_sessions::session::Terms;
pub use lichen_ledger::{Deployment, Hash, JOURNAL_LEN};
use serde::{Deserialize, Serialize};

/// Each party's share of the funding transaction's fee.
pub const FEE_SHARE: Amount = Amount::from_sat(1_000);
/// On the dispute path, bits below this pay nothing (dust): `2^9` sats.
pub const LOW_BITS: u32 = 9;
/// The withdrawal guest's image id (the build committed in ln-gap,
/// `guests/withdraw.bin`).
pub const IMAGE_ID: &str = "e0cd81a7ada6a59415be2e4a4e0cea04b6a616cc0efeeb7443e49be38a90298e";

pub use lichen_chain::{Net, Patience, Stall};

/// The contracts' timing on a network, in blocks: escalating waits
/// `to_self_delay` after the funding; each move's window is δ, and the
/// prover's extra δ′. Windows leave time for a person, or a restart, at
/// the network's block time; on testnet4, whose blocks come in bursts,
/// wide in blocks so that a burst doesn't use one up.
pub fn params(net: Net) -> ChannelParams {
    let p = ChannelParams::regtest(Amount::from_sat(0));
    match net {
        Net::Regtest => p,
        // 30 s blocks: 5 min, 20 min windows
        Net::Mutinynet => ChannelParams { to_self_delay: 10, delta: 40, delta_prime: 40, deadline_margin: 20, ..p },
        // 10 min blocks: 30 min, 1 h windows
        Net::Signet => ChannelParams { to_self_delay: 3, delta: 6, delta_prime: 6, deadline_margin: 3, ..p },
        // nominally 10 min, in bursts: 6 h windows
        Net::Testnet4 => ChannelParams { to_self_delay: 6, delta: 36, delta_prime: 36, deadline_margin: 12, ..p },
    }
}

/// How long a deposit waits before Alice may take it back alone (CSV,
/// blocks from its confirmation): about a day; a hub that never funds the
/// contract costs her that wait, never the coins.
pub fn deposit_timeout(net: Net) -> u16 {
    match net {
        Net::Regtest => 20,
        Net::Mutinynet => 2_880,
        Net::Signet | Net::Testnet4 => 144,
    }
}

/// What a deposit carries beyond the contract's `D + r_A` and the funding
/// fee's share: Alice's fee budget for a dispute. Where the target
/// feerate is the links' own floor (1 sat/vB) no child is needed, and
/// the budget covers the coins terminal transactions add; above it, each
/// of her links' children pays about `vsize · (feerate − 1)` (her links
/// are ~90 kvB in the deepest Groth16 dispute).
pub fn fee_budget(net: Net) -> Amount {
    match net {
        Net::Mutinynet | Net::Signet => Amount::from_sat(20_000),
        Net::Regtest | Net::Testnet4 => Amount::from_sat(150_000),
    }
}

/// The deposit address's tree: the hub and Alice together (the funding
/// transaction spends it), or Alice alone after `timeout` blocks (her
/// refund). A NUMS key path: every spend is a script path. (With MuSig2 the
/// first leaf would be the key path, and the deposit an ordinary-looking
/// P2TR output.)
pub fn deposit_tree(alice: &bitcoin::XOnlyPublicKey, hub: &bitcoin::XOnlyPublicKey, timeout: u16) -> Result<lngap_btc::taptree::TapTree> {
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV, OP_DROP};
    use lngap_btc::taptree::Leaf;
    use lngap_btc::tx::Timelock;
    let open = bitcoin::script::Builder::new().push_x_only_key(hub).push_opcode(OP_CHECKSIGVERIFY).push_x_only_key(alice).push_opcode(OP_CHECKSIG).into_script();
    let refund = bitcoin::script::Builder::new().push_int(i64::from(timeout)).push_opcode(OP_CSV).push_opcode(OP_DROP).push_x_only_key(alice).push_opcode(OP_CHECKSIG).into_script();
    lngap_btc::taptree::TapTree::new(vec![Leaf::new(DEPOSIT_OPEN, open, Timelock::NONE), Leaf::new(DEPOSIT_REFUND, refund, Timelock { cltv: None, csv: Some(timeout) })])
}
pub const DEPOSIT_OPEN: &str = "deposit_open";
pub const DEPOSIT_REFUND: &str = "deposit_refund";

/// A contract's default life, opening to `T_close`, in blocks: a week
/// (regtest: 1,000 blocks).
pub fn default_duration(net: Net) -> u32 {
    match net {
        Net::Regtest => 1_000,
        Net::Mutinynet => 20_160,
        Net::Signet | Net::Testnet4 => 1_008,
    }
}

/// The statement the disputes run: `groth16`, BitVMX's Groth16 verifier
/// over a proof of the withdrawal guest (the real thing; its program
/// definition should ask for an 8-ary search and a jump list: 21 depths),
/// or `mock`, ln-gap's small stand-in (for fast tests; 8-ary, a jump list,
/// 7 depths): a program that accepts exactly the returns `(b, c)` in its
/// table, for one memo `session`. Both sides must build the same one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Statement {
    /// The program definition (yaml) of BitVMX's Groth16 verifier.
    Groth16 { pdf: PathBuf },
    Mock { session: u32, returns: Vec<(u32, u32)> },
}

impl std::str::FromStr for Statement {
    type Err = anyhow::Error;
    /// `mock`, `groth16` (BitVMX's verifier found in the cargo checkout:
    /// [`Statement::groth16`]) or `groth16:<path to the verifier's program
    /// definition>`.
    fn from_str(s: &str) -> Result<Statement> {
        match s.split_once(':') {
            None if s == "mock" => Ok(Statement::Mock { session: 0, returns: vec![] }),
            None if s == "groth16" => Statement::groth16(),
            Some(("groth16", pdf)) => Ok(Statement::Groth16 { pdf: PathBuf::from(pdf) }),
            _ => bail!("a statement is `mock`, `groth16` or `groth16:<pdf>`"),
        }
    }
}

/// BitVMX's Groth16 verifier ELF (FairgateLabs' `bitvmx-zk-verifier`, as
/// BitVMX-CPU ships it), by its SHA-256.
pub const VERIFIER_ELF_SHA256: &str = "2b96e192300ab938b918a860b5bdf5f72a066e0e4688fdf7efc32228d6915598";

/// The verifier's program definition: an 8-ary search with a jump list,
/// the input of [`Statement::layout`] (51 words).
pub const GROTH16_PDF: &str = "elf: zkverifier.elf\nnary_search: 8\nmax_steps: 536870912\ninput_section_name: .input\njump_list: true\ninputs:\n  - size: 204\n    owner: prover\n";

/// Where BitVMX's verifier ELF is: `LICHEN_VERIFIER_ELF`, or BitVMX-CPU's
/// cargo checkout (it is a dependency, so building lichen fetched it);
/// checked against [`VERIFIER_ELF_SHA256`].
pub fn verifier_elf() -> Result<PathBuf> {
    let found = match std::env::var_os("LICHEN_VERIFIER_ELF") {
        Some(p) => PathBuf::from(p),
        None => {
            let cargo = std::env::var_os("CARGO_HOME").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo"))).context("no CARGO_HOME or HOME")?;
            let checkouts = cargo.join("git").join("checkouts");
            let mut found = None;
            for d in std::fs::read_dir(&checkouts).with_context(|| format!("reading {}", checkouts.display()))?.flatten() {
                if !d.file_name().to_string_lossy().starts_with("bitvmx-cpu-") {
                    continue;
                }
                for rev in std::fs::read_dir(d.path())?.flatten() {
                    let elf = rev.path().join("docker-riscv32/verifier/build/zkverifier-new-mul.elf");
                    if elf.exists() {
                        found = Some(elf);
                    }
                }
            }
            found.with_context(|| format!("no BitVMX-CPU checkout with the verifier ELF under {} (set LICHEN_VERIFIER_ELF)", checkouts.display()))?
        }
    };
    let bytes = std::fs::read(&found).with_context(|| format!("reading {}", found.display()))?;
    let sha = <bitcoin::hashes::sha256::Hash as bitcoin::hashes::Hash>::hash(&bytes).to_string();
    ensure!(sha == VERIFIER_ELF_SHA256, "{}: SHA-256 {sha}, not the verifier's {VERIFIER_ELF_SHA256}", found.display());
    Ok(found)
}

impl Statement {
    /// The Groth16 statement on BitVMX's verifier ([`verifier_elf`]), its
    /// program definition written beside a copy of the ELF in the
    /// temporary directory.
    pub fn groth16() -> Result<Statement> {
        let dir = std::env::temp_dir().join(format!("lichen-groth16-{}", &VERIFIER_ELF_SHA256[..12]));
        std::fs::create_dir_all(&dir)?;
        if !dir.join("zkverifier.elf").exists() {
            std::fs::copy(verifier_elf()?, dir.join("zkverifier.elf"))?;
        }
        std::fs::write(dir.join("groth16.yaml"), GROTH16_PDF)?;
        Ok(Statement::Groth16 { pdf: dir.join("groth16.yaml") })
    }
    pub fn id(&self) -> &'static str {
        match self {
            Statement::Groth16 { .. } => "groth16",
            Statement::Mock { .. } => "mock",
        }
    }
    /// The program, built under `dir` if it must be.
    pub fn program(&self, dir: &Path) -> Result<Program> {
        match self {
            Statement::Groth16 { pdf } => Program::load(&pdf.display().to_string()),
            Statement::Mock { session, returns } => Program::load(&lngap_sessions::statement::write_program_with(&dir.join(format!("mock-statement-{session}")), *session, returns, 8, true)?),
        }
    }
    /// Where `b` is in the input, and the checks for memo `c` and the
    /// deployment (`deployment`, its id). The Groth16 verifier's input: the
    /// journal's length in words (0), the image id (1-8), the proof (9-40),
    /// the journal `b ‖ c ‖ D` (41, 42, 43-50). The escalation publishes
    /// `b` and the eleven words up to the memo; the deployment's eight go
    /// with the rest of the input (`inputs`), since the escalation's
    /// witness, with move 1's hashes, must fit Script's stack.
    pub fn layout(&self, c: u32, deployment: &Hash) -> (usize, Vec<Check>) {
        let check = |name: &str, word: usize, value: u32| Check { name: name.to_string(), word, value, in_claim: true };
        let late = |name: &str, word: usize, value: u32| Check { name: name.to_string(), word, value, in_claim: false };
        match self {
            Statement::Groth16 { .. } => {
                let id = lngap_zk::final_d60::input_words(&hex::decode(IMAGE_ID).expect("hex"));
                let dep = lngap_zk::final_d60::input_words(deployment);
                let mut checks = vec![check("journal_len", 0, (JOURNAL_LEN / 4) as u32), check("memo", 42, c)];
                checks.extend((1..9).map(|j| check(&format!("image_{j}"), j, id[j - 1])));
                checks.extend((0..8).map(|j| late(&format!("deployment_{}", j + 1), 43 + j, dep[j])));
                (41, checks)
            }
            Statement::Mock { .. } => (0, vec![check("memo", 1, c)]),
        }
    }
    /// Whether the program accepts `input`, answered natively when that is
    /// cheap: the Groth16 verifier's check in milliseconds instead of its
    /// 478M-step emulation (`None` for the mock: its emulation is quick).
    /// The emulation stays the authority whenever the trace matters.
    pub fn accepts(&self, input: &[u8]) -> Option<bool> {
        match self {
            Statement::Groth16 { .. } => Some(lngap_zk::groth16::verify_input(input).is_ok()),
            Statement::Mock { .. } => None,
        }
    }
    /// The input a claim of `b` with memo `c` runs the program on: for the
    /// mock, `(b, c)`; for Groth16 it is the verifier's input for a proof
    /// (made elsewhere).
    pub fn mock_input(&self, b: u32, c: u32) -> Option<Vec<u8>> {
        match self {
            Statement::Mock { .. } => Some(lngap_sessions::statement::input(b, c)),
            Statement::Groth16 { .. } => None,
        }
    }
}

/// What the hub offers (`GET /info`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Info {
    /// The Bitcoin network; the wallet must be on the same.
    #[serde(default)]
    pub network: Net,
    /// The L2 deployment the hub is in (its sequencer's key and its own);
    /// the wallet must know the same.
    pub deployment: Deployment,
    /// The statement's id ([`Statement::id`]); the wallet must run the same.
    pub statement: String,
    /// Its depths: how many move keys a contract takes.
    pub depths: u32,
    /// The hub's reserve for a contract of cap `V_max`: `V_max` times this,
    /// in parts per million.
    pub reserve_ppm: u64,
    /// The largest cap, as bits (`V_max = 2^bits - 1` sats).
    pub max_bits: u32,
    /// Blocks from opening to `T_close`.
    pub duration: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenRequest {
    pub alice: PartyPubKeys,
    /// Where the hub mints `D` on the L2.
    pub l2_address: [u8; 32],
    pub deposit: u64,
    /// `V_max = 2^bits - 1` sats.
    pub bits: u32,
    /// Alice's reserve `r_A`.
    pub reserve: u64,
    /// Alice's move keys, depths 1, 3, 5, ..., one per field of each move.
    pub moves: Vec<Vec<WotsPublic>>,
    /// Alice's input-word keys.
    pub inputs: Vec<WotsPublic>,
    /// Under a jump list: Alice's keys for her choice of hop, one per
    /// combine of the hub's path.
    #[serde(default)]
    pub hops: Vec<WotsPublic>,
    /// The contract number the hub gave the deposit ([`DepositOffer`]).
    pub cid: u32,
    /// Alice's deposit coin (to [`deposit_tree`]), confirmed: `D + r_A`,
    /// the funding fee's share, and the rest her fee budget.
    pub deposit_coin: (OutPoint, TxOut),
    /// Where the funding transaction pays her fee budget (a key of hers).
    pub fee_spk: bitcoin::ScriptBuf,
}

/// Alice asks for a deposit address (`POST /deposit`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositRequest {
    /// Her key in the deposit's tree.
    pub alice: bitcoin::XOnlyPublicKey,
}

/// The hub's answer: the contract's number, its key in the deposit's
/// tree, the refund's timeout.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositOffer {
    pub cid: u32,
    pub hub: bitcoin::XOnlyPublicKey,
    pub timeout: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenOffer {
    /// The contract's number, its memo `c`.
    pub cid: u32,
    pub t_close: u32,
    pub reserve_hub: u64,
    pub hub: PartyPubKeys,
    /// The hub's move keys, depths 2, 4, 6, ..., one per field.
    pub moves: Vec<Vec<WotsPublic>>,
    /// Under a jump list: the hub's keys for its path, by chunk and field.
    #[serde(default)]
    pub path: Vec<Vec<WotsPublic>>,
    /// Inputs: Alice's coins, then the hub's. Outputs: the contract, then
    /// Alice's change, then the hub's.
    pub funding: Transaction,
    /// The prevouts of the hub's inputs.
    pub hub_coins: Vec<(OutPoint, TxOut)>,
    pub hub_sigs: HashMap<String, Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Accept {
    pub cid: u32,
    pub alice_sigs: HashMap<String, Vec<u8>>,
    /// Alice's signature on the funding transaction's deposit input (the
    /// `deposit_open` leaf; the hub adds its own).
    pub deposit_sig: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Opened {
    pub txid: Txid,
}

/// The cooperative close's fee, from the hub's share.
pub const FOLD_FEE: Amount = Amount::from_sat(1_000);
/// The default's fee coin, the hub's.
pub const DEFAULT_FEE: Amount = Amount::from_sat(2_000);

/// Alice asks the hub to fold contract `cid` for her return at `index`
/// (a sealed note of `b` sats to the hub with memo `cid`), with her
/// signature on the fold.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FoldRequest {
    pub cid: u32,
    pub index: u32,
    pub b: u64,
    pub alice_sig: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Folded {
    pub txid: Txid,
}

/// Interleave both sides' move keys by depth (Alice moves at odd depths).
pub fn all_moves(alice: &[Vec<WotsPublic>], hub: &[Vec<WotsPublic>]) -> Vec<Vec<WotsPublic>> {
    let m = alice.len() + hub.len();
    (1..=m).map(|d| if d % 2 == 1 { alice[(d - 1) / 2].clone() } else { hub[d / 2 - 1].clone() }).collect()
}

/// The tail's keys (a jump list's read and jump challenges), if the
/// statement has one: the hub's path keys and Alice's choices'.
pub fn tail_keys(program: &Program, path: &[Vec<WotsPublic>], hops: &[WotsPublic]) -> Result<Option<lngap_ladder::tail::TailKeys>> {
    if program.schedule.jump.is_none() {
        ensure!(path.is_empty() && hops.is_empty(), "keys for a tail the statement doesn't have");
        return Ok(None);
    }
    ensure!(path.len() == lngap_ladder::tail::CHUNKS && hops.len() == lngap_ladder::tail::CHUNKS, "the tail's keys: {} path chunks and {} choices", path.len(), hops.len());
    Ok(Some(lngap_ladder::tail::TailKeys { path: path.to_vec(), hop: hops.to_vec() }))
}

/// A link's anchor: the output whose script is the poster's anchor for
/// its payment key.
pub fn anchor_vout(tx: &Transaction, payment: &bitcoin::XOnlyPublicKey) -> Result<u32> {
    let spk = lngap_sessions::contract::anchor_tree_for(payment)?.script_pubkey();
    tx.output.iter().position(|o| o.script_pubkey == spk).map(|v| v as u32).context("the link has no anchor of this party's")
}

/// The anchor's witness in a fee child (input 0 spends the anchor), signed
/// with the poster's payment key.
pub fn sign_anchor(kp: &bitcoin::key::Keypair, child: &Transaction, prevouts: &[TxOut]) -> Result<bitcoin::Witness> {
    let tree = lngap_sessions::contract::anchor_tree_for(&kp.x_only_public_key().0)?;
    let leaf = tree.leaf("fee")?;
    let sig = lngap_btc::sighash::sign_tapscript(kp, child, 0, prevouts, &leaf.script)?;
    Ok(lngap_btc::witness::tapscript_witness(&[sig.as_ref().to_vec()], &leaf.script, &tree.control_block("fee")?))
}

/// A contract as each side keeps it: enough to rebuild every transaction
/// and both parties' signatures on the pre-signed set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub statement: String,
    /// The Bitcoin network, which fixes the contract's timing.
    #[serde(default)]
    pub network: Net,
    /// The L2 deployment's id: the claim's journal must carry it.
    pub deployment: Hash,
    pub terms: Terms,
    pub pubs: [PartyPubKeys; 2],
    /// The move keys by depth, one per field.
    pub moves: Vec<Vec<WotsPublic>>,
    pub inputs: Vec<WotsPublic>,
    /// Under a jump list: the read and jump challenges' keys.
    #[serde(default)]
    pub tail: Option<lngap_ladder::tail::TailKeys>,
    pub l2_address: [u8; 32],
    pub funding: OutPoint,
    pub hub_sigs: HashMap<String, Vec<u8>>,
    pub alice_sigs: HashMap<String, Vec<u8>>,
}

impl Record {
    pub fn cid(&self) -> u32 {
        self.terms.id
    }
    pub fn spec(&self, statement: &Statement) -> Spec {
        let (b_word, checks) = statement.layout(self.terms.id, &self.deployment);
        Spec { terms: self.terms, cid: self.terms.id, params: params(self.network), pubs: self.pubs.clone(), b_word, checks, moves: self.moves.clone(), inputs: self.inputs.clone(), tail: self.tail.clone() }
    }
    pub fn contract(&self, statement: &Statement, program: &Program) -> Result<Contract> {
        ensure!(statement.id() == self.statement, "the contract runs {}, not {}", self.statement, statement.id());
        Contract::new(self.spec(statement), program)
    }
    pub fn signed(&self) -> Signed {
        Signed { hub: self.hub_sigs.clone(), alice: self.alice_sigs.clone() }
    }
    /// The pre-signed set, both signatures checked.
    pub fn presigned(&self, c: &Contract) -> Result<Vec<Presign>> {
        let set = c.presign(self.funding)?;
        self.signed().verify(&set, &self.pubs)?;
        Ok(set)
    }
}

/// The terms of a contract opened from `req` with the hub's choices.
pub fn terms(cid: u32, req: &OpenRequest, t_close: u32, reserve_hub: u64) -> Result<Terms> {
    ensure!((10..=32).contains(&req.bits), "a cap of 2^{} sats", req.bits);
    let v_max = (1u64 << req.bits) - 1;
    ensure!(req.deposit > 0 && req.deposit <= v_max, "a deposit of {} with a cap of {v_max}", req.deposit);
    Ok(Terms {
        id: cid,
        unit: Amount::from_sat(1),
        bits: req.bits,
        low_bits: LOW_BITS,
        deposit: u32::try_from(req.deposit).context("the deposit")?,
        t_close,
        reserve_alice: Amount::from_sat(req.reserve),
        reserve_hub: Amount::from_sat(reserve_hub),
    })
}

/// What each side puts into the contract: Alice `D + r_A`, the hub
/// `V_max - D + r_H`.
pub fn contributions(t: &Terms) -> (Amount, Amount) {
    let d = Amount::from_sat(u64::from(t.deposit));
    (d + t.reserve_alice, t.v_max() - d + t.reserve_hub)
}

/// Check a funding transaction against the contract: output 0 is the
/// contract; `mine` are the checker's coins, which must all be spent, and
/// `change` its change, which must be paid in full; what it contributes is
/// exactly `want` plus its fee share.
pub fn check_funding(tx: &Transaction, c: &Contract, mine: &[(OutPoint, TxOut)], change: &TxOut, want: Amount) -> Result<()> {
    let tree = c.tree()?;
    ensure!(tx.output.first().map(|o| (o.value, &o.script_pubkey)) == Some((c.value(), &tree.script_pubkey())), "output 0 is not the contract");
    for (op, _) in mine {
        ensure!(tx.input.iter().any(|i| i.previous_output == *op), "a coin of mine is missing");
    }
    ensure!(tx.output.contains(change), "my change is missing");
    let spent: Amount = mine.iter().map(|c| c.1.value).sum();
    if spent != want + FEE_SHARE + change.value {
        bail!("I would put in {}, not {}", spent - change.value, want + FEE_SHARE);
    }
    Ok(())
}

/// Alice's check of the funding transaction offered: it spends her
/// deposit, its output 0 is the contract, and it pays her fee budget
/// `fee` (the rest of the deposit). The hub's coins are its business.
pub fn check_deposit_funding(tx: &Transaction, c: &Contract, deposit: &OutPoint, fee: &TxOut) -> Result<()> {
    let tree = c.tree()?;
    ensure!(tx.output.first().map(|o| (o.value, &o.script_pubkey)) == Some((c.value(), &tree.script_pubkey())), "output 0 is not the contract");
    ensure!(tx.input.iter().any(|i| i.previous_output == *deposit), "my deposit is not spent");
    ensure!(tx.output.contains(fee), "my fee budget is missing");
    Ok(())
}

/// The fee budget a deposit leaves: what it holds beyond `D + r_A` and the
/// funding fee's share.
pub fn fee_budget_of(deposit: Amount, t: &Terms) -> Result<Amount> {
    deposit.checked_sub(contributions(t).0 + FEE_SHARE).context("the deposit doesn't cover the deposit, the reserve and the funding fee")
}

// ----- disputes: what both sides' engines share -----

/// The feerate the parties aim for on a dispute's transactions, sat/vB:
/// the links' own floor (1) where that confirms (Mutinynet, signet: no
/// children), 2 on regtest (so the tests post children) and testnet4.
pub fn feerate(net: Net) -> u64 {
    match net {
        Net::Mutinynet | Net::Signet => 1,
        Net::Regtest | Net::Testnet4 => 2,
    }
}

/// The fee a terminal transaction's broadcaster adds with its coin
/// (`Chain::post_terminal`): the transaction's own size and the coin's
/// input (a key-path spend, 58 vB), at the network's feerate.
pub fn terminal_fee(tx: &Transaction, net: Net) -> Amount {
    Amount::from_sat((tx.vsize() as u64 + 60) * feerate(net))
}

/// The link that carries move `j` (`escalate` for move 1).
pub fn link_name(j: u32) -> String {
    if j == 1 { "escalate".into() } else { format!("move_{j}") }
}

/// The input bytes from its words (BitVMX reads them little-endian).
pub fn input_from_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// A contract as a dispute needs it: the contract and its pre-signed set
/// (both signatures checked), by name.
pub struct Disputed {
    pub record: Record,
    pub program: Program,
    pub contract: Contract,
    pub set: HashMap<String, Presign>,
}

impl Disputed {
    pub fn new(record: &Record, statement: &Statement, dir: &Path) -> Result<Disputed> {
        let program = statement.program(dir)?;
        let contract = record.contract(statement, &program)?;
        let set = record.presigned(&contract)?.into_iter().map(|p| (p.name.clone(), p)).collect();
        Ok(Disputed { record: record.clone(), program, contract, set })
    }
    /// A pre-signed transaction with both signatures, `wire` below them.
    pub fn finish(&self, name: &str, wire: Vec<Vec<u8>>) -> Result<Transaction> {
        let p = self.set.get(name).with_context(|| format!("no pre-signed {name}"))?;
        Ok(p.finish(wire, &self.record.hub_sigs[name], &self.record.alice_sigs[name]))
    }
    /// A pre-signed transaction of several inputs (a path's combine), each
    /// its wire and both signatures.
    pub fn finish_multi(&self, name: &str, wires: Vec<Vec<Vec<u8>>>) -> Result<Transaction> {
        let p = self.set.get(name).with_context(|| format!("no pre-signed {name}"))?;
        let n = p.inputs();
        let sigs = |m: &HashMap<String, Vec<u8>>| (0..n).map(|i| m[&lngap_sessions::contract::sig_name(name, i)].clone()).collect::<Vec<_>>();
        Ok(p.finish_multi(wires, &sigs(&self.record.hub_sigs), &sigs(&self.record.alice_sigs)))
    }
    /// The txid the set fixed for `name`.
    pub fn txid(&self, name: &str) -> Txid {
        self.set[name].tx.compute_txid()
    }
    /// The move keys of depth `d`, one per field.
    pub fn key(&self, d: u32) -> &[WotsPublic] {
        &self.contract.spec.moves[(d - 1) as usize]
    }
    /// The tail's keys (a jump list).
    pub fn tail(&self) -> Result<&lngap_ladder::tail::TailKeys> {
        self.contract.spec.tail.as_ref().context("the statement has no jump list")
    }
    /// A rule's witness, built from the chain: its own bytes `wit`, then
    /// each message's signatures as posted. `link` fetches a posted link
    /// by name; `k` is the path's combine, for the tail's rules.
    pub fn rule_wire(&self, rule: &lngap_ladder::rules::Rule, wit: &[u8], k: Option<usize>, link: &dyn Fn(&str) -> Result<Transaction>) -> Result<Vec<Vec<u8>>> {
        use lngap_ladder::script::Msg;
        use lngap_sessions::play::{move_wires, move_wires_in, word_wires};
        let words = |js: &[usize]| js.iter().map(|&j| self.contract.spec.inputs[j].clone()).collect::<Vec<_>>();
        let mut reveals = vec![];
        for msg in &rule.msgs {
            reveals.push(match *msg {
                Msg::Field(d, f) => move_wires(&link(&link_name(d))?, self.key(d))?[f].clone(),
                Msg::Word(j) => {
                    // a claim word is in the escalation, the rest in `inputs`
                    let claim = self.contract.claim_words();
                    match claim.iter().position(|x| *x == j) {
                        Some(i) => word_wires(&link("escalate")?, &words(&claim), Some(self.key(1)))?[i].clone(),
                        None => {
                            let rest = self.contract.rest_words();
                            let i = rest.iter().position(|x| *x == j).context("an input word of neither link")?;
                            word_wires(&link("inputs")?, &words(&rest), None)?[i].clone()
                        }
                    }
                }
                Msg::Path(c, f) => {
                    let k = k.context("a path's rule without its combine")?;
                    move_wires_in(&link(&format!("combine_{k}"))?, c, &self.tail()?.path[c])?[f].clone()
                }
                Msg::Hop(l) => move_wires(&link(&format!("hop_{}", l + 1))?, std::slice::from_ref(&self.tail()?.hop[l]))?[0].clone(),
            });
        }
        Ok(lngap_ladder::script::rule_wire(wit, &reveals))
    }
    /// Alice's proof of her last step's record `rec`: its name, and whether
    /// it spends on her moves as posted (the hub's check, and hers).
    pub fn proves(&self, rec: &lngap_zk::game::Record, link: &dyn Fn(&str) -> Result<Transaction>) -> Result<(String, bool)> {
        let m = self.contract.m();
        let name = format!("prove_{}", lngap_zk::guard::key_of(rec.read.opcode, rec.read.micro).context("the step's class")?);
        let rule = self.contract.rule(m, &name)?;
        let ctx = self.contract.ctx();
        let script = rule.script(bitcoin::script::Builder::new(), &|msg| self.contract.ladder_spec(&ctx).key(msg));
        let wire = self.rule_wire(&rule, &[], None, link)?;
        Ok((name, lngap_ladder::rules::spends(&script, wire).0))
    }
}

/// A move's signatures as a link carries them, given each field's: the
/// last field first (the first is verified first, on top).
pub fn move_wire(fields: &[lngap_lamport::winternitz::WotsSig]) -> Vec<Vec<u8>> {
    fields.iter().rev().flat_map(lngap_ladder::script::wots_wire).collect()
}

/// Sign a message field by field (`sizes`, in order) as a link carries it.
pub fn sign_fields(keys: &[lngap_lamport::winternitz::WotsSecret], msg: &[u8], sizes: &[usize]) -> Result<Vec<Vec<u8>>> {
    ensure!(keys.len() == sizes.len() && sizes.iter().sum::<usize>() == msg.len(), "a message of {} bytes for fields {sizes:?}", msg.len());
    let mut at = 0;
    let mut sigs = vec![];
    for (k, n) in keys.iter().zip(sizes) {
        sigs.push(k.sign(&msg[at..at + n])?);
        at += n;
    }
    Ok(move_wire(&sigs))
}

/// Sign move `d` field by field, its message split by the schedule.
pub fn sign_move(program: &Program, d: u32, keys: &[lngap_lamport::winternitz::WotsSecret], msg: &[u8]) -> Result<Vec<Vec<u8>>> {
    let sizes: Vec<usize> = program.schedule.fields(d).into_iter().map(|(_, l)| l).collect();
    sign_fields(keys, msg, &sizes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hub checks the claim natively on the input it rebuilds from the
    /// words read off the chain: that round trip keeps a valid proof valid
    /// (and a tampered one not).
    #[test]
    fn the_native_check_on_the_words_read() {
        let valid = hex::decode(include_str!("../../../../ln-gap/crates/apps/sessions/tests/data/withdraw-9-42-deployment.hex").trim()).unwrap();
        let g16 = Statement::Groth16 { pdf: PathBuf::from("unused.yaml") };
        let rebuilt = input_from_words(&lngap_zk::final_d60::input_words(&valid));
        assert_eq!(rebuilt, valid);
        assert_eq!(g16.accepts(&rebuilt), Some(true));
        let mut words = lngap_zk::final_d60::input_words(&valid);
        words[41] = 10;
        assert_eq!(g16.accepts(&input_from_words(&words)), Some(false), "b tampered");
        assert_eq!(Statement::Mock { session: 0, returns: vec![] }.accepts(&valid), None);
    }

    /// `groth16` alone finds the verifier, and its program definition's
    /// input is the layout's: the journal's length, the image id, the proof,
    /// the journal.
    #[test]
    fn the_groth16_statement_found() {
        assert!(GROTH16_PDF.contains(&format!("size: {}", 4 + 32 + 128 + JOURNAL_LEN)));
        let Statement::Groth16 { pdf } = "groth16".parse::<Statement>().unwrap() else { panic!("not groth16") };
        assert!(pdf.exists() && pdf.with_file_name("zkverifier.elf").exists());
        for n in ["regtest", "mutinynet", "signet", "testnet4"] {
            assert_eq!(n.parse::<Net>().unwrap().to_string(), n);
        }
        // the windows are in blocks: wider where blocks come faster or in bursts
        assert!(params(Net::Mutinynet).delta > params(Net::Signet).delta);
        assert!(params(Net::Testnet4).delta > params(Net::Signet).delta);
    }

    /// The Groth16 layout checks the journal `b ‖ c ‖ D`: a claim in this
    /// contract's deployment passes every check, one in another fails the
    /// deployment's words.
    #[test]
    fn the_groth16_layout_pins_the_deployment() {
        let g16 = Statement::Groth16 { pdf: PathBuf::from("unused.yaml") };
        let (ours, theirs) = (Deployment::toy(), Deployment { sequencer: [1; 32], hub: [2; 32] });
        let (b_word, checks) = g16.layout(42, &ours.id());
        assert_eq!(b_word, 41);
        assert_eq!(checks.len(), 1 + 8 + 1 + 8, "the journal's length, the image id, the memo, the deployment");
        let claim = |d: &Deployment| {
            let mut w = vec![(JOURNAL_LEN / 4) as u32];
            w.extend(lngap_zk::final_d60::input_words(&hex::decode(IMAGE_ID).unwrap()));
            w.extend([0; 32]); // the proof
            w.extend([9, 42]);
            w.extend(lngap_zk::final_d60::input_words(&d.id()));
            w
        };
        let failing = |w: &[u32]| checks.iter().filter(|c| w[c.word] != c.value).map(|c| c.name.clone()).collect::<Vec<_>>();
        assert_eq!(claim(&ours).len(), 51);
        assert!(failing(&claim(&ours)).is_empty());
        assert_eq!(failing(&claim(&theirs)), (1..=8).map(|j| format!("deployment_{j}")).collect::<Vec<_>>());
        // the real claim (the canonical guest's proof of the toy
        // deployment's return of 9, memo 42) passes every check
        let real = hex::decode(include_str!("../../../../ln-gap/crates/apps/sessions/tests/data/withdraw-9-42-deployment.hex").trim()).unwrap();
        let words = lngap_zk::final_d60::input_words(&real);
        assert_eq!(words.len(), 51);
        assert!(failing(&words).is_empty(), "{:?}", failing(&words));
        assert_eq!(words[b_word], 9);
        assert_eq!(g16.accepts(&real), Some(true));
    }
}
