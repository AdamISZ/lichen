//! What the wallet and the hub exchange to open a contract, and the record
//! each keeps of it.
//!
//! Opening (the wallet asks, the hub answers):
//! 1. [`OpenRequest`]: Alice's keys (her move keys for the odd depths, her
//!    input-word keys), her deposit `D`, cap and reserve, the coins she
//!    funds with and her change;
//! 2. [`OpenOffer`]: the contract's number (its memo `c`), `T_close`, the
//!    hub's reserve and keys, the funding transaction (unsigned), the
//!    hub's signatures on the whole pre-signed set, and `D` already minted
//!    on the L2 to the [`mint_owner`] of Alice's L2 key and an adaptor
//!    point `T` that is the funding transaction's own;
//! 3. [`Accept`]: having checked the offer, every signature in it and the
//!    mint (sealed), Alice's signatures on the set and an adaptor
//!    pre-signature on the funding's deposit input, locked to `T`; the hub
//!    completes it with `t`, signs its inputs and broadcasts, and answers
//!    with `t` ([`Opened`]). Neither side signs the funding before holding
//!    the other's pre-signed set.
//!
//! The funding and the mint are a swap: the hub can't spend the deposit
//! without completing Alice's pre-signature, and completing it puts `t`
//! in the funding's witness, which unlocks her `D` (it is in [`Opened`]
//! too; the witness is for a hub that doesn't answer). Until the deposit's
//! refund matures, nothing but the funding can spend the deposit, so the
//! hub broadcasts only well before then ([`broadcast_deadline`]). An
//! opening that never completes leaves its mint stranded: tokens no one
//! can spend, which cost the hub nothing. Amounts are in sats.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use bitcoin::secp256k1::{schnorr, Message, PublicKey, SecretKey, XOnlyPublicKey};
use bitcoin::{Amount, OutPoint, Transaction, TxOut, Txid};
use lngap_btc::adaptor::AdaptorSig;
use lngap_channel::{ChannelParams, PartyPubKeys};
use lngap_lamport::winternitz::WotsPublic;
use lngap_sessions::contract::{Check, Contract, Presign, Program, Signed, Spec};
pub use lngap_sessions::contract::{Site, Windows};
use lngap_sessions::session::Terms;
pub use lichen_ledger::{Deployment, Hash, JOURNAL_LEN};
use serde::{Deserialize, Serialize};

/// Each party's share of the funding transaction's fee.
pub const FEE_SHARE: Amount = Amount::from_sat(1_000);
/// On the dispute path, bits below this pay nothing (dust): `2^9` sats.
pub const LOW_BITS: u32 = 9;
/// The withdrawal guest's image id, hex (the build committed in
/// `r0/guests/withdraw.bin`; with the file's newline).
pub const IMAGE_ID: &str = include_str!("../../../r0/guests/withdraw.id");

pub use lichen_chain::{Net, Patience, Stall};

/// The contracts' timing on a network, in blocks: escalating waits
/// `to_self_delay` after the funding; a disprove waits δ (an equivocation
/// first). The windows are [`windows`]'; a contract made before them has
/// one window for every move, δ + δ′, and its races at the end δ′.
/// Windows leave time for a person, or a restart, at the network's block
/// time; on testnet4, whose blocks come in bursts, wide in blocks so that
/// a burst doesn't use one up.
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

/// The dispute's windows by obligation on a network, in blocks
/// (lngap-ladder's `Windows`): Alice's for each of her moves and her
/// proof, the window [`params`] gives each move; the hub's for its choices,
/// shorter (a reply of a few hundred bytes, and what users wait when the
/// hub is gone); its heavy moves' (at the final step, its path) as
/// Alice's. A hub sized for many contracts would offer longer heavy
/// windows (the paper's congestion table).
pub fn windows(net: Net) -> Windows {
    match net {
        // blocks every 150 ms in the dispute tests: distinct, so that a
        // deadline read from the wrong window shows
        Net::Regtest => Windows { user: 14, hub: 10, path: 16 },
        // 30 s blocks: 40 min, 10 min, 40 min
        Net::Mutinynet => Windows { user: 80, hub: 20, path: 80 },
        // 10 min blocks: 2 h, 1 h, 2 h
        Net::Signet => Windows { user: 12, hub: 6, path: 12 },
        // nominally 10 min, in bursts: 12 h, 3 h, 12 h
        Net::Testnet4 => Windows { user: 72, hub: 18, path: 72 },
    }
}

/// How long a deposit waits before Alice may take it back alone (CSV,
/// blocks from its confirmation): about a day; a hub that never funds the
/// contract costs her that wait, never the coins. The hub broadcasts the
/// funding only in the first half of it ([`broadcast_deadline`]); on
/// regtest, 1,000 blocks leave time to open with blocks every 150 ms (the
/// dispute tests) or every second (the demo).
pub fn deposit_timeout(net: Net) -> u16 {
    match net {
        Net::Regtest => 1_000,
        Net::Mutinynet => 2_880,
        Net::Signet | Net::Testnet4 => 144,
    }
}

/// What a deposit carries beyond the contract's `D + r_A` and the funding
/// fee's share: Alice's fee budget for a dispute. Where the target
/// feerate is the links' own floor (1 sat/vB) no child is needed, and
/// the budget covers the one terminal transaction she posts: on Groth16
/// her heaviest, a last step's proof, needs 26,793 sats at 1 sat/vB
/// ([`terminal_need`]; the wallet checks it at opening). Above the floor,
/// each of her links' children pays about `vsize · (feerate − 1)` too
/// (her links are ~90 kvB in the deepest Groth16 dispute).
pub fn fee_budget(net: Net) -> Amount {
    match net {
        Net::Mutinynet | Net::Signet => Amount::from_sat(30_000),
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
                let id = lngap_zk::final_d60::input_words(&hex::decode(IMAGE_ID.trim()).expect("hex"));
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
    /// `T`, the adaptor point of this funding transaction.
    pub mint_point: PublicKey,
    /// The note minting `D` to [`mint_owner`]`(l2_address, T)`.
    pub mint_index: u32,
    /// The dispute's windows (none from a hub from before them: the
    /// single window).
    #[serde(default)]
    pub windows: Option<Windows>,
    /// In an anchored deployment, the contract's checkpoint.
    #[serde(default)]
    pub checkpoint: Option<Checkpoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Accept {
    pub cid: u32,
    pub alice_sigs: HashMap<String, Vec<u8>>,
    /// Alice's pre-signature on the funding transaction's deposit input
    /// (the `deposit_open` leaf), locked to `T`: the hub completes it with
    /// `t` and adds its own.
    pub deposit_presig: Presig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Opened {
    pub txid: Txid,
    /// The adaptor secret, once the funding is broadcast.
    pub t: SecretKey,
}

/// An adaptor pre-signature on the wire ([`lngap_btc::adaptor::AdaptorSig`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presig {
    pub r_final: XOnlyPublicKey,
    pub r: PublicKey,
    pub s_prime: SecretKey,
}

impl From<AdaptorSig> for Presig {
    fn from(a: AdaptorSig) -> Presig {
        Presig { r_final: a.r_final, r: a.r, s_prime: a.s_prime }
    }
}

impl From<&Presig> for AdaptorSig {
    fn from(p: &Presig) -> AdaptorSig {
        AdaptorSig { r_final: p.r_final, r: p.r, s_prime: p.s_prime }
    }
}

/// Who a deposit's `D` is minted to before the funding: Alice's L2 key
/// and the funding's adaptor point ([`lichen_ledger::mint_key`]).
pub fn mint_owner(l2_address: &Hash, mint_point: &PublicKey) -> Result<Hash> {
    lichen_ledger::mint_key(l2_address, &mint_point.serialize())
}

/// The message a signature on the funding's deposit input commits to
/// (SIGHASH_DEFAULT, the `deposit_open` leaf), and that input's index.
/// `coins`: the prevouts of every input of the funding.
pub fn deposit_open_msg(funding: &Transaction, deposit: &OutPoint, coins: &[(OutPoint, TxOut)], tree: &lngap_btc::taptree::TapTree) -> Result<(usize, Message)> {
    let prevouts: Vec<TxOut> = funding.input.iter().map(|i| coins.iter().find(|k| k.0 == i.previous_output).map(|k| k.1.clone()).context("an input of the funding not offered")).collect::<Result<_>>()?;
    let dep = funding.input.iter().position(|i| i.previous_output == *deposit).context("the deposit input")?;
    Ok((dep, lngap_btc::sighash::tapscript_sighash(funding, dep, &prevouts, &tree.leaf(DEPOSIT_OPEN)?.script)?))
}

/// Alice's signature in a funding transaction's deposit input, as
/// broadcast: the first witness item (`deposit_open` pops the hub's, then
/// hers).
pub fn deposit_sig_in(funding: &Transaction, deposit: &OutPoint) -> Option<schnorr::Signature> {
    let input = funding.input.iter().find(|i| i.previous_output == *deposit)?;
    schnorr::Signature::from_slice(input.witness.nth(0)?).ok()
}

/// The last height at which the hub may broadcast a funding transaction:
/// half the refund's timeout before the refund matures, so that the
/// funding confirms (fee-bumped by the hub's change if need be) while
/// nothing else can spend the deposit. `confirmed`: the deposit's
/// confirmation height.
pub fn broadcast_deadline(confirmed: u32, timeout: u16) -> u32 {
    confirmed + u32::from(timeout) - u32::from(timeout) / 2
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

/// How many blocks' work, at the checkpoint's difficulty, a withdrawal
/// shows on top of the anchor of its root (docs/ANCHOR_PLAN.md).
pub const ANCHOR_DEPTH: u128 = 10;

/// The Bitcoin block a contract opened at, in an anchored deployment: its
/// difficulty fixes the work `W` a withdrawal shows on top of its anchor.
/// Each side checks it against its own view of the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: u32,
    pub hash: bitcoin::BlockHash,
    pub bits: u32,
}

impl Checkpoint {
    /// The checkpoint at the chain's tip.
    pub fn tip(chain: &lichen_chain::Chain) -> Result<Checkpoint> {
        let height = chain.height()?;
        let hash = chain.block_hash(height)?;
        let header = chain.header(&hash)?;
        Ok(Checkpoint { height, hash, bits: u32::from_le_bytes(header[72..76].try_into().unwrap()) })
    }
    /// `W`: [`ANCHOR_DEPTH`] blocks of its difficulty.
    pub fn work(&self) -> u128 {
        ANCHOR_DEPTH.saturating_mul(lichen_ledger::lichen_validity::btc::work(self.bits))
    }
    /// Check it against `chain`: its block on the best chain with these
    /// bits, at most `stale` blocks below the tip.
    pub fn check(&self, chain: &lichen_chain::Chain, stale: u32) -> Result<()> {
        ensure!(chain.block_hash(self.height)? == self.hash, "the checkpoint {} isn't the best chain's block {}", self.hash, self.height);
        let header = chain.header(&self.hash)?;
        ensure!(u32::from_le_bytes(header[72..76].try_into().unwrap()) == self.bits, "the checkpoint's bits aren't its block's");
        ensure!(chain.height()? <= self.height + stale, "the checkpoint, block {}, is stale", self.height);
        Ok(())
    }
}

/// Headers on top of block `from` (internal order), from the chain, until
/// their work reaches `work`: what a withdrawal shows on top of its
/// anchor. An error, saying how far it has got, if not there yet.
pub fn headers_for(chain: &lichen_chain::Chain, from: &Hash, work: u128) -> Result<Vec<[u8; 80]>> {
    use bitcoin::hashes::Hash as _;
    let block = bitcoin::BlockHash::from_byte_array(*from);
    let mut out = vec![];
    let mut sum = 0u128;
    for h in chain.headers_after(&block, 4 * ANCHOR_DEPTH as usize)? {
        sum = sum.saturating_add(lichen_ledger::lichen_validity::btc::work(u32::from_le_bytes(h[72..76].try_into().unwrap())));
        out.push(h);
        if sum >= work && !out.is_empty() {
            return Ok(out);
        }
    }
    bail!("the anchor isn't deep enough yet: {} blocks on it, {sum} of the {work} work the contract asks", out.len())
}

/// The journal's `D` a contract pins: the deployment's id, or in an
/// anchored deployment (a genesis seal) the contract's, of the genesis
/// seal and the checkpoint's `W` too.
pub fn contract_word(d: &Deployment, checkpoint: Option<&Checkpoint>) -> Result<Hash> {
    match (d.seal, checkpoint) {
        (None, None) => Ok(d.id()),
        (Some(seal), Some(c)) => Ok(lichen_ledger::lichen_withdraw_contract_id(&d.id(), &seal, c.work())),
        (Some(_), None) => bail!("an anchored deployment's contract needs a checkpoint"),
        (None, Some(_)) => bail!("a checkpoint in a deployment that doesn't anchor"),
    }
}

/// A contract as each side keeps it: enough to rebuild every transaction
/// and both parties' signatures on the pre-signed set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub statement: String,
    /// The Bitcoin network, which fixes the contract's timing.
    #[serde(default)]
    pub network: Net,
    /// The claim's journal must carry this: the L2 deployment's id, or in
    /// an anchored deployment the contract's ([`contract_word`]).
    pub deployment: Hash,
    /// In an anchored deployment, the Bitcoin block the contract opened at,
    /// which fixes the work a withdrawal shows on top of its anchor.
    #[serde(default)]
    pub checkpoint: Option<Checkpoint>,
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
    /// The dispute's windows by obligation; none for a contract made
    /// before them, which keeps the single window `δ + δ′`.
    #[serde(default)]
    pub windows: Option<Windows>,
}

impl Record {
    pub fn cid(&self) -> u32 {
        self.terms.id
    }
    pub fn spec(&self, statement: &Statement) -> Spec {
        let (b_word, checks) = statement.layout(self.terms.id, &self.deployment);
        Spec { terms: self.terms, cid: self.terms.id, params: params(self.network), pubs: self.pubs.clone(), b_word, checks, moves: self.moves.clone(), inputs: self.inputs.clone(), tail: self.tail.clone(), windows: self.windows }
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

/// What the heaviest of Alice's terminal transactions in contract `c`
/// (its pre-signed `set`) needs from her fee budget on `net`: its fee
/// ([`terminal_fee`]) and the split that makes a coin of exactly that.
/// Hers are the last step's proofs (`prove_<class>`, the heaviest: about
/// 25 kvB on Groth16) and her timeouts; each message a proof reveals is
/// sized at its full length, as the links' floors are.
pub fn terminal_need(c: &Contract, set: &[Presign], net: Net) -> Result<Amount> {
    let ctx = c.ctx();
    let spec = c.ladder_spec(&ctx);
    let full = |k: &WotsPublic| (0..k.params.total_digits()).flat_map(|_| [vec![0u8; 20], vec![15u8]]).collect::<Vec<_>>();
    let mut most = Amount::ZERO;
    for p in set.iter().filter(|p| !p.link) {
        let wire = if p.name.starts_with("prove_") {
            let rule = c.rule(c.m(), &p.name)?;
            let reveals: Vec<_> = rule.msgs.iter().map(|m| full(&spec.key(*m))).collect();
            lngap_ladder::script::rule_wire(&[], &reveals)
        } else if p.name.starts_with("timeout_") {
            vec![]
        } else {
            continue;
        };
        most = most.max(terminal_fee(&p.finish(wire, &[0; 64], &[0; 64]), net));
    }
    Ok(most + lichen_chain::KeyFees::split_cost(feerate(net)))
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

/// The canned claim's `D` (`tests/data/claim-60-42.*`, the real-receipt
/// test's): the toy deployment with the genesis seal of the regtest run
/// that made it, a contract checkpointed at regtest's difficulty.
pub fn canned_d() -> Hash {
    let d = Deployment { seal: Some(canned_seal()), ..Deployment::toy() };
    let regtest = Checkpoint { height: 0, hash: <bitcoin::BlockHash as bitcoin::hashes::Hash>::all_zeros(), bits: 0x207fffff };
    contract_word(&d, Some(&regtest)).unwrap()
}

/// The canned claim's genesis seal.
pub fn canned_seal() -> lichen_ledger::OutPoint {
    lichen_ledger::outpoint::parse(include_str!("../tests/data/claim-60-42.seal").trim()).expect("the canned claim's genesis seal")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hub checks the claim natively on the input it rebuilds from the
    /// words read off the chain: that round trip keeps a valid proof valid
    /// (and a tampered one not).
    #[test]
    fn the_native_check_on_the_words_read() {
        let valid = hex::decode(include_str!("../tests/data/claim-60-42.hex").trim()).unwrap();
        let g16 = Statement::Groth16 { pdf: PathBuf::from("unused.yaml") };
        let rebuilt = input_from_words(&lngap_zk::final_d60::input_words(&valid));
        assert_eq!(rebuilt, valid);
        assert_eq!(g16.accepts(&rebuilt), Some(true));
        let mut words = lngap_zk::final_d60::input_words(&valid);
        words[41] = 61;
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
        // the windows by obligation fit the disprove delay; Alice's moves
        // keep the window they had, the hub's choices are quicker
        for net in [Net::Regtest, Net::Mutinynet, Net::Signet, Net::Testnet4] {
            let (w, p) = (windows(net), params(net));
            w.check(p.delta, lngap_sessions::contract::POST_CSV).unwrap();
            assert!(w.user >= p.delta + p.delta_prime && w.hub < w.user, "{net:?}: {w:?}");
        }
    }

    /// The Groth16 layout checks the journal `b ‖ c ‖ D`: a claim in this
    /// contract's deployment passes every check, one in another fails the
    /// deployment's words.
    #[test]
    fn the_groth16_layout_pins_the_deployment() {
        let g16 = Statement::Groth16 { pdf: PathBuf::from("unused.yaml") };
        let (ours, theirs) = (Deployment::toy(), Deployment { sequencer: [1; 32], hub: [2; 32], seal: None });
        let (b_word, checks) = g16.layout(42, &ours.id());
        assert_eq!(b_word, 41);
        assert_eq!(checks.len(), 1 + 8 + 1 + 8, "the journal's length, the image id, the memo, the deployment");
        let claim = |d: &Deployment| {
            let mut w = vec![(JOURNAL_LEN / 4) as u32];
            w.extend(lngap_zk::final_d60::input_words(&hex::decode(IMAGE_ID.trim()).unwrap()));
            w.extend([0; 32]); // the proof
            w.extend([9, 42]);
            w.extend(lngap_zk::final_d60::input_words(&d.id()));
            w
        };
        let failing = |w: &[u32]| checks.iter().filter(|c| w[c.word] != c.value).map(|c| c.name.clone()).collect::<Vec<_>>();
        assert_eq!(claim(&ours).len(), 51);
        assert!(failing(&claim(&ours)).is_empty());
        assert_eq!(failing(&claim(&theirs)), (1..=8).map(|j| format!("deployment_{j}")).collect::<Vec<_>>());
        // the real claim (the committed guest's proof of the toy
        // deployment's return of 60, memo 42, anchored on regtest: D the
        // contract's, of the run's genesis seal and regtest's W) passes
        // every check
        let real = hex::decode(include_str!("../tests/data/claim-60-42.hex").trim()).unwrap();
        let words = lngap_zk::final_d60::input_words(&real);
        assert_eq!(words.len(), 51);
        let (_, checks) = g16.layout(42, &canned_d());
        let failing = |w: &[u32]| checks.iter().filter(|c| w[c.word] != c.value).map(|c| c.name.clone()).collect::<Vec<_>>();
        assert!(failing(&words).is_empty(), "{:?}", failing(&words));
        assert_eq!(words[b_word], 60);
        assert_eq!(g16.accepts(&real), Some(true));
    }
}
