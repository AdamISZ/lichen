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
use serde::{Deserialize, Serialize};

/// Each party's share of the funding transaction's fee.
pub const FEE_SHARE: Amount = Amount::from_sat(1_000);
/// On the dispute path, bits below this pay nothing (dust): `2^9` sats.
pub const LOW_BITS: u32 = 9;
/// The withdrawal guest's image id (the canonical build pinned in ln-gap).
pub const IMAGE_ID: &str = "4beda75466ff0db4aa6c6fe9512140368ad287c695f0ff162775db93039aa639";

/// The contracts' timing, on regtest.
pub fn params() -> ChannelParams {
    ChannelParams::regtest(Amount::from_sat(0))
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
    /// `mock`, or `groth16:<path to the verifier's program definition>`.
    fn from_str(s: &str) -> Result<Statement> {
        match s.split_once(':') {
            None if s == "mock" => Ok(Statement::Mock { session: 0, returns: vec![] }),
            Some(("groth16", pdf)) => Ok(Statement::Groth16 { pdf: PathBuf::from(pdf) }),
            _ => bail!("a statement is `mock` or `groth16:<pdf>`"),
        }
    }
}

impl Statement {
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
    /// Where `b` is in the input, and the checks for memo `c`.
    pub fn layout(&self, c: u32) -> (usize, Vec<Check>) {
        let check = |name: &str, word: usize, value: u32| Check { name: name.to_string(), word, value };
        match self {
            Statement::Groth16 { .. } => {
                let id = lngap_zk::final_d60::input_words(&hex::decode(IMAGE_ID).expect("hex"));
                let mut checks = vec![check("journal_len", 0, 2), check("memo", 42, c)];
                checks.extend((1..9).map(|j| check(&format!("image_{j}"), j, id[j - 1])));
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
    /// The coins Alice funds with, and her change.
    pub coins: Vec<(OutPoint, TxOut)>,
    pub change: TxOut,
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
    /// The funding transaction, Alice's inputs signed.
    pub funding: Transaction,
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
        let (b_word, checks) = statement.layout(self.terms.id);
        Spec { terms: self.terms, cid: self.terms.id, params: params(), pubs: self.pubs.clone(), b_word, checks, moves: self.moves.clone(), inputs: self.inputs.clone(), tail: self.tail.clone() }
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

// ----- disputes: what both sides' engines share -----

/// The feerate the parties pay on the dispute's transactions, sat/vB.
pub const FEERATE: u64 = 2;

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
        let valid = hex::decode(include_str!("../../../../ln-gap/crates/apps/sessions/tests/data/withdraw-9-42.hex").trim()).unwrap();
        let g16 = Statement::Groth16 { pdf: PathBuf::from("unused.yaml") };
        let rebuilt = input_from_words(&lngap_zk::final_d60::input_words(&valid));
        assert_eq!(rebuilt, valid);
        assert_eq!(g16.accepts(&rebuilt), Some(true));
        let mut words = lngap_zk::final_d60::input_words(&valid);
        words[41] = 10;
        assert_eq!(g16.accepts(&input_from_words(&words)), Some(false), "b tampered");
        assert_eq!(Statement::Mock { session: 0, returns: vec![] }.accepts(&valid), None);
    }
}
