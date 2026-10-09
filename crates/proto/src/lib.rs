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
/// over a proof of the withdrawal guest (the real thing, 59 depths), or
/// `mock`, ln-gap's small stand-in (17 depths; for fast tests).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Statement {
    /// The program definition (yaml) of BitVMX's Groth16 verifier.
    Groth16 { pdf: PathBuf },
    Mock,
}

impl std::str::FromStr for Statement {
    type Err = anyhow::Error;
    /// `mock`, or `groth16:<path to the verifier's program definition>`.
    fn from_str(s: &str) -> Result<Statement> {
        match s.split_once(':') {
            None if s == "mock" => Ok(Statement::Mock),
            Some(("groth16", pdf)) => Ok(Statement::Groth16 { pdf: PathBuf::from(pdf) }),
            _ => bail!("a statement is `mock` or `groth16:<pdf>`"),
        }
    }
}

impl Statement {
    pub fn id(&self) -> &'static str {
        match self {
            Statement::Groth16 { .. } => "groth16",
            Statement::Mock => "mock",
        }
    }
    /// The program, built under `dir` if it must be.
    pub fn program(&self, dir: &Path) -> Result<Program> {
        match self {
            Statement::Groth16 { pdf } => Program::load(&pdf.display().to_string()),
            Statement::Mock => Program::load(&lngap_sessions::statement::write_program(&dir.join("mock-statement"), 0, &[])?),
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
            Statement::Mock => (0, vec![check("memo", 1, c)]),
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
    /// Alice's move keys, depths 1, 3, 5, ...
    pub moves: Vec<WotsPublic>,
    /// Alice's input-word keys.
    pub inputs: Vec<WotsPublic>,
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
    /// The hub's move keys, depths 2, 4, 6, ...
    pub moves: Vec<WotsPublic>,
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

/// Interleave both sides' move keys by depth (Alice moves at odd depths).
pub fn all_moves(alice: &[WotsPublic], hub: &[WotsPublic]) -> Vec<WotsPublic> {
    let m = alice.len() + hub.len();
    (1..=m).map(|d| if d % 2 == 1 { alice[(d - 1) / 2].clone() } else { hub[d / 2 - 1].clone() }).collect()
}

/// A contract as each side keeps it: enough to rebuild every transaction
/// and both parties' signatures on the pre-signed set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub statement: String,
    pub terms: Terms,
    pub pubs: [PartyPubKeys; 2],
    pub moves: Vec<WotsPublic>,
    pub inputs: Vec<WotsPublic>,
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
        Spec { terms: self.terms, cid: self.terms.id, params: params(), pubs: self.pubs.clone(), b_word, checks, moves: self.moves.clone(), inputs: self.inputs.clone() }
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
