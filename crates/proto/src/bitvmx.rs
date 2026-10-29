//! The BitVMX gadget's part of the protocol: a dispute is BitVMX's n-ary
//! search over the statement program (ln-gap's ladder), its claim the
//! program's input words under Alice's one-time keys, under a jump list a
//! tail of read and jump challenges. What a contract keeps of it
//! ([`BitVmxKeys`]), what the opening exchanges ([`BitVmxRequest`],
//! [`BitVmxOffer`]), the statement's program and input layout, and what
//! both sides' engines share in a dispute ([`Disputed`]).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use bitcoin::{Amount, Transaction, Txid};
use lngap_lamport::winternitz::WotsPublic;
use lngap_sessions::contract::{Check, Contract, Presign, Program, Spec};
pub use lngap_sessions::contract::{Site, Windows};
use serde::{Deserialize, Serialize};

use crate::{feerate, params, terminal_fee, Hash, Net, Record, Statement, IMAGE_ID, JOURNAL_LEN};

/// The BitVMX keys a contract keeps (in its [`Record`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitVmxKeys {
    /// The move keys by depth, one per field.
    pub moves: Vec<Vec<WotsPublic>>,
    pub inputs: Vec<WotsPublic>,
    /// Under a jump list: the read and jump challenges' keys.
    #[serde(default)]
    pub tail: Option<lngap_ladder::tail::TailKeys>,
    /// The dispute's windows by obligation; none for a contract made
    /// before them, which keeps the single window `δ + δ′`.
    #[serde(default)]
    pub windows: Option<Windows>,
}

/// Alice's BitVMX keys in an opening request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitVmxRequest {
    /// Her move keys, depths 1, 3, 5, ..., one per field of each move.
    pub moves: Vec<Vec<WotsPublic>>,
    /// Her input-word keys.
    pub inputs: Vec<WotsPublic>,
    /// Under a jump list: her keys for her choice of hop, one per combine
    /// of the hub's path.
    #[serde(default)]
    pub hops: Vec<WotsPublic>,
}

/// The hub's BitVMX keys and windows in an offer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitVmxOffer {
    /// The hub's move keys, depths 2, 4, 6, ..., one per field.
    pub moves: Vec<Vec<WotsPublic>>,
    /// Under a jump list: the hub's keys for its path, by chunk and field.
    #[serde(default)]
    pub path: Vec<Vec<WotsPublic>>,
    /// The dispute's windows (none from a hub from before them: the
    /// single window).
    #[serde(default)]
    pub windows: Option<Windows>,
}

impl Record {
    /// The ladder's spec of a BitVMX contract under `statement`.
    pub fn spec(&self, statement: &Statement) -> Result<Spec> {
        let k = self.bitvmx()?;
        let (b_word, checks) = statement.layout(self.terms.id, &self.deployment);
        Ok(Spec { terms: self.terms, cid: self.terms.id, params: params(self.network), pubs: self.pubs.clone(), b_word, checks, moves: k.moves.clone(), inputs: k.inputs.clone(), tail: k.tail.clone(), windows: k.windows })
    }
    /// The BitVMX contract under `statement` and its `program`.
    pub fn contract(&self, statement: &Statement, program: &Program) -> Result<Contract> {
        ensure!(statement.id() == self.statement, "the contract runs {}, not {}", self.statement, statement.id());
        Contract::new(self.spec(statement)?, program)
    }
}

/// The dispute's windows by obligation on a network, in blocks
/// (lngap-ladder's `Windows`): Alice's for each of her moves and her
/// proof, the window [`crate::params`] gives each move; the hub's for its choices,
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
    pub fn bitvmx() -> Result<Statement> {
        let dir = std::env::temp_dir().join(format!("lichen-groth16-{}", &VERIFIER_ELF_SHA256[..12]));
        std::fs::create_dir_all(&dir)?;
        if !dir.join("zkverifier.elf").exists() {
            std::fs::copy(verifier_elf()?, dir.join("zkverifier.elf"))?;
        }
        std::fs::write(dir.join("groth16.yaml"), GROTH16_PDF)?;
        Ok(Statement::BitVmx { pdf: dir.join("groth16.yaml") })
    }
    /// The program, built under `dir` if it must be.
    pub fn program(&self, dir: &Path) -> Result<Program> {
        match self {
            Statement::BitVmx { pdf } => Program::load(&pdf.display().to_string()),
            Statement::BitVmxMock { session, returns } => Program::load(&lngap_sessions::statement::write_program_with(&dir.join(format!("mock-statement-{session}")), *session, returns, 8, true)?),
            Statement::Babe { .. } => anyhow::bail!("the BABE statement has no program"),
        }
    }
    /// The program, for a BitVMX statement; none for BABE's.
    pub fn program_if(&self, dir: &Path) -> Result<Option<Program>> {
        match self {
            Statement::Babe { .. } => Ok(None),
            _ => self.program(dir).map(Some),
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
            Statement::BitVmx { .. } => {
                let id = lngap_zk::final_d60::input_words(&hex::decode(IMAGE_ID.trim()).expect("hex"));
                let dep = lngap_zk::final_d60::input_words(deployment);
                let mut checks = vec![check("journal_len", 0, (JOURNAL_LEN / 4) as u32), check("memo", 42, c)];
                checks.extend((1..9).map(|j| check(&format!("image_{j}"), j, id[j - 1])));
                checks.extend((0..8).map(|j| late(&format!("deployment_{}", j + 1), 43 + j, dep[j])));
                (41, checks)
            }
            Statement::BitVmxMock { .. } | Statement::Babe { .. } => (0, vec![check("memo", 1, c)]),
        }
    }
    /// Whether the program accepts `input`, answered natively when that is
    /// cheap: the Groth16 verifier's check in milliseconds instead of its
    /// 478M-step emulation (`None` for the mock: its emulation is quick).
    /// The emulation stays the authority whenever the trace matters.
    pub fn accepts(&self, input: &[u8]) -> Option<bool> {
        match self {
            Statement::BitVmx { .. } => Some(lngap_zk::groth16::verify_input(input).is_ok()),
            Statement::BitVmxMock { .. } | Statement::Babe { .. } => None,
        }
    }
    /// The input a claim of `b` with memo `c` runs the program on: for the
    /// mock, `(b, c)`; for Groth16 it is the verifier's input for a proof
    /// (made elsewhere).
    pub fn mock_input(&self, b: u32, c: u32) -> Option<Vec<u8>> {
        match self {
            Statement::BitVmxMock { .. } => Some(lngap_sessions::statement::input(b, c)),
            Statement::BitVmx { .. } | Statement::Babe { .. } => None,
        }
    }
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


/// The keys of an opening request beyond its move keys (which the
/// contract checks): one input-word key per word of the statement's input
/// and one hop key per tail chunk, each of the parameters the scripts are
/// built for.
pub fn check_request_keys(program: &Program, req: &BitVmxRequest) -> Result<()> {
    let wants = |k: &lngap_lamport::winternitz::WotsPublic, p: lngap_lamport::winternitz::WotsParams| k.params == p && k.digits.len() == p.total_digits() as usize;
    ensure!(req.inputs.len() == program.info.input_words, "{} input-word keys for {} words", req.inputs.len(), program.info.input_words);
    ensure!(req.inputs.iter().all(|k| wants(k, lngap_zk::final_d60::input_key_params())), "an input-word key of other parameters");
    ensure!(req.hops.iter().all(|k| wants(k, lngap_lamport::winternitz::WotsParams::for_bytes(1))), "a hop key of other parameters");
    Ok(())
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
        let built = record.build(statement, Some(&program))?;
        let set = record.presigned(&built)?.into_iter().map(|p| (p.name.clone(), p)).collect();
        let crate::Built::BitVmx(contract) = built else { anyhow::bail!("contract {} is not a BitVMX contract", record.cid()) };
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

