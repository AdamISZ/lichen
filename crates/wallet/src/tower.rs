//! A turnkey tower (docs/TOWER_PLAN.md): Alice's dispute played from a
//! package her wallet exports once the hub has refused a withdrawal, on a
//! machine of hers that holds nothing else of hers. The package carries the
//! contract and this contract's one-time secrets, never the wallet's key:
//! not the key of `b`'s word (her signature on `b` instead, so the tower
//! can't claim another amount), nor her payment key, which sweeps what she
//! wins (each link goes at its floor until anchors get a key of their own).
//! The tower stops at the payout; the wallet sweeps it
//! ([`crate::Wallet::sweep_dispute`]).
//!
//! Under BABE the package holds none of her keys, only signatures: on `b`
//! and on π1 (the claim's proof, made before the export), and, in the
//! contract, on `wrongly_challenged` (made at the opening, kept from the
//! hub). Her answer to a challenge is a kept instance's `msg`, which takes
//! the instances (beside the package, in its work directory) and the
//! chain, no key. At worst a tower stays silent.

use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{SecretKey, SECP256K1};
use bitcoin::Txid;
use lichen_babe::graph::Babe;
use lichen_babe::reveal::Preimage;
use lichen_babe::setup::digits;
use lichen_chain::{Chain, KeyFees, Net};
use lichen_proto::{Gadget, Record, Statement};
use lngap_ladder::script::wots_wire;
use lngap_lamport::winternitz::{WotsParams, WotsSecret};
use lngap_sessions::contract::Program;
use lngap_zk::final_d60::{input_key_params, input_message};
use serde::{Deserialize, Serialize};

use crate::engine::{Engine, Options, Outcome, Signer, Store};
use crate::Wallet;

/// The package's format.
pub const VERSION: u32 = 1;

/// What a tower needs to play one contract's dispute.
#[derive(Clone, Serialize, Deserialize)]
pub struct Package {
    pub version: u32,
    /// The sequencer (the return's note, its path and the signed root, for
    /// a tower that proves), asked only for what isn't packed below.
    pub sequencer: String,
    /// The contract.
    pub record: Record,
    /// The withdrawal: its amount, and the note returning it to the hub.
    pub b: u32,
    pub note: u32,
    /// Her signature on `b`, hex: under BitVMX its input word's, as a
    /// witness wire; under BABE as `request` takes it.
    pub b_wire: Vec<String>,
    /// The entropy of her key for each input word, hex; none for `b`'s.
    pub inputs: Vec<Option<String>>,
    /// The entropy of her move keys, by depth and field, hex (empty at the
    /// hub's depths).
    pub moves: Vec<Vec<String>>,
    /// The entropy of her keys for her choice of hop, by chunk count - 1.
    pub hops: Vec<String>,
    /// The fee budget's secret key, hex.
    pub fee_key: String,
    /// The claim's input (the statement program's), hex, when made before
    /// export; else the tower builds the mock's, or proves.
    #[serde(default)]
    pub claim: Option<String>,
    /// The withdrawal statement's input and the chain receipt at its
    /// height (hex), as the wallet kept them: a tower that has them needs
    /// nothing from the sequencer.
    #[serde(default)]
    pub input: Option<lichen_ledger::WithdrawInput>,
    #[serde(default)]
    pub chain: Option<String>,
    /// In an anchored deployment, the anchor the input is under (with the
    /// height whose chain receipt first carries it).
    #[serde(default)]
    pub anchor: Option<lichen_ledger::Anchored>,
    /// Under BABE, her Lamport signature on π1 (the claim's): a preimage
    /// a digit, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pi1: Option<Vec<String>>,
}

fn entropy(h: &str) -> Result<[u8; 32]> {
    hex::decode(h)?.try_into().ok().context("an entropy is 32 bytes")
}

impl Package {
    pub fn network(&self) -> Net {
        self.record.network
    }
    pub fn cid(&self) -> u32 {
        self.record.cid()
    }
    pub fn load(path: &Path) -> Result<Package> {
        let p: Package = serde_json::from_slice(&std::fs::read(path).with_context(|| format!("{}", path.display()))?).context("a tower's package")?;
        ensure!(p.version == VERSION, "a package of version {}, this tower reads {VERSION}", p.version);
        Ok(p)
    }
}

/// The work directory of the package at `package` (under BABE, the kept
/// instances go there, [`Wallet::export_instances`]).
pub fn work_dir(package: &Path) -> PathBuf {
    package.with_extension("d")
}

/// The withdrawal statement's input for the package's return: as packed,
/// or from the sequencer's public state (the note, its path, the signed
/// root). Checked against the contract (its deployment, the note's memo
/// and amount).
pub fn withdraw_input(p: &Package) -> Result<lichen_ledger::WithdrawInput> {
    Ok(withdrawal(p)?.0)
}

/// The input and, in an anchored deployment, its anchor: as packed, or
/// from the sequencer.
fn withdrawal(p: &Package) -> Result<(lichen_ledger::WithdrawInput, Option<lichen_ledger::Anchored>)> {
    let (input, anchor) = match &p.input {
        Some(i) => (i.clone(), p.anchor),
        None => {
            let seq = lichen_l2::Client::new(&p.sequencer)?;
            let state = seq.state()?;
            match p.record.checkpoint {
                Some(_) => state.anchored_input(p.note, &seq.deployment).map(|(i, a)| (i, Some(a)))?,
                None => (state.withdraw_input(p.note, &seq.deployment)?, None),
            }
        }
    };
    let d = lichen_ledger::deployment_id(&input.sequencer, &input.hub);
    let ours = match (p.record.checkpoint, anchor) {
        (Some(c), Some(a)) => lichen_ledger::lichen_withdraw_contract_id(&d, &a.anchor.genesis, c.work()),
        (None, None) => d,
        _ => anyhow::bail!("an anchored contract's input needs its anchor"),
    };
    ensure!(ours == p.record.deployment, "the input is in another deployment than the contract's");
    ensure!(input.index == p.note && input.note.memo == p.cid() && input.note.value == u64::from(p.b), "note {} is not a return of {} with memo {}", p.note, p.b, p.cid());
    Ok((input, anchor))
}

/// Prove the package's withdrawal and wrap the proof: the statement's
/// input and the chain receipt for it (as packed, or from the sequencer),
/// and in an anchored deployment the headers on the anchor's block (from
/// `chain`), then `prover claim <input.json> <chain receipt> <claim.hex>`
/// (`lichen-r0`: the STARK and the Groth16 wrap, x86 for the wrap), in
/// `work`. The claim's input, the verifier's.
pub fn prove(p: &Package, chain: &Chain, work: &Path, prover: &Path) -> Result<Vec<u8>> {
    std::fs::create_dir_all(work)?;
    let (json, receipt_file, out) = (work.join("withdraw-input.json"), work.join("chain.receipt"), work.join("claim.hex"));
    let (input, anchor) = withdrawal(p)?;
    let receipt = match &p.chain {
        Some(r) => hex::decode(r)?,
        None => crate::chain_receipt(&lichen_l2::Client::new(&p.sequencer)?, anchor.map_or(input.height, |a| a.from))?,
    };
    let full = crate::prover_input(input, anchor.as_ref(), p.record.checkpoint.as_ref(), chain)?;
    std::fs::write(&json, serde_json::to_vec_pretty(&full)?)?;
    std::fs::write(&receipt_file, receipt)?;
    let status = std::process::Command::new(prover).arg("claim").arg(&json).arg(&receipt_file).arg(&out).status().with_context(|| format!("running the prover {}", prover.display()))?;
    ensure!(status.success(), "the prover {} failed: {status}", prover.display());
    Ok(hex::decode(std::fs::read_to_string(&out)?.trim())?)
}

/// The claim's input: as exported, or as made before (a resumed tower),
/// or the mock's, or proved. Under BABE, as exported: her signature on it
/// is in the package, her key isn't.
fn claim_input(p: &Package, chain: &Chain, statement: &Statement, kept: Option<&(u32, String)>, work: &Path, prover: &Path) -> Result<Vec<u8>> {
    if let Some(h) = &p.claim {
        return Ok(hex::decode(h)?);
    }
    ensure!(p.record.gadget() == Gadget::BitVmx, "a BABE package carries its claim, the proof she signed");
    if let Some((_, h)) = kept {
        return Ok(hex::decode(h)?);
    }
    if let Some(i) = statement.mock_input(p.b, p.cid()) {
        return Ok(i);
    }
    prove(p, chain, work, prover)
}

/// A package as a dispute's signer.
pub struct PackageSigner {
    p: Package,
    /// Under BitVMX, `b`'s input word.
    b_word: Option<usize>,
}

impl PackageSigner {
    pub fn new(p: Package, statement: &Statement) -> Result<PackageSigner> {
        let b_word = match p.record.gadget() {
            Gadget::BitVmx => {
                let b_word = p.record.spec(statement)?.b_word;
                ensure!(p.inputs.get(b_word).is_some_and(|e| e.is_none()), "the package must not carry b's key");
                Some(b_word)
            }
            Gadget::Babe => {
                ensure!(p.inputs.is_empty() && p.moves.is_empty() && p.hops.is_empty(), "a BABE package carries no keys");
                ensure!(p.claim.is_some() && p.pi1.is_some(), "a BABE package carries the claim and her signature on it");
                None
            }
        };
        Ok(PackageSigner { p, b_word })
    }
}

impl Signer for PackageSigner {
    fn fees(&self) -> KeyFees {
        let sk = SecretKey::from_slice(&hex::decode(&self.p.fee_key).expect("the fee key, hex")).expect("the fee key");
        KeyFees { keypair: Keypair::from_secret_key(SECP256K1, &sk), feerate: lichen_proto::feerate(self.p.network()) }
    }
    fn anchor(&self) -> Option<Keypair> {
        None
    }
    fn bitvmx(&self) -> Result<&dyn crate::engine::bitvmx::Secrets> {
        Ok(self)
    }
    fn babe(&self) -> Result<&dyn crate::engine::babe::Secrets> {
        Ok(self)
    }
}

impl crate::engine::babe::Secrets for PackageSigner {
    fn request_wire(&self, b: u32, _exit: bool) -> Result<Vec<Vec<u8>>> {
        ensure!(b == self.p.b, "the claim's b is {b}, the package's {}", self.p.b);
        self.p.b_wire.iter().map(|h| Ok(hex::decode(h)?)).collect()
    }
    fn sign_pi1(&self, digits: &[u8]) -> Result<Vec<Preimage>> {
        let pi1 = self.p.pi1.as_ref().context("no signature on π1 in the package")?;
        let lamport = &self.p.record.babe()?.lamport;
        ensure!(pi1.len() == digits.len(), "{} preimages for {} digits", pi1.len(), digits.len());
        pi1.iter()
            .zip(digits)
            .enumerate()
            .map(|(d, (h, v))| {
                let p: Preimage = hex::decode(h)?.try_into().ok().context("a preimage is 20 bytes")?;
                ensure!(lamport.read(d, &p) == Some(*v), "the package's signature on π1 is not on this proof (digit {d})");
                Ok(p)
            })
            .collect()
    }
}

impl crate::engine::bitvmx::Secrets for PackageSigner {
    fn move_secrets(&self, program: &Program, d: u32) -> Vec<WotsSecret> {
        let es = &self.p.moves[(d - 1) as usize];
        program.field_bytes(d).into_iter().zip(es).map(|(n, e)| WotsSecret::from_entropy(WotsParams::for_bytes(n), entropy(e).expect("a move key's entropy"))).collect()
    }
    fn input_wire(&self, j: usize, word: u32) -> Result<Vec<Vec<u8>>> {
        if Some(j) == self.b_word {
            ensure!(word == self.p.b, "the claim's b is {word}, the package's {}", self.p.b);
            return self.p.b_wire.iter().map(|h| Ok(hex::decode(h)?)).collect();
        }
        let e = self.p.inputs.get(j).and_then(|e| e.as_deref()).with_context(|| format!("no key for input word {j}"))?;
        Ok(wots_wire(&WotsSecret::from_entropy(input_key_params(), entropy(e)?).sign(&input_message(word))?))
    }
    fn hop_secret(&self, k: usize) -> WotsSecret {
        WotsSecret::from_entropy(WotsParams::for_bytes(1), entropy(&self.p.hops[k - 1]).expect("a hop key's entropy"))
    }
}

/// What a tower keeps, beside its package.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TowerState {
    pub claim: Option<(u32, String)>,
    pub payout: Option<Outcome>,
    pub lost: Option<Txid>,
}

/// A tower's state in its file.
pub struct StateFile {
    path: PathBuf,
    pub state: TowerState,
}

impl StateFile {
    /// The state beside `package` (`<package>.state.json`), or a fresh one.
    pub fn beside(package: &Path) -> Result<StateFile> {
        let path = package.with_extension("state.json");
        let state = if path.exists() { serde_json::from_slice(&std::fs::read(&path)?).context("a tower's state")? } else { TowerState::default() };
        Ok(StateFile { path, state })
    }
    fn save(&self) -> Result<()> {
        lichen_ledger::files::write_private(&self.path, &serde_json::to_vec_pretty(&self.state)?)?;
        Ok(())
    }
}

impl Store for StateFile {
    fn claim(&self) -> Option<(u32, String)> {
        self.state.claim.clone()
    }
    fn set_claim(&mut self, b: u32, input: &[u8]) -> Result<()> {
        self.state.claim = Some((b, hex::encode(input)));
        self.save()
    }
    fn payout(&self) -> Option<Outcome> {
        self.state.payout.clone()
    }
    fn set_payout(&mut self, outcome: &Outcome) -> Result<()> {
        self.state.payout = Some(outcome.clone());
        self.save()
    }
    fn set_lost(&mut self, txid: Txid) -> Result<()> {
        self.state.lost = Some(txid);
        self.save()
    }
}

/// Play the dispute of the package at `package` to its end (the payout,
/// for a win), its state beside it, its work in `dir`; with no claim in
/// the package, prove it first with `prover`. Resumable.
pub fn run(chain: &Chain, statement: &Statement, package: &Path, dir: &Path, prover: &Path, opts: Options) -> Result<Outcome> {
    let p = Package::load(package)?;
    ensure!(chain.network == p.network(), "the package is for {}, the chain {}", p.network(), chain.network);
    let mut store = StateFile::beside(package)?;
    if let Some(txid) = store.state.lost {
        return Ok(Outcome::Lost).inspect(|_| eprintln!("the claim lost: {txid}"));
    }
    if store.state.claim.is_none() && p.claim.is_none() && statement.mock_input(p.b, p.cid()).is_none() {
        if let Some(f) = &opts.progress {
            f(format!("proving the withdrawal of {} sats (note {}) with {}", p.b, p.note, prover.display()));
        }
    }
    let input = claim_input(&p, chain, statement, store.state.claim.as_ref(), &dir.join("proof"), prover)?;
    if p.record.gadget() == Gadget::Babe {
        let data = crate::engine::babe::data_dir(dir, p.cid());
        ensure!(data.join("opened.json").exists(), "no instances in {}: copy them there with the package", data.display());
    }
    let (record, b) = (p.record.clone(), p.b);
    let signer = PackageSigner::new(p, statement)?;
    Engine { signer: &signer, store: &mut store, opts }.run(chain, &record, statement, dir, b, &input)
}

impl Wallet {
    /// The package for a tower to play contract `cid`'s dispute: the
    /// withdrawal returned on the L2 (its note found among the wallet's
    /// returns) with its input and chain receipt as far as the wallet has
    /// them, and `claim` if made already (else the tower builds the mock's,
    /// or proves). Under BABE the claim is needed, and the package carries
    /// her signatures on it and on `b`, no key; its instances are copied
    /// beside it by [`Wallet::export_instances`]. `program` is BitVMX's.
    pub fn export_dispute(&mut self, statement: &Statement, program: Option<&Program>, cid: u32, claim: Option<&[u8]>) -> Result<Package> {
        let note = self.returned(cid).with_context(|| format!("no return to the hub with memo {cid}: return the withdrawal first"))?;
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        ensure!(h.closed.is_none(), "contract {cid} is closed");
        if h.record.gadget() == Gadget::Babe {
            return self.export_babe(statement, cid, note, claim.context("a BABE package carries the claim (her proof), signed: prove first")?);
        }
        let program = program.context("a BitVMX package needs the statement's program")?;
        // as far as the sequencer has them; what it hasn't, the tower asks for
        let input = self.withdraw_input(cid).ok();
        let chain = input.as_ref().and_then(|_| self.chain_receipt(cid).ok()).map(hex::encode);
        let anchor = self.kept(note).and_then(|k| k.anchor);
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let b = match &input {
            Some(i) => i.note.value,
            None => self.state()?.note(note).with_context(|| format!("no note {note}"))?.value,
        };
        let b = u32::try_from(b).context("b fits in a u32")?;
        let s = self.secrets(&h.nonce);
        let spec = h.record.spec(statement)?;
        let b_wire = wots_wire(&s.input_secret(spec.b_word).sign(&input_message(b))?).iter().map(hex::encode).collect();
        let inputs = (0..program.info.input_words).map(|j| (j != spec.b_word).then(|| hex::encode(s.input_entropy(j)))).collect();
        let moves = (1..=program.depths())
            .map(|d| if lngap_ladder::mover_at(d) == lngap_channel::Role::User { (0..program.field_bytes(d).len()).map(|f| hex::encode(s.move_entropy(d, f))).collect() } else { vec![] })
            .collect();
        let hops = if program.schedule.jump.is_some() { (1..=lngap_ladder::tail::CHUNKS).map(|k| hex::encode(s.hop_entropy(k))).collect() } else { vec![] };
        let fee_key = hex::encode(s.fees(h.record.network).keypair.secret_bytes());
        Ok(Package { version: VERSION, sequencer: self.sequencer.url.clone(), record: h.record.clone(), b, note, b_wire, inputs, moves, hops, fee_key, claim: claim.map(hex::encode), input, chain, anchor, pi1: None })
    }

    /// A BABE contract's package: her signatures on `b` (the return's) and
    /// on the claim's π1, the claim checked first (a proof the hub would
    /// challenge and win against is refused).
    fn export_babe(&mut self, statement: &Statement, cid: u32, note: u32, claim: &[u8]) -> Result<Package> {
        let b = u32::try_from(self.state()?.note(note).with_context(|| format!("no note {note}"))?.value).context("b fits in a u32")?;
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let proof = lichen_babe::statement::proof_from_bytes(claim).context("the claim is not a Groth16 proof")?;
        let kind = statement.babe_kind().context("not a BABE statement")?;
        ensure!(kind.verify(&h.record.babe_journal()?, &proof), "the proof doesn't verify for contract {cid}'s journal: the hub would challenge it and win");
        let s = self.secrets(&h.nonce);
        let b_wire = crate::engine::babe::return_wire(&s, b, h.record.babe()?.exit.is_some())?.iter().map(hex::encode).collect();
        let pi1 = s.babe_lamport().sign(&digits(&lichen_babe::gadget::input(&proof.a))).iter().map(hex::encode).collect();
        let fee_key = hex::encode(s.fees(h.record.network).keypair.secret_bytes());
        Ok(Package {
            version: VERSION,
            sequencer: self.sequencer.url.clone(),
            record: h.record.clone(),
            b,
            note,
            b_wire,
            inputs: vec![],
            moves: vec![],
            hops: vec![],
            fee_key,
            claim: Some(hex::encode(claim)),
            input: None,
            chain: None,
            anchor: None,
            pi1: Some(pi1),
        })
    }

    /// Under BABE, copy contract `cid`'s instances (the kept ones and the
    /// opened ones' shares, under the wallet's `dir`) to the work
    /// directory of the package at `package`, where its tower reads them;
    /// the bytes copied.
    pub fn export_instances(&self, dir: &Path, cid: u32, package: &Path) -> Result<u64> {
        let (from, to) = (crate::engine::babe::data_dir(dir, cid), crate::engine::babe::data_dir(&work_dir(package), cid));
        std::fs::create_dir_all(&to)?;
        let mut n = 0;
        for e in std::fs::read_dir(&from).with_context(|| format!("contract {cid}'s instances, {}", from.display()))? {
            let e = e?;
            n += std::fs::copy(e.path(), to.join(e.file_name()))?;
        }
        Ok(n)
    }
}
