//! A turnkey tower (docs/TOWER_PLAN.md): Alice's dispute played from a
//! package her wallet exports once the hub has refused a withdrawal, on a
//! machine of hers that holds nothing else of hers. The package carries the
//! contract and this contract's one-time secrets, never the wallet's key:
//! not the key of `b`'s word (her signature on `b` instead, so the tower
//! can't claim another amount), nor her payment key, which sweeps what she
//! wins (each link goes at its floor until anchors get a key of their own).
//! The tower stops at the payout; the wallet sweeps it
//! ([`crate::Wallet::sweep_dispute`]).

use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{SecretKey, SECP256K1};
use bitcoin::Txid;
use lichen_chain::{Chain, KeyFees, Net};
use lichen_proto::{Record, Statement};
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
    /// a tower that proves).
    pub sequencer: String,
    /// The contract.
    pub record: Record,
    /// The withdrawal: its amount, and the note returning it to the hub.
    pub b: u32,
    pub note: u32,
    /// Her signature on `b` (its input word's), as a witness wire, hex.
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
    /// The claim's input: as exported, or the mock's.
    pub fn input(&self, statement: &Statement) -> Result<Vec<u8>> {
        match &self.claim {
            Some(h) => Ok(hex::decode(h)?),
            None => statement.mock_input(self.b, self.cid()).context("the package has no claim (a proof's, for groth16)"),
        }
    }
}

/// A package as a dispute's signer.
pub struct PackageSigner {
    p: Package,
    b_word: usize,
}

impl PackageSigner {
    pub fn new(p: Package, statement: &Statement) -> Result<PackageSigner> {
        let b_word = p.record.spec(statement).b_word;
        ensure!(p.inputs.get(b_word).is_some_and(|e| e.is_none()), "the package must not carry b's key");
        Ok(PackageSigner { p, b_word })
    }
}

impl Signer for PackageSigner {
    fn move_secrets(&self, program: &Program, d: u32) -> Vec<WotsSecret> {
        let es = &self.p.moves[(d - 1) as usize];
        program.field_bytes(d).into_iter().zip(es).map(|(n, e)| WotsSecret::from_entropy(WotsParams::for_bytes(n), entropy(e).expect("a move key's entropy"))).collect()
    }
    fn input_wire(&self, j: usize, word: u32) -> Result<Vec<Vec<u8>>> {
        if j == self.b_word {
            ensure!(word == self.p.b, "the claim's b is {word}, the package's {}", self.p.b);
            return self.p.b_wire.iter().map(|h| Ok(hex::decode(h)?)).collect();
        }
        let e = self.p.inputs.get(j).and_then(|e| e.as_deref()).with_context(|| format!("no key for input word {j}"))?;
        Ok(wots_wire(&WotsSecret::from_entropy(input_key_params(), entropy(e)?).sign(&input_message(word))?))
    }
    fn hop_secret(&self, k: usize) -> WotsSecret {
        WotsSecret::from_entropy(WotsParams::for_bytes(1), entropy(&self.p.hops[k - 1]).expect("a hop key's entropy"))
    }
    fn fees(&self) -> KeyFees {
        let sk = SecretKey::from_slice(&hex::decode(&self.p.fee_key).expect("the fee key, hex")).expect("the fee key");
        KeyFees { keypair: Keypair::from_secret_key(SECP256K1, &sk), feerate: lichen_proto::feerate(self.p.network()) }
    }
    fn anchor(&self) -> Option<Keypair> {
        None
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
        std::fs::write(&self.path, serde_json::to_vec_pretty(&self.state)?)?;
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
/// for a win), its state beside it, its work in `dir`. Resumable.
pub fn run(chain: &Chain, statement: &Statement, package: &Path, dir: &Path, opts: Options) -> Result<Outcome> {
    let p = Package::load(package)?;
    ensure!(chain.network == p.network(), "the package is for {}, the chain {}", p.network(), chain.network);
    let input = p.input(statement)?;
    let (record, b) = (p.record.clone(), p.b);
    let signer = PackageSigner::new(p, statement)?;
    let mut store = StateFile::beside(package)?;
    if let Some(txid) = store.state.lost {
        return Ok(Outcome::Lost).inspect(|_| eprintln!("the claim lost: {txid}"));
    }
    Engine { signer: &signer, store: &mut store, opts }.run(chain, &record, statement, dir, b, &input)
}

impl Wallet {
    /// The package for a tower to play contract `cid`'s dispute: the
    /// withdrawal returned on the L2 (its note found among the wallet's
    /// returns), and `claim` if made already (else the tower builds the
    /// mock's, or proves).
    pub fn export_dispute(&self, statement: &Statement, program: &Program, cid: u32, claim: Option<&[u8]>) -> Result<Package> {
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        ensure!(h.closed.is_none(), "contract {cid} is closed");
        let &(_, note) = self.returns.iter().rev().find(|(memo, _)| *memo == cid).with_context(|| format!("no return to the hub with memo {cid}: return the withdrawal first"))?;
        let b = self.sequencer.state()?.notes.get(note as usize).with_context(|| format!("no note {note}"))?.value;
        let b = u32::try_from(b).context("b fits in a u32")?;
        let s = self.secrets(&h.nonce);
        let spec = h.record.spec(statement);
        let b_wire = wots_wire(&s.input_secret(spec.b_word).sign(&input_message(b))?).iter().map(hex::encode).collect();
        let inputs = (0..program.info.input_words).map(|j| (j != spec.b_word).then(|| hex::encode(s.input_entropy(j)))).collect();
        let moves = (1..=program.depths())
            .map(|d| if lngap_ladder::mover_at(d) == lngap_channel::Role::User { (0..program.field_bytes(d).len()).map(|f| hex::encode(s.move_entropy(d, f))).collect() } else { vec![] })
            .collect();
        let hops = if program.schedule.jump.is_some() { (1..=lngap_ladder::tail::CHUNKS).map(|k| hex::encode(s.hop_entropy(k))).collect() } else { vec![] };
        let fee_key = hex::encode(s.fees(h.record.network).keypair.secret_bytes());
        Ok(Package { version: VERSION, sequencer: self.sequencer.url.clone(), record: h.record.clone(), b, note, b_wire, inputs, moves, hops, fee_key, claim: claim.map(hex::encode) })
    }
}
