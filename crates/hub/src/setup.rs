//! The hub's side of a contract's BABE setup (`lichen_proto::hp`): the
//! user garbles for the hub's statement, the hub keeps some of her
//! instances and checks the others, opened. The statement's terms and the
//! parties' keys for the dispute's front are the L2's ([`HubL2`]).
//!
//! Its keys as the prover (a Lamport key for π1, adaptor keys) derive from
//! its seed. Of the setup it keeps `hp/<cid>.json` (the setup, her
//! commitment, the instances kept and their hashlocks, the opened ones'
//! shares) and the kept instances, `hp/<cid>/instance-<i>.bin`.

use anyhow::{ensure, Context, Result};
use lichen_babe::reveal::{AdaptorKeys, LamportKey};
use lichen_babe::setup::{check_opened, choose, par, Hash, Instance, Secret, DIGITS, VALUES};
use lichen_btc::keys::Seed;
use lichen_proto::hp::{check_commit, HpCommit, HpKept, HpKeys, HpOffer, HpSetup, HpSetupRequest};
use lichen_proto::setup::{dealing_from_hex, shares_from_hex, Opened};
use lichen_proto::{OpenRequest, Presig, Record};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};

use crate::{HubL2, Inner};

pub(crate) fn contract_seed(seed: &str, cid: u32) -> Seed {
    Seed::from_label(&format!("{seed}/contract/{cid}/hp"))
}

/// The hub's Lamport key for π1 in contract `cid`.
pub(crate) fn hub_lamport(seed: &str, cid: u32) -> LamportKey {
    LamportKey::new(&contract_seed(seed, cid), DIGITS)
}

/// The hub's adaptor keys in contract `cid`.
pub(crate) fn hub_adaptor(seed: &str, cid: u32) -> AdaptorKeys {
    AdaptorKeys::new(&contract_seed(seed, cid), DIGITS)
}

/// What the hub keeps of a setup.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Prepared {
    pub(crate) setup: HpSetup,
    #[serde(default)]
    pub(crate) commit: Option<HpCommit>,
    #[serde(default)]
    pub(crate) kept: Vec<u32>,
    /// Each kept instance uploaded, its hashlock.
    #[serde(default, with = "lichen_babe::hexbytes::btree_fixed")]
    pub(crate) uploaded: std::collections::BTreeMap<u32, Hash>,
    /// The instances not kept, opened (at the opening).
    #[serde(default)]
    pub(crate) opened: Vec<Opened>,
}

/// The cut-and-choose on a network: `N` instances, `M` kept. BABE's
/// smallest point with secret sharing, (78, 10); regtest's tests keep 2
/// of 4.
pub fn cut_and_choose(net: lichen_proto::Net) -> (u32, u32) {
    match net {
        lichen_proto::Net::Regtest => (4, 2),
        _ => (78, 10),
    }
}

impl<L: HubL2> Inner<L> {
    pub(crate) fn hp_dir(&self, cid: u32) -> std::path::PathBuf {
        self.cfg.dir.join("hp").join(cid.to_string())
    }
    fn hp_prepared_path(&self, cid: u32) -> std::path::PathBuf {
        self.cfg.dir.join("hp").join(format!("{cid}.json"))
    }
    pub(crate) fn hp_prepared(&self, cid: u32) -> Result<Prepared> {
        Ok(serde_json::from_slice(&std::fs::read(self.hp_prepared_path(cid)).with_context(|| format!("no setup for contract {cid}"))?)?)
    }
    fn hp_save(&self, cid: u32, p: &Prepared) -> Result<()> {
        std::fs::create_dir_all(self.cfg.dir.join("hp"))?;
        Ok(lichen_proto::files::write_atomic(&self.hp_prepared_path(cid), &serde_json::to_vec(p)?)?)
    }

    /// The setup for contract `cid` (`POST /hp/setup`): the statement's
    /// terms fixed (the deposit coin paid and confirmed; the L2's), and the
    /// hub's keys as the prover. Asked again, the same.
    pub(crate) fn hp_setup(&self, req: HpSetupRequest) -> Result<HpSetup> {
        let cid = req.cid;
        ensure!(self.deposits.lock().unwrap().contains_key(&cid), "no deposit asked for contract {cid}");
        ensure!(req.unit >= 1, "a unit of 0");
        if let Ok(p) = self.hp_prepared(cid) {
            ensure!(p.setup.deposit == req.deposit && p.setup.unit == req.unit && self.l2.same_setup(&p.setup, &req), "contract {cid}'s setup is for another deposit, unit or terms");
            return Ok(p.setup);
        }
        self.check_deposit(cid, &req.deposit)?;
        let l2 = self.l2.setup_terms(self, &req)?;
        let (n, m) = cut_and_choose(self.cfg.network);
        let setup = HpSetup { cid, n, m, unit: req.unit, deposit: req.deposit, lamport: hub_lamport(&self.cfg.seed, cid).public(), adaptor: hub_adaptor(&self.cfg.seed, cid).public(), l2 };
        self.hp_save(cid, &Prepared { setup: setup.clone(), commit: None, kept: vec![], uploaded: Default::default(), opened: vec![] })?;
        Ok(setup)
    }

    /// The user's commitment to her instances (`POST /hp/commit`): the hub
    /// chooses the ones it keeps. Asked again with the same, the same.
    pub(crate) fn hp_commit(&self, c: HpCommit) -> Result<HpKept> {
        let cid = c.cid;
        let mut p = self.hp_prepared(cid)?;
        check_commit(&c, p.setup.n)?;
        self.l2.check_keys(&c.keys)?;
        dealing_from_hex(&c.dealing, (p.setup.n - p.setup.m) as usize)?;
        if let Some(old) = &p.commit {
            ensure!(old.commitments == c.commitments && old.dealing == c.dealing && old.keys == c.keys, "contract {cid}'s instances are committed already");
            return Ok(HpKept { cid, kept: p.kept });
        }
        let rng = &mut ChaCha20Rng::from_seed(lichen_proto::fresh_rho());
        p.kept = choose(p.setup.n as usize, p.setup.m as usize, rng).into_iter().map(|k| k as u32 + 1).collect();
        p.commit = Some(c);
        self.hp_save(cid, &p)?;
        Ok(HpKept { cid, kept: p.kept })
    }

    /// A kept instance, uploaded (`POST /hp/instance/<cid>/<i>`, bytes):
    /// checked against the user's commitment, and kept.
    pub(crate) fn hp_upload(&self, url: &str, bytes: &[u8]) -> Result<String> {
        let (cid, i) = url["/hp/instance/".len()..].split_once('/').context("/hp/instance/<cid>/<i>")?;
        let (cid, i): (u32, u32) = (cid.parse()?, i.parse()?);
        let mut p = self.hp_prepared(cid)?;
        let commit = p.commit.as_ref().context("no instances committed")?;
        ensure!(p.kept.contains(&i), "instance {i} is not kept");
        let inst = Instance::from_bytes(bytes).with_context(|| format!("instance {i} is no instance"))?;
        ensure!(hex::encode(inst.commitment()) == commit.commitments[i as usize - 1], "instance {i} is not the one committed");
        std::fs::create_dir_all(self.hp_dir(cid))?;
        std::fs::write(self.hp_dir(cid).join(format!("instance-{i}.bin")), bytes)?;
        p.uploaded.insert(i, inst.hmsg);
        self.hp_save(cid, &p)?;
        Ok(serde_json::json!({ "kept": i }).to_string())
    }

    /// The contract's keys from the user's opening request: every kept
    /// instance uploaded, the others opened, their shares on her dealing
    /// and each rebuilt to its commitment. The record's and the offer's
    /// (the pre-signatures to come, [`Inner::hp_presign`]); the L2's from
    /// the L2.
    pub(crate) fn hp_open_keys(&self, cid: u32, req: &OpenRequest, unit: bitcoin::Amount, t_close: u32) -> Result<(HpKeys, HpOffer)> {
        let mut p = self.hp_prepared(cid)?;
        let s = p.setup.clone();
        ensure!(s.unit == unit.to_sat() && s.deposit == req.deposit_coin.0, "the setup is for another unit or deposit than the opening's");
        let commit = p.commit.clone().context("no instances committed")?;
        let (l2_keys, l2_offer) = self.l2.open_keys(self, &s, &commit.keys, req, t_close)?;
        ensure!(p.kept.iter().all(|i| p.uploaded.contains_key(i)), "not every kept instance uploaded");
        let opened = &req.dispute.hp_opened;
        let want: Vec<u32> = (1..=s.n).filter(|i| !p.kept.contains(i)).collect();
        ensure!(opened.iter().map(|o| o.i).collect::<Vec<_>>() == want, "other instances opened than those not kept");
        let dealing = dealing_from_hex(&commit.dealing, (s.n - s.m) as usize)?;
        let shares: Vec<(u64, Vec<[Secret; VALUES]>)> = opened.iter().map(|o| Ok((u64::from(o.i), shares_from_hex(&o.shares)?))).collect::<Result<_>>()?;
        ensure!(dealing.verify(&shares, &mut ChaCha20Rng::from_seed(lichen_proto::fresh_rho())), "an opened instance's shares are off the dealing's polynomials");
        let kind = self.cfg.statement.hp_kind()?;
        let journal = self.l2.setup_journal(cid, &s, &commit.keys)?;
        let (vk, public) = (kind.verifying_key(), kind.public_inputs(&journal));
        let seeds: Vec<[u8; 32]> = opened.iter().map(|o| hex::decode(&o.seed)?.try_into().map_err(|_| anyhow::anyhow!("a seed of other than 32 bytes"))).collect::<Result<_>>()?;
        let commits: Vec<[u8; 32]> = opened.iter().map(|o| hex::decode(&commit.commitments[o.i as usize - 1])?.try_into().map_err(|_| anyhow::anyhow!("a commitment of other than 32 bytes"))).collect::<Result<_>>()?;
        let start = std::time::Instant::now();
        let ok = par(seeds.len(), |k| check_opened(&commits[k], &seeds[k], &shares[k].1, &vk, &public));
        if let Some(k) = ok.iter().position(|o| !o) {
            anyhow::bail!("opened instance {} is not the one committed", opened[k].i);
        }
        self.note(format!("contract {cid}: the user's {} opened instances checked in {:.1?}", seeds.len(), start.elapsed()));
        p.opened = opened.clone();
        self.hp_save(cid, &p)?;
        let windows = lichen_proto::hp::windows(self.cfg.network);
        let keys = HpKeys {
            hub_lamport: s.lamport,
            hub_adaptor: s.adaptor,
            n: s.n,
            kept: p.kept.clone(),
            hmsg: p.kept.iter().map(|i| p.uploaded[i]).collect(),
            hp_windows: windows,
            deposit: s.deposit,
            hub_presigs: vec![],
            l2: l2_keys,
        };
        Ok((keys, HpOffer { hp_windows: windows, hp_presigs: vec![], l2: l2_offer }))
    }

    /// The hub's adaptor pre-signatures on `challenge_assert`, adapted to
    /// the user's dealing's points, into the record and the offer.
    pub(crate) fn hp_presign(&self, record: &mut Record, offer: &mut HpOffer, set: &[lichen_contract::Presign]) -> Result<()> {
        let cid = record.cid();
        let p = self.hp_prepared(cid)?;
        let commit = p.commit.as_ref().context("no instances committed")?;
        let dealing = dealing_from_hex(&commit.dealing, (p.setup.n - p.setup.m) as usize)?;
        let msg = lichen_babe::graph::Graph::link_sighash(set, "challenge_assert")?;
        let presigs: Vec<[Presig; VALUES]> = hub_adaptor(&self.cfg.seed, cid).presign(&msg, &lichen_babe::reveal::points(&dealing)).into_iter().map(|p| p.map(Presig::from)).collect();
        record.dispute.hub_presigs = presigs.clone();
        offer.hp_presigs = presigs;
        Ok(())
    }

    /// The user's signatures on what the hub keeps its own of from her
    /// (`wrongly_challenged`): its answer needs them.
    pub(crate) fn hp_accept(&self, record: &Record) -> Result<()> {
        let built = self.built(record)?;
        for p in built.presign(record.funding)?.iter().filter(|p| built.withheld(&p.name)) {
            let s = record.alice_sigs.get(&p.name).with_context(|| format!("the user didn't sign {}", p.name))?;
            p.verify_input(&record.pubs[0].payment, 0, s).with_context(|| format!("the user's signature on {}", p.name))?;
        }
        Ok(())
    }
}
