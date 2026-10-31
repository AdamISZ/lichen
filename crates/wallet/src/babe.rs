//! The wallet's part of a BABE contract's opening (`lichen_proto::babe`):
//! the setup asked for and her choice of instances, then, the offer in
//! hand and before she signs anything, the cut-and-choose checked: the
//! opened instances' shares on the dealing's polynomials and each rebuilt
//! to its hash; the kept ones downloaded, each to its hash and hashlock,
//! and kept under the wallet's directory with the opened ones' shares.
//! Then her adaptor pre-signatures on `challenge_assert`.

use std::io::Read as _;
use std::path::Path;

use anyhow::{ensure, Context, Result};
use lichen_babe::graph::Babe;
use lichen_babe::setup::{check_opened, choose, par, Instance, Secret, VALUES};
use lichen_proto::babe::{dealing_from_hex, min_soundness, shares_from_hex, soundness, windows, BabeOffer, BabeRequest, Setup, SetupRequest};
use lichen_proto::{BabeKeys, DisputeKeys, Net, Presig, Record, Statement};
use lngap_lamport::winternitz::WotsParams;
use lngap_sessions::contract::Presign;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::engine::babe::{data_dir, request_keys};
use crate::engine::ContractSecrets;
use crate::{hub_call, Wallet};

impl Wallet {
    /// Ask the hub for contract `cid`'s setup, with the exit for the
    /// deposit coin `deposit`, check its parameters, and choose the
    /// instances to keep: her opening request's keys.
    pub(crate) fn babe_request(&self, hub: &str, cid: u32, deposit: bitcoin::OutPoint, s: &ContractSecrets, net: Net) -> Result<(BabeRequest, Setup)> {
        let setup: Setup = hub_call(&format!("{hub}/babe/setup"), Some(serde_json::to_string(&SetupRequest { cid, deposit: Some(deposit) })?))?;
        ensure!(setup.cid == cid, "the setup is for contract {}, not {cid}", setup.cid);
        let x = setup.exit.as_ref().context("the hub's setup has no exit")?;
        x.check()?;
        ensure!(x.deposit == deposit, "the setup is for another deposit");
        let (n, m) = (setup.n, setup.m);
        ensure!(m >= 1 && m < n, "a cut-and-choose keeping {m} of {n}");
        ensure!(soundness(n, m) >= min_soundness(net), "keeping {m} of {n} instances: a cheating hub escapes with odds of 1 in 2^{}, not 2^{}", soundness(n, m), min_soundness(net));
        ensure!(setup.hub_b.params == WotsParams::for_bytes(4) && setup.hub_b.digits.len() == 10, "the hub's key for b is of other parameters");
        ensure!(setup.commitments.len() == n as usize, "{} commitments for {n} instances", setup.commitments.len());
        let mut rng = ChaCha20Rng::from_seed(lichen_ledger::fresh_rho());
        let kept = choose(n as usize, m as usize, &mut rng).into_iter().map(|k| k as u32 + 1).collect();
        Ok((request_keys(s, kept), setup))
    }

    /// The contract's BABE keys from her request and the hub's offer,
    /// checked against the setup.
    pub(crate) fn babe_record_keys(net: Net, t_close: u32, ours: &BabeRequest, setup: &Setup, theirs: &BabeOffer) -> Result<DisputeKeys> {
        ensure!(theirs.windows == windows(net, t_close), "the hub's windows {:?}, not the network's", theirs.windows);
        ensure!(theirs.hmsg.len() == ours.kept.len(), "{} hashlocks for {} kept instances", theirs.hmsg.len(), ours.kept.len());
        Ok(DisputeKeys::Babe(Box::new(BabeKeys {
            b_key: ours.b_key.clone(),
            hub_b: setup.hub_b.clone(),
            lamport: ours.lamport.clone(),
            adaptor: ours.adaptor.clone(),
            n: setup.n,
            kept: ours.kept.clone(),
            hmsg: theirs.hmsg.clone(),
            windows: theirs.windows,
            presigs: vec![],
            exit: match (&ours.e_key, &setup.exit) {
                (Some(e_key), Some(x)) => Some(lichen_proto::babe::BabeExit { e_key: e_key.clone(), hub: x.clone() }),
                _ => None,
            },
        })))
    }

    /// The cut-and-choose, checked before she signs: the opened instances
    /// rebuilt to their hashes, their shares on the dealing; the kept ones
    /// downloaded to their hashes and hashlocks, and kept under `dir`.
    /// Then her adaptor pre-signatures on `challenge_assert` (in `set`),
    /// into the record.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn babe_check(&self, hub: &str, dir: &Path, statement: &Statement, record: &mut Record, s: &ContractSecrets, setup: &Setup, offer: &BabeOffer, set: &[Presign]) -> Result<Vec<[Presig; VALUES]>> {
        let cid = record.cid();
        ensure!(setup.checkpoint == record.checkpoint, "the offer's checkpoint is not the setup's");
        let keys = record.babe()?.clone();
        let (n, m) = (setup.n, setup.m);
        let dealing = dealing_from_hex(&setup.dealing, (n - m) as usize)?;
        let commitment = |i: u32| -> Result<[u8; 32]> { hex::decode(&setup.commitments[i as usize - 1])?.try_into().map_err(|_| anyhow::anyhow!("a commitment of other than 32 bytes")) };
        // the opened: every instance not kept, its shares on the dealing
        let want: Vec<u32> = (1..=n).filter(|i| !keys.kept.contains(i)).collect();
        ensure!(offer.opened.iter().map(|o| o.i).collect::<Vec<_>>() == want, "the hub opened other instances than those not kept");
        let shares: Vec<(u64, Vec<[Secret; VALUES]>)> = offer.opened.iter().map(|o| Ok((u64::from(o.i), shares_from_hex(&o.shares)?))).collect::<Result<_>>()?;
        ensure!(dealing.verify(&shares, &mut ChaCha20Rng::from_seed(lichen_ledger::fresh_rho())), "an opened instance's shares are off the dealing's polynomials");
        let kind = statement.babe_kind().context("not a BABE statement")?;
        let journal = record.babe_journal()?;
        let (vk, public) = (kind.verifying_key(), kind.public_inputs(&journal));
        let seeds: Vec<[u8; 32]> = offer.opened.iter().map(|o| hex::decode(&o.seed)?.try_into().map_err(|_| anyhow::anyhow!("a seed of other than 32 bytes"))).collect::<Result<_>>()?;
        let commits: Vec<[u8; 32]> = offer.opened.iter().map(|o| commitment(o.i)).collect::<Result<_>>()?;
        let ok = par(seeds.len(), |k| check_opened(&commits[k], &seeds[k], &shares[k].1, &vk, &public));
        if let Some(k) = ok.iter().position(|o| !o) {
            anyhow::bail!("opened instance {} is not the one the hub committed to: it cheats", offer.opened[k].i);
        }
        // the kept: each as committed, its hashlock the graph's
        let data = data_dir(dir, cid);
        std::fs::create_dir_all(&data)?;
        for (k, i) in keys.kept.iter().enumerate() {
            let mut bytes = Vec::new();
            ureq::get(&format!("{hub}/babe/instance/{cid}/{i}")).call().with_context(|| format!("downloading kept instance {i}"))?.into_reader().read_to_end(&mut bytes)?;
            let inst = Instance::from_bytes(&bytes).with_context(|| format!("kept instance {i} is no instance"))?;
            ensure!(inst.commitment() == commitment(*i)?, "kept instance {i} is not the one committed");
            ensure!(inst.hmsg == keys.hmsg[k], "kept instance {i}'s hashlock is not the graph's");
            std::fs::write(data.join(format!("instance-{i}.bin")), &bytes)?;
        }
        std::fs::write(data.join("opened.json"), serde_json::to_vec(&offer.opened)?)?;
        // her pre-signatures, adapted to the dealing's points
        let msg = Babe::challenge_sighash(set)?;
        let presigs: Vec<[Presig; VALUES]> = s.babe_adaptor().presign(&msg, &lichen_babe::reveal::points(&dealing)).into_iter().map(|p| p.map(Presig::from)).collect();
        let DisputeKeys::Babe(k) = &mut record.dispute else { unreachable!("a BABE record") };
        k.presigs = presigs.clone();
        Ok(presigs)
    }

    /// Under the real BABE statement, the claim's input for contract `cid`
    /// from a RISC Zero claim (`lichen-r0 bitvmx-input`'s, or `babe-claim`'s;
    /// its bytes): its proof, checked to be the BABE guest's for the
    /// contract's journal.
    pub fn babe_claim_input(&self, cid: u32, claim: &[u8]) -> Result<Vec<u8>> {
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let journal = h.record.babe_journal()?;
        let proof = lichen_babe::statement::risc0_claim(claim, &journal)?;
        ensure!(lichen_babe::statement::Kind::Risc0.verify(&journal, &proof), "the claim's proof doesn't verify");
        Ok(lichen_babe::statement::proof_to_bytes(&proof))
    }

    /// For trials: a RISC Zero claim of another contract's journal, as a
    /// false claim's input (its proof verifies, but not for this
    /// contract's journal).
    pub fn babe_false_input(&self, claim: &[u8]) -> Result<Vec<u8>> {
        let (_, _, journal) = lngap_zk::groth16::split_input(claim)?;
        let proof = lichen_babe::statement::risc0_claim(claim, journal)?;
        Ok(lichen_babe::statement::proof_to_bytes(&proof))
    }

    /// Under the mock BABE statement, the claim's input for contract
    /// `cid`: a proof of the toy circuit for its journal.
    pub fn babe_mock_input(&self, cid: u32) -> Result<Vec<u8>> {
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        Ok(lichen_babe::statement::proof_to_bytes(&lichen_babe::statement::mock_prove(&h.record.babe_journal()?)))
    }
}
