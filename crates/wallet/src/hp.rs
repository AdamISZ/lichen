//! The wallet's part of a contract's opening (`lichen_proto::hp`): she
//! fixes her four one-time keys, so the statement's journal, garbles for
//! the hub's statement, commits to her instances and uploads the ones the
//! hub keeps.

use anyhow::{ensure, Context, Result};
use lichen_babe::countersigned::Countersigned;
use lichen_babe::setup::{instance, par, VALUES};
use lichen_proto::setup::{dealing_to_hex, min_soundness, shares_to_hex, soundness, Opened};
use lichen_proto::hp::{check_setup, HpCommit, HpKept, HpKeys, HpOffer, HpRequest, HpSetup, HpSetupRequest};
use lichen_proto::{Net, Statement};
use lngap_sessions::contract::Presign;

use crate::engine::hp::{dealing, instance_seed};
use crate::engine::ContractSecrets;
use crate::{hub_call, Wallet};

/// What her opening request carries, and what it rests on.
pub(crate) struct HpOpening {
    pub request: HpRequest,
    pub setup: HpSetup,
    pub kept: Vec<u32>,
    /// The kept instances' hashlocks, in `kept`'s order.
    pub hmsg: Vec<[u8; 32]>,
}

impl Wallet {
    /// The setup of contract `cid`, with the deposit coin `deposit`: the
    /// hub's statement and keys checked; her instances built for it, the
    /// input secrets dealt, committed to; the ones the hub keeps uploaded,
    /// the others opened in her request.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn hp_opening(&self, hub: &str, statement: &Statement, cid: u32, deposit: bitcoin::OutPoint, unit: u64, v0: u64, s: &ContractSecrets, net: Net) -> Result<HpOpening> {
        let owner = lichen_notes::xonly(&s.l2());
        let setup: HpSetup = hub_call(&format!("{hub}/hp/setup"), Some(serde_json::to_string(&HpSetupRequest { cid, deposit, unit, owner, v0 })?), false)?;
        ensure!(setup.cid == cid && setup.unit == unit && setup.deposit == deposit && setup.owner == owner && setup.v0 == v0, "the setup is for another contract, unit, deposit, owner or mint");
        ensure!(setup.issuer == self.deployment.hub, "the setup's issuer isn't the deployment's");
        check_setup(&setup)?;
        let (n, m) = (setup.n, setup.m);
        ensure!(soundness(n, m) >= min_soundness(net), "keeping {m} of {n} instances: a cheating garbler escapes with odds of 1 in 2^{}, not 2^{}", soundness(n, m), min_soundness(net));
        let keys = s.alice_keys();
        let journal = lichen_proto::hp::contract(cid, &setup.issuer, &owner, unit, v0, &keys).journal();
        let kind = statement.hp_kind()?;
        let (vk, public) = (kind.verifying_key(), kind.public_inputs(&journal));
        let (dealer, dealt) = dealing(s, n, m);
        self.say(format!("garbling {n} instances of the hub's statement (the hub keeps {m})"));
        let start = std::time::Instant::now();
        let done = std::sync::atomic::AtomicU32::new(0);
        self.opened_step(crate::Opening::Garbling { done: 0, total: n });
        let commitments: Vec<String> = par(n as usize, |k| {
            let i = k as u32 + 1;
            let c = hex::encode(instance(&instance_seed(s, i), &dealer.shares(u64::from(i)), &vk, &public).0.commitment());
            self.opened_step(crate::Opening::Garbling { done: done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1, total: n });
            c
        });
        self.say(format!("garbled in {:.1?}", start.elapsed()));
        let commit = HpCommit { cid, keys, commitments, dealing: dealing_to_hex(&dealt) };
        let kept: HpKept = hub_call(&format!("{hub}/hp/commit"), Some(serde_json::to_string(&commit)?), false)?;
        let mut k = kept.kept.clone();
        k.sort_unstable();
        k.dedup();
        ensure!(k.len() == m as usize && k == kept.kept && k.iter().all(|i| (1..=n).contains(i)), "the hub keeps {:?}, not {m} distinct of {n}", kept.kept);
        let mut hmsg = vec![];
        for (j, i) in k.iter().enumerate() {
            let (inst, _) = instance(&instance_seed(s, *i), &dealer.shares(u64::from(*i)), &vk, &public);
            let bytes = inst.to_bytes();
            self.say(format!("uploading the instance the hub keeps, {} of {m} ({} MB)", j + 1, bytes.len() >> 20));
            // its progress told as it goes (the instances are the same size)
            let (len, total) = (bytes.len() as u64, bytes.len() as u64 * u64::from(m));
            let before = len * j as u64;
            let body = Counted { inner: std::io::Cursor::new(&bytes), sent: 0, told: 0, tell: &|sent| self.opened_step(crate::Opening::Uploading { sent: before + sent, total }) };
            lichen_l2::http::slow().post(&format!("{hub}/hp/instance/{cid}/{i}")).set("Content-Length", &len.to_string()).send(body).with_context(|| format!("uploading kept instance {i}"))?;
            self.opened_step(crate::Opening::Uploading { sent: before + len, total });
            hmsg.push(inst.hmsg);
        }
        let opened = (1..=n).filter(|i| !k.contains(i)).map(|i| Opened { i, seed: hex::encode(instance_seed(s, i)), shares: shares_to_hex(&dealer.shares(u64::from(i))) }).collect();
        Ok(HpOpening { request: HpRequest { hp_opened: opened }, setup, kept: k, hmsg })
    }

    /// The hub's offer checked against her opening: its windows the
    /// network's, its pre-signatures on `challenge_assert` (in `set`)
    /// under its adaptor keys, adapted to her dealing's points.
    pub(crate) fn hp_check_offer(net: Net, _t_close: u32, s: &ContractSecrets, o: &HpOpening, offer: &HpOffer, set: &[Presign]) -> Result<()> {
        ensure!(offer.hp_windows == lichen_proto::hp::windows(net), "the hub's windows {:?}, not the network's", offer.hp_windows);
        let (_, dealt) = dealing(s, o.setup.n, o.setup.m);
        let msg = Countersigned::link_sighash(set, "challenge_assert")?;
        let presigs: Vec<[lngap_btc::adaptor::AdaptorSig; VALUES]> = offer.hp_presigs.iter().map(|p| p.each_ref().map(lngap_btc::adaptor::AdaptorSig::from)).collect();
        ensure!(lichen_babe::reveal::check_presigs(&o.setup.adaptor, &msg, &lichen_babe::reveal::points(&dealt), &presigs), "the hub's adaptor pre-signatures on challenge_assert");
        Ok(())
    }

    /// The record's keys, the pre-signatures as given.
    pub(crate) fn hp_keys(s: &ContractSecrets, o: &HpOpening, offer: &HpOffer) -> HpKeys {
        let (windows, presigs) = (offer.hp_windows, offer.hp_presigs.clone());
        HpKeys {
            alice_keys: s.alice_keys(),
            corr_key: offer.corr_key.clone(),
            u_key: offer.u_key.clone(),
            hub_lamport: o.setup.lamport.clone(),
            hub_adaptor: o.setup.adaptor.clone(),
            n: o.setup.n,
            kept: o.kept.clone(),
            hmsg: o.hmsg.clone(),
            hp_windows: windows,
            deposit: o.setup.deposit,
            issuer: o.setup.issuer,
            v0: o.setup.v0,
            hub_presigs: presigs,
        }
    }
}

/// A body read through, its progress told every MB.
struct Counted<'a, R> {
    inner: R,
    sent: u64,
    told: u64,
    tell: &'a dyn Fn(u64),
}

impl<R: std::io::Read> std::io::Read for Counted<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let k = self.inner.read(buf)?;
        self.sent += k as u64;
        if self.sent - self.told >= 1 << 20 {
            self.told = self.sent;
            (self.tell)(self.sent);
        }
        Ok(k)
    }
}
