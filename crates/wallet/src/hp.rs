//! The wallet's part of a contract's opening (`lichen_proto::hp`): she
//! fixes her keys for the dispute (the L2's), so the statement's journal,
//! garbles for the hub's statement, commits to her instances and uploads
//! the ones the hub keeps.

use anyhow::{ensure, Context, Result};
use lichen_babe::graph::Graph;
use lichen_babe::opening::{soundness, Garbler};
use lichen_babe::setup::VALUES;
use lichen_proto::setup::{dealing_to_hex, min_soundness, Opened};
use lichen_proto::hp::{check_setup, HpCommit, HpKept, HpKeys, HpOffer, HpRequest, HpSetup, HpSetupRequest};
use lichen_proto::{Hash, Net, Statement};
use lichen_contract::Presign;
use sha2::Digest;

use crate::engine::garbler;
use crate::engine::ContractSecrets;
use crate::{hub_call, Quote, SentOpening, Wallet, WalletL2};

/// What her opening request carries, and what it rests on.
pub(crate) struct HpOpening {
    pub request: HpRequest,
    pub setup: HpSetup,
    /// Her keys for the dispute (the L2's).
    pub keys: serde_json::Value,
    /// The journal's hash: her instances are garbled for it.
    pub journal: Hash,
    pub kept: Vec<u32>,
    /// The kept instances' hashlocks, in `kept`'s order.
    pub hmsg: Vec<[u8; 32]>,
    pub garbler: Garbler,
}

impl<L: WalletL2> Wallet<L> {
    /// The setup of contract `cid`, with the deposit coin `deposit`: the
    /// hub's statement and keys checked; her instances built for it, the
    /// input secrets dealt, committed to; the ones the hub keeps uploaded,
    /// the others opened in her request. `sent`, the openings sent before
    /// for this deposit: the hub must keep the same instances again for
    /// the same journal ([`check_kept`]).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn hp_opening(&self, hub: &str, chain: &lichen_chain::Chain, statement: &Statement, cid: u32, deposit: bitcoin::OutPoint, quote: &Quote, owner: &Hash, s: &ContractSecrets, sent: &[SentOpening], net: Net) -> Result<HpOpening> {
        let unit = quote.unit;
        let asked = L::setup_terms(self, cid, quote, owner)?;
        let setup: HpSetup = hub_call(&format!("{hub}/hp/setup"), Some(serde_json::to_string(&HpSetupRequest { cid, deposit, unit, l2: asked.clone() })?), false)?;
        ensure!(setup.cid == cid && setup.unit == unit && setup.deposit == deposit, "the setup is for another contract, unit or deposit");
        L::check_setup(self, chain, &setup, &asked)?;
        check_setup(&setup)?;
        let (n, m) = (setup.n, setup.m);
        ensure!(soundness(n, m) >= min_soundness(net), "keeping {m} of {n} instances: a cheating garbler escapes with odds of 1 in 2^{}, not 2^{}", soundness(n, m), min_soundness(net));
        let keys = L::alice_keys(s);
        let journal = L::setup_journal(cid, &setup, &keys)?;
        let journal_hash: Hash = sha2::Sha256::digest(&journal).into();
        let kind = statement.hp_kind()?;
        let g = garbler(s, n, m, &kind, &journal);
        self.say(format!("garbling {n} instances of the hub's statement (the hub keeps {m})"));
        let start = std::time::Instant::now();
        let done = std::sync::atomic::AtomicU32::new(0);
        self.opened_step(crate::Opening::Garbling { done: 0, total: n });
        let commitments: Vec<String> = g.commitments(|| self.opened_step(crate::Opening::Garbling { done: done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1, total: n })).iter().map(hex::encode).collect();
        self.say(format!("garbled in {:.1?}", start.elapsed()));
        let commit = HpCommit { cid, keys: keys.clone(), commitments, dealing: dealing_to_hex(g.dealing()) };
        let kept: HpKept = hub_call(&format!("{hub}/hp/commit"), Some(serde_json::to_string(&commit)?), false)?;
        let k = kept.kept;
        check_kept(sent, &journal_hash, &k)?;
        let opened = g.open(&k)?.iter().map(Opened::of).collect();
        let mut hmsg = vec![];
        for (j, i) in k.iter().enumerate() {
            let inst = g.instance(*i);
            let bytes = inst.to_bytes();
            self.say(format!("uploading the instance the hub keeps, {} of {m} ({} MB)", j + 1, bytes.len() >> 20));
            // its progress told as it goes (the instances are the same size)
            let (len, total) = (bytes.len() as u64, bytes.len() as u64 * u64::from(m));
            let before = len * j as u64;
            let body = Counted { inner: std::io::Cursor::new(&bytes), sent: 0, told: 0, tell: &|sent| self.opened_step(crate::Opening::Uploading { sent: before + sent, total }) };
            lichen_proto::http::slow().post(&format!("{hub}/hp/instance/{cid}/{i}")).set("Content-Length", &len.to_string()).send(body).with_context(|| format!("uploading kept instance {i}"))?;
            self.opened_step(crate::Opening::Uploading { sent: before + len, total });
            hmsg.push(inst.hmsg);
        }
        Ok(HpOpening { request: HpRequest { hp_opened: opened }, setup, keys, journal: journal_hash, kept: k, hmsg, garbler: g })
    }

    /// The hub's offer checked against her opening: its windows the
    /// network's, its pre-signatures on `challenge_assert` (in `set`)
    /// under its adaptor keys, adapted to her dealing's points.
    /// The hub's offer's keys: the network's windows, and its adaptor
    /// pre-signatures on `challenge_assert` (on `set`), against her
    /// dealing's points.
    pub(crate) fn hp_check_offer(net: Net, o: &HpOpening, offer: &HpOffer, set: &[Presign]) -> Result<()> {
        ensure!(offer.hp_windows == lichen_proto::hp::windows(net), "the hub's windows {:?}, not the network's", offer.hp_windows);
        let dealt = o.garbler.dealing();
        let msg = Graph::link_sighash(set, "challenge_assert")?;
        let presigs: Vec<[lichen_btc::adaptor::AdaptorSig; VALUES]> = offer.hp_presigs.iter().map(|p| p.each_ref().map(lichen_btc::adaptor::AdaptorSig::from)).collect();
        ensure!(lichen_babe::reveal::check_presigs(&o.setup.adaptor, &msg, &lichen_babe::reveal::points(dealt), &presigs), "the hub's adaptor pre-signatures on challenge_assert");
        Ok(())
    }

    /// The contract's keys: BABE's from the setup and the offer, the L2's
    /// from the L2.
    pub(crate) fn hp_keys(&self, o: &HpOpening, offer: &HpOffer, quote: &Quote) -> Result<HpKeys> {
        Ok(HpKeys {
            hub_lamport: o.setup.lamport.clone(),
            hub_adaptor: o.setup.adaptor.clone(),
            n: o.setup.n,
            kept: o.kept.clone(),
            hmsg: o.hmsg.clone(),
            hp_windows: offer.hp_windows,
            deposit: o.setup.deposit,
            hub_presigs: offer.hp_presigs.clone(),
            l2: L::record_keys(self, &o.setup, &o.keys, offer, quote)?,
        })
    }
}

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

/// The kept set the hub chose, against the openings sent before for this
/// deposit. For the same journal her instances are the same ones (from the
/// contract's seed and the journal), so the hub must keep the same set
/// again: opening any other would hand it the seeds of instances it keeps,
/// and so their `msg`s, an answer to her challenge without a valid proof.
/// For another journal they are other instances, and any set will do.
pub(crate) fn check_kept(sent: &[SentOpening], journal: &Hash, kept: &[u32]) -> Result<()> {
    if let Some(s) = sent.iter().find(|s| s.journal == *journal) {
        ensure!(s.kept == kept, "the hub keeps instances {kept:?}, but it was sent the opening of all but {:?} already: opening others would give it the seeds of instances it keeps. This contract can't be opened again; refund its deposit after its timeout", s.kept);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_resumed_opening_opens_the_same_instances_or_none() {
        let (j, other) = ([1u8; 32], [2u8; 32]);
        let sent = vec![SentOpening { journal: j, kept: vec![2, 5] }];
        // nothing sent yet: any set
        assert!(check_kept(&[], &j, &[1, 3]).is_ok());
        // the same journal: the same set only
        assert!(check_kept(&sent, &j, &[2, 5]).is_ok());
        assert!(check_kept(&sent, &j, &[2, 6]).is_err());
        assert!(check_kept(&sent, &j, &[2]).is_err());
        // another journal: other instances, any set
        assert!(check_kept(&sent, &other, &[1, 3]).is_ok());
    }

    #[test]
    fn a_deposit_recorded_before_the_field_still_loads() {
        let key = bitcoin::secp256k1::Keypair::from_seckey_slice(bitcoin::secp256k1::SECP256K1, &[7; 32]).unwrap().x_only_public_key().0;
        let old = serde_json::json!({ "nonce": "ab", "cid": 3, "hub": key, "timeout": 144, "payout": "0014" });
        let d: crate::Deposit = serde_json::from_value(old).unwrap();
        assert!(d.sent.is_empty() && d.offered.is_none() && d.earlier.is_empty());
        let sent = SentOpening { journal: [9; 32], kept: vec![4, 8] };
        let back: SentOpening = serde_json::from_str(&serde_json::to_string(&sent).unwrap()).unwrap();
        assert_eq!(back, sent);
    }
}
