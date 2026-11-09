//! Alice's side of a hub-proves dispute (docs/HUB_PROVES_PLAN.md;
//! [`super::Engine::run`] dispatches here). She requests, posting her
//! claim; the hub asserts a proof that it is false, or after `w_H` her
//! timeout pays her. If it asserts, she checks its proof natively: a valid
//! one she lets stand (the claim was false, and `success` is the hub's
//! after `Δ2`); a false one she challenges, revealing π1's input secrets
//! by completing the hub's adaptor pre-signatures with her dealing's, and
//! if the hub can't answer with a kept instance's `msg` within `Δ1`,
//! `failure` pays her.
//!
//! Also her secrets: her one-time keys for `b` and `E`, her setup's
//! ([`dealing`], [`instance_seed`]); from her contract's seed, so that
//! nothing of them need be kept.

use std::time::Duration;

use anyhow::{ensure, Context, Result};
use bitcoin::OutPoint;
use lichen_babe::reveal::{complete, reveal_args};
use lichen_babe::hp::HubProves;
use lichen_babe::setup::DIGITS;
use lichen_babe::vsss::{deal, Dealer, Dealing};
use lichen_chain::{Chain, Stall};
use lichen_proto::hp::HpDisputed;
use lichen_proto::{Record, Statement};
use lngap_btc::adaptor::AdaptorSig;
use lngap_btc::keys::Seed;
use lngap_lamport::winternitz::{WotsParams, WotsSecret};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use super::{confirmed_at, wait_link, ContractSecrets, Engine, Next, Outcome};

impl ContractSecrets {
    fn hp_seed(&self) -> Seed {
        Seed::from_label(&format!("{}/hp", self.seed))
    }
    /// Her one-time key for `b` (4 bytes): `request` and the payout's bit
    /// outputs read it.
    pub fn hp_b(&self) -> WotsSecret {
        WotsSecret::from_entropy(WotsParams::for_bytes(4), self.wots("hp/b"))
    }
    /// Her one-time key for `E`, the claim's fingerprint (32 bytes).
    pub fn hp_e(&self) -> WotsSecret {
        WotsSecret::from_entropy(WotsParams::for_bytes(32), self.wots("hp/e"))
    }
    /// `request`'s wire: her signatures on `b` and `E`, and the claim
    /// posted.
    pub fn request_wire(&self, b: u32, e: &[u8; 32], posted: &[u8]) -> Result<Vec<Vec<u8>>> {
        HubProves::request_wire(&self.hp_b().sign(&b.to_be_bytes())?, &self.hp_e().sign(e)?, posted)
    }
    /// Her signature on `b` as the payout's leaves take it.
    pub fn b_wire(&self, b: u32) -> Result<Vec<Vec<u8>>> {
        Ok(HubProves::b_wire(&self.hp_b().sign(&b.to_be_bytes())?))
    }
}

/// Her dealing of the input secrets, of degree `n − m`.
pub fn dealing(s: &ContractSecrets, n: u32, m: u32) -> (Dealer, Dealing) {
    deal(DIGITS, (n - m) as usize, &mut ChaCha20Rng::from_seed(s.hp_seed().derive_bytes("dealing")))
}

/// Instance `i`'s seed (from 1).
pub fn instance_seed(s: &ContractSecrets, i: u32) -> [u8; 32] {
    s.hp_seed().derive_bytes(&format!("instance/{i}"))
}

impl Engine<'_> {
    /// A hub-proves dispute ([`Engine::run`]): the exit's claim of `b`
    /// from contract `record`. Blocks until it ends. Resumable: what is on
    /// chain is replayed, not posted again.
    pub(super) fn run_hp(&mut self, chain: &Chain, record: &Record, statement: &Statement, b: u32) -> Result<Outcome> {
        let d = HpDisputed::new(record, statement)?;
        let w = d.graph.spec.windows;
        let plan = self.store.exit().context("a hub-proves dispute is an exit: no claim kept")?;
        ensure!(plan.b == b, "the claim kept is of {}, not {b}", plan.b);
        let mut stall = Stall::new(chain.height()?, chain.network);
        while chain.confirmations(&record.funding.txid)? < u32::from(d.graph.spec.params.to_self_delay) {
            ensure!(!stall.stalled(chain.height()?), "the chain stalled before the contract's funding was deep enough to request");
            std::thread::sleep(Duration::from_millis(200));
        }
        let wire = self.signer.contract().request_wire(b, &plan.e()?, &plan.posted()?)?;
        let tx = d.finish("request", wire)?;
        self.step(format!("requesting {b} units ({} sats), {} ({} vB)", u64::from(b) * record.terms.unit.to_sat(), d.txid("request"), tx.vsize()));
        let at = self.post_link(chain, "request", tx)?;
        if self.opts.pause_after == Some(1) {
            return Ok(Outcome::Paused);
        }
        self.step(format!("the hub may assert the claim false until block {}", at + u32::from(w.w_h)));
        let assert = match wait_link(chain, &d.txid("assert"), &OutPoint { txid: d.txid("request"), vout: 0 }, at + u32::from(w.w_h))? {
            Next::Link(tx) => tx,
            Next::Deadline => {
                self.step("the hub didn't assert: request_timeout pays the user".into());
                let txid = self.post_terminal(chain, &d.finish("request_timeout", vec![])?, &d.set["request_timeout"].prevout)?;
                return self.paid(Outcome::HubTimedOut(txid));
            }
            Next::Taken => return self.lost(d.txid("request")),
        };
        // its proof, checked natively
        let asserted = d.asserted(&assert)?;
        let kind = statement.hp_kind()?;
        let journal = record.hp_journal();
        let valid = asserted.proof.as_ref().is_some_and(|p| kind.verify(&journal, p));
        if valid && !self.opts.unchecked_claims {
            self.step("the hub asserted a valid proof that the claim is false: success is the hub's".into());
            return Ok(Outcome::Countered);
        }
        let asserted_at = confirmed_at(chain, &d.txid("assert"))?.context("the assertion")?;
        self.step(format!("{}: challenging", if valid { "the hub's proof is valid, challenging anyway" } else { "the hub's proof is false" }));
        ensure!(chain.height()? < asserted_at + u32::from(w.delta2) || chain.get_tx(&d.txid("challenge_assert")).is_some(), "the challenge's window has passed");
        let keys = record.hp();
        let (dealer, _) = dealing(self.signer.contract(), keys.n, keys.kept.len() as u32);
        let revealed: Vec<_> = asserted.digits.iter().enumerate().map(|(j, v)| dealer.reveal(j, *v)).collect();
        let presigs: Vec<[AdaptorSig; 4]> = keys.hub_presigs.iter().map(|s| s.each_ref().map(AdaptorSig::from)).collect();
        let sigs = complete(&presigs, &asserted.digits, &revealed);
        let wire = HubProves::challenge_wire(reveal_args(&asserted.preimages, &sigs));
        let tx = d.finish("challenge_assert", wire)?;
        let vsize = tx.vsize();
        let challenged = self.post_link(chain, "challenge_assert", tx)?;
        let deadline = challenged + u32::from(w.delta1);
        self.step(format!("challenged at {challenged} ({vsize} vB): the hub may answer until block {deadline}"));
        let c_op = OutPoint { txid: d.txid("challenge_assert"), vout: 0 };
        let mut stall = Stall::new(chain.height()?, chain.network);
        loop {
            if !chain.unspent(&c_op)? {
                if chain.get_tx(&d.txid("failure")).is_some() {
                    return self.paid(Outcome::Refuted(d.txid("failure")));
                }
                self.step("the hub answered the challenge: its proof was valid".into());
                return self.lost(c_op.txid);
            }
            let h = chain.height()?;
            if h >= deadline {
                let txid = self.post_terminal(chain, &d.finish("failure", vec![])?, &d.set["failure"].prevout)?;
                self.step(format!("the hub didn't answer: failure pays the user, {txid}"));
                return self.paid(Outcome::Refuted(txid));
            }
            ensure!(!stall.stalled(h), "the chain stalled");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
