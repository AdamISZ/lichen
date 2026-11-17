//! Alice's side of a dispute (papers/lichen-grants-v0.5.6, §6;
//! [`super::Engine::run`] dispatches here). She requests, posting her
//! claim `Q` and `b`; the hub corrects it (`correct`: `b_corr` and the
//! unlock `U`) or after `w_H` her timeout pays her. If `U` opens her spend
//! in flight, she completes it: her new note settles, and the seed is
//! public for the counterparty. Then she accepts a correction to what she
//! is owed (after `w_A`, `accept` pays it), or countersigns it in `ack`,
//! and the hub must prove: a valid proof she lets stand (`success` pays
//! `b_corr`); a false one she challenges, revealing π1's input secrets by
//! completing the hub's adaptor pre-signatures with her dealing's, and if
//! the hub can't answer with a kept instance's `msg` within `Δ1`,
//! `failure` pays her `b`.
//!
//! Also her secrets: her one-time keys for `Q`, `b`, `b_corr` and `U`, her
//! setup's ([`dealing`], [`instance_seed`]); from her contract's seed, so
//! that nothing of them need be kept.

use std::time::Duration;

use anyhow::{ensure, Context, Result};
use bitcoin::OutPoint;
use lichen_babe::countersigned::{Countersigned, Q_LEN, U_LEN};
use lichen_babe::reveal::{complete, reveal_args};
use lichen_babe::setup::DIGITS;
use lichen_babe::vsss::{deal, Dealer, Dealing};
use lichen_chain::{Chain, Stall};
use lichen_proto::hp::{AliceKeys, HpDisputed};
use lichen_proto::setup::link_args;
use lichen_proto::{Record, Statement};
use lichen_btc::adaptor::AdaptorSig;
use lichen_btc::keys::Seed;
use lichen_wots::{Wots256Secret, WotsParams};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use super::{confirmed_at, wait_link, ContractSecrets, Engine, Next, Outcome};

impl ContractSecrets {
    fn hp_seed(&self) -> Seed {
        Seed::from_label(&format!("{}/hp", self.seed))
    }
    fn ots(&self, label: &str, n: usize) -> Wots256Secret {
        Wots256Secret::from_entropy(WotsParams::for_bytes(n as u32), self.wots(label))
    }
    /// Her one-time key for `b` (4 bytes): `request`, and the payout's bit
    /// outputs read it.
    pub fn hp_b(&self) -> Wots256Secret {
        self.ots("grants/b", 4)
    }
    /// Her one-time key for the posted claim `Q`.
    pub fn hp_q(&self) -> Wots256Secret {
        self.ots("grants/q", Q_LEN)
    }
    /// Her one-time keys for her countersignatures in `ack`, on `b_corr`
    /// and `U`.
    pub fn hp_a_corr(&self) -> Wots256Secret {
        self.ots("grants/a_corr", 4)
    }
    pub fn hp_a_u(&self) -> Wots256Secret {
        self.ots("grants/a_u", U_LEN)
    }
    /// Her four one-time keys, as the journal binds them.
    pub fn alice_keys(&self) -> AliceKeys {
        AliceKeys { q_key: self.hp_q().public(), b_key: self.hp_b().public(), a_corr_key: self.hp_a_corr().public(), a_u_key: self.hp_a_u().public() }
    }
    /// `request`'s wire: her signatures on `b` and on `Q`.
    pub fn request_wire(&self, b: u32, q: &[u8]) -> Result<Vec<Vec<u8>>> {
        Countersigned::request_wire(&self.hp_b().sign(&b.to_be_bytes())?, &self.hp_q().sign(q)?)
    }
    /// Her signature on `b` as the payout's leaves take it.
    pub fn b_wire(&self, b: u32) -> Result<Vec<Vec<u8>>> {
        Ok(Countersigned::word_wire(&self.hp_b().sign(&b.to_be_bytes())?))
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
    /// A dispute ([`Engine::run`]): the exit's claim of `b` from contract
    /// `record`. Blocks until it ends. Resumable: what is on chain is
    /// replayed, not posted again.
    pub(super) fn run_hp(&mut self, chain: &Chain, record: &Record, statement: &Statement, b: u32) -> Result<Outcome> {
        let d = HpDisputed::new(record, statement)?;
        let w = d.graph.spec.windows;
        let plan = self.store.exit().context("a dispute is an exit: no claim kept")?;
        ensure!(plan.b == b, "the claim kept is of {}, not {b}", plan.b);
        let mut stall = Stall::new(chain.height()?, chain.network);
        while chain.confirmations(&record.funding.txid)? < u32::from(d.graph.spec.params.to_self_delay) {
            ensure!(!stall.stalled(chain.height()?), "the chain stalled before the contract's funding was deep enough to request");
            std::thread::sleep(Duration::from_millis(200));
        }
        let q = plan.posted()?;
        let wire = self.signer.contract().request_wire(b, &q)?;
        let tx = d.finish("request", wire)?;
        self.step(format!("requesting {b} units ({} sats), {} ({} vB)", u64::from(b) * record.terms.unit.to_sat(), d.txid("request"), tx.vsize()));
        let at = self.post_link(chain, "request", tx)?;
        if self.opts.pause_after == Some(1) {
            return Ok(Outcome::Paused);
        }
        self.step(format!("the hub may correct the claim until block {}", at + u32::from(w.w_h)));
        let correct = match wait_link(chain, &d.txid("correct"), &OutPoint { txid: d.txid("request"), vout: 0 }, at + u32::from(w.w_h))? {
            Next::Link(tx) => tx,
            Next::Deadline => {
                self.step("the hub didn't correct the claim: request_timeout pays the user".into());
                let txid = self.post_terminal(chain, &d.finish("request_timeout", vec![])?, &d.set["request_timeout"].prevout)?;
                return self.paid(Outcome::HubTimedOut(txid));
            }
            Next::Taken => return self.lost(d.txid("request")),
        };
        let (b_corr, u) = HpDisputed::corrected(&correct)?;
        let corrected_at = confirmed_at(chain, &d.txid("correct"))?.context("correct")?;
        // the unlock: if it opens our spend in flight, that step counts, and
        // its new note is ours (and the counterparty's, from the same seed)
        let unit = record.terms.unit.to_sat();
        let expected = match (u != [0; U_LEN]).then(|| self.store.unlocked(&u)).transpose()?.flatten() {
            Some(v) => {
                self.step(format!("correct's unlock completes our payment in flight: our new note holds {v} sats"));
                b.min(u32::try_from(v / unit).unwrap_or(u32::MAX))
            }
            None => b,
        };
        self.step(format!("the hub corrected the claim to {b_corr} units (we reckon {expected})"));
        if b_corr >= expected && !self.opts.contest {
            // accept: after w_A, accept pays b_corr
            self.step(format!("accepting: accept pays {b_corr} units from block {}", corrected_at + u32::from(w.w_a)));
            let paid = self.await_terminal(chain, &d, "correct", "accept", corrected_at + u32::from(w.w_a))?;
            return self.paid(Outcome::Corrected { success: paid, b_corr });
        }
        // contest: countersign the hub's values in ack, digit by digit
        let (hub_corr, hub_u) = Countersigned::read_correct(&link_args(&correct))?;
        let s = self.signer.contract();
        let wire = Countersigned::ack_wire(&hub_corr, &s.hp_a_corr().sign(&b_corr.to_be_bytes())?, &hub_u, &s.hp_a_u().sign(&u)?);
        let tx = d.finish("ack", wire)?;
        self.step(format!("contesting the correction: ack, {} ({} vB)", d.txid("ack"), tx.vsize()));
        let acked_at = self.post_link(chain, "ack", tx)?;
        if self.opts.pause_after == Some(2) {
            return Ok(Outcome::Paused);
        }
        self.step(format!("the hub may prove its correction until block {}", acked_at + u32::from(w.w_h)));
        let assert = match wait_link(chain, &d.txid("assert"), &OutPoint { txid: d.txid("ack"), vout: 0 }, acked_at + u32::from(w.w_h))? {
            Next::Link(tx) => tx,
            Next::Deadline => {
                self.step("the hub didn't prove its correction: ack_timeout pays the user".into());
                let txid = self.post_terminal(chain, &d.finish("ack_timeout", vec![])?, &d.set["ack_timeout"].prevout)?;
                return self.paid(Outcome::HubTimedOut(txid));
            }
            Next::Taken => return self.lost(d.txid("ack")),
        };
        // its proof, checked natively
        let asserted = d.asserted(&assert)?;
        let kind = statement.hp_kind()?;
        let journal = record.hp_journal();
        let valid = asserted.proof.as_ref().is_some_and(|p| kind.verify(&journal, p));
        let asserted_at = confirmed_at(chain, &d.txid("assert"))?.context("the assertion")?;
        if valid && !self.opts.unchecked_claims {
            self.step(format!("the hub proved the claim is owed at most {b_corr} units: success pays that from block {}", asserted_at + u32::from(w.delta2)));
            let success = self.await_terminal(chain, &d, "assert", "success", asserted_at + u32::from(w.delta2))?;
            return self.paid(Outcome::Corrected { success, b_corr });
        }
        self.step(format!("{}: challenging", if valid { "the hub's proof is valid, challenging anyway" } else { "the hub's proof is false" }));
        ensure!(chain.height()? < asserted_at + u32::from(w.delta2) || chain.get_tx(&d.txid("challenge_assert")).is_some(), "the challenge's window has passed");
        let keys = record.hp();
        let (dealer, _) = dealing(self.signer.contract(), keys.n, keys.kept.len() as u32);
        let revealed: Vec<_> = asserted.digits.iter().enumerate().map(|(j, v)| dealer.reveal(j, *v)).collect();
        let presigs: Vec<[AdaptorSig; 4]> = keys.hub_presigs.iter().map(|s| s.each_ref().map(AdaptorSig::from)).collect();
        let sigs = complete(&presigs, &asserted.digits, &revealed);
        let wire = Countersigned::challenge_wire(reveal_args(&asserted.preimages, &sigs));
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

    /// The payout `terminal` of link `link`'s output, once `due`: the hub's
    /// to post, or hers if it doesn't. Its txid, confirmed.
    fn await_terminal(&self, chain: &Chain, d: &HpDisputed, link: &str, terminal: &str, due: u32) -> Result<bitcoin::Txid> {
        let op = OutPoint { txid: d.txid(link), vout: 0 };
        let from = confirmed_at(chain, &op.txid)?.context("the link")?;
        let mut stall = Stall::new(chain.height()?, chain.network);
        let mut posted = false;
        loop {
            if let Some(t) = chain.spender(&op, from)? {
                return Ok(t);
            }
            let h = chain.height()?;
            if h >= due + 2 && !posted && chain.unspent(&op)? {
                // the hub hasn't: hers to post (it pays her b_corr)
                if let Err(e) = self.post_terminal(chain, &d.finish(terminal, vec![])?, &d.set[terminal].prevout) {
                    self.step(format!("posting {terminal}: {e:#}"));
                }
                posted = true;
            }
            ensure!(!stall.stalled(h), "the chain stalled");
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}
