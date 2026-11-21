//! BABE's tail of a dispute, the user's side: after the L2's front, the
//! hub must assert before the front's last window ends, or that link's
//! terminal pays her claim. Its proof she checks natively: a valid one she
//! lets stand (`success` pays out); a false one she challenges, revealing
//! π1's input secrets by completing the hub's adaptor pre-signatures with
//! her dealing's, and if the hub can't answer with a kept instance's
//! `msg` within `Δ1`, `failure` pays her claim.

use std::time::Duration;

use anyhow::{ensure, Context, Result};
use bitcoin::OutPoint;
use lichen_babe::graph::Graph;
use lichen_babe::reveal::{complete, reveal_args};
use lichen_btc::adaptor::AdaptorSig;
use lichen_chain::{Chain, Stall};
use lichen_proto::hp::Disputed;
use lichen_proto::Statement;

use super::{confirmed_at, revealed, wait_link, Engine, Next, Outcome};

impl Engine<'_> {
    /// The tail, the front's last link confirmed at `at`: if the hub's
    /// proof stands, `success` pays `b_corr` (or, with none, the hub).
    pub(crate) fn tail(&mut self, chain: &Chain, d: &Disputed, statement: &Statement, journal: &[u8], at: u32, b_corr: Option<u32>) -> Result<Outcome> {
        let last = d.last_front()?;
        let link = d.graph.front.links()?.pop().context("an empty front")?;
        let w = d.graph.tail.windows;
        self.step(format!("the hub may assert until block {}", at + u32::from(link.window)));
        let assert = match wait_link(chain, &d.txid("assert"), &OutPoint { txid: d.txid(last), vout: 0 }, at + u32::from(link.window))? {
            Next::Link(tx) => tx,
            Next::Deadline => {
                self.step(format!("the hub didn't assert: {} pays the user", link.terminal));
                let txid = self.post_terminal(chain, &d.finish(link.terminal, vec![])?, &d.set[link.terminal].prevout)?;
                return self.paid(Outcome::HubTimedOut(txid));
            }
            Next::Taken => return self.lost(d.txid(last)),
        };
        // its proof, checked natively
        let asserted = d.asserted(&assert)?;
        let kind = statement.hp_kind()?;
        let valid = asserted.proof.as_ref().is_some_and(|p| kind.verify(journal, p));
        let asserted_at = confirmed_at(chain, &d.txid("assert"))?.context("the assertion")?;
        if valid && !self.opts.unchecked_claims {
            return match b_corr {
                Some(b_corr) => {
                    self.step(format!("the hub proved the claim is owed at most {b_corr} units: success pays that from block {}", asserted_at + u32::from(w.delta2)));
                    let success = self.await_terminal(chain, d, "assert", "success", asserted_at + u32::from(w.delta2))?;
                    self.paid(Outcome::Corrected { success, b_corr })
                }
                None => {
                    self.step("the hub proved the claim false: success pays it the contract".into());
                    self.lost(d.txid("assert"))
                }
            };
        }
        self.step(format!("{}: challenging", if valid { "the hub's proof is valid, challenging anyway" } else { "the hub's proof is false" }));
        ensure!(chain.height()? < asserted_at + u32::from(w.delta2) || chain.get_tx(&d.txid("challenge_assert")).is_some(), "the challenge's window has passed");
        let keys = d.record.hp();
        let presigs: Vec<[AdaptorSig; 4]> = keys.hub_presigs.iter().map(|s| s.each_ref().map(AdaptorSig::from)).collect();
        let msg = Graph::link_sighash(std::slice::from_ref(&d.set["challenge_assert"]), "challenge_assert")?;
        let revealed = revealed(self.signer.contract(), keys.n, keys.kept.len() as u32, &kind, journal, (&keys.hub_adaptor, &msg, &presigs), &asserted.digits);
        let sigs = complete(&presigs, &asserted.digits, &revealed);
        let wire = Graph::challenge_wire(reveal_args(&asserted.preimages, &sigs));
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

    /// Wait for terminal `terminal` (spending `link`'s output) from block
    /// `due`, posting it herself if the hub hasn't; its txid.
    pub fn await_terminal(&self, chain: &Chain, d: &Disputed, link: &str, terminal: &str, due: u32) -> Result<bitcoin::Txid> {
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
                // the hub hasn't: hers to post
                if let Err(e) = self.post_terminal(chain, &d.finish(terminal, vec![])?, &d.set[terminal].prevout) {
                    self.step(format!("posting {terminal}: {e:#}"));
                }
                posted = true;
            }
            ensure!(!stall.stalled(h), "the chain stalled");
            std::thread::sleep(Duration::from_millis(200));
        }
    }}
