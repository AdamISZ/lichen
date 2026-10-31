//! Alice's side of a BABE dispute ([`super::Engine::run`] dispatches
//! here). She requests her `b`; the hub responds, signing it too (or her
//! timeout pays her after `w_H`); she asserts her proof, π1 Lamport-signed
//! in 2-bit digits with π2 and π3 beside it, before `T_A`. If the hub
//! doesn't challenge within `Δ2`, `success` pays her. If it does, she
//! reads π1's secrets from the challenge (its completions of her adaptor
//! pre-signatures), interpolates each kept instance's from them and the
//! opened instances' shares, evaluates its garbled circuit on π1 and
//! decrypts: a valid proof opens `msg`, which she posts in
//! `wrongly_challenged`, and it pays her.
//!
//! Also what the dispute signs with ([`Secrets`]: her keys under her
//! contract's seed, or a tower's package of her signatures, keyless), the
//! keys an opening exchanges ([`request_keys`]), and where the instances
//! are kept ([`data_dir`]).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use bitcoin::{OutPoint, Txid};
use lichen_babe::garble::evaluate;
use lichen_babe::graph::Babe;
use lichen_babe::reveal::{extract, AdaptorKeys, LamportKey, Preimage};
use lichen_babe::setup::{digits, Instance, Secret, DIGITS};
use lichen_babe::statement::{pi23_to_bytes, proof_from_bytes};
use lichen_babe::vsss::interpolate;
use lichen_babe::we::decrypt;
use lichen_chain::{Chain, Stall};
use lichen_proto::babe::{shares_from_hex, BabeRequest, Disputed, Opened};
use lichen_proto::{Record, Statement};
use lngap_btc::adaptor::AdaptorSig;
use lngap_btc::keys::Seed;
use lngap_lamport::winternitz::{WotsParams, WotsSecret};

use super::{confirmed_at, wait_link, ContractSecrets, Engine, Next, Outcome, WalletSigner};

/// What a BABE dispute signs with: her two signatures, on `b` and on π1.
/// Nothing after `assert` is hers to sign (her signature on
/// `wrongly_challenged` was made at the opening), so a tower can play it
/// from the signatures alone.
pub trait Secrets {
    /// Her signature on `b`, as `request` takes it (with the exit, her
    /// signature on [`RETURN_E`] beside it: a return's dispute).
    fn request_wire(&self, b: u32, exit: bool) -> Result<Vec<Vec<u8>>>;
    /// An exit's `request` wire: her signatures on `b` and on the claim's
    /// `E`, and the claim as posted.
    fn exit_wire(&self, b: u32, e: &[u8; 32], posted: &[u8]) -> Result<Vec<Vec<u8>>>;
    /// Her Lamport signature on π1's digits: a preimage a digit.
    fn sign_pi1(&self, digits: &[u8]) -> Result<Vec<Preimage>>;
}

impl ContractSecrets {
    fn babe_seed(&self) -> Seed {
        Seed::from_label(&format!("{}/babe", self.seed))
    }
    pub fn babe_b(&self) -> WotsSecret {
        WotsSecret::from_entropy(WotsParams::for_bytes(4), self.wots("babe/b"))
    }
    pub fn babe_lamport(&self) -> LamportKey {
        LamportKey::new(&self.babe_seed(), DIGITS)
    }
    pub fn babe_adaptor(&self) -> AdaptorKeys {
        AdaptorKeys::new(&self.babe_seed(), DIGITS)
    }
    /// Her one-time key for `E`, the exit's claim (32 bytes).
    pub fn babe_e(&self) -> WotsSecret {
        WotsSecret::from_entropy(WotsParams::for_bytes(32), self.wots("babe/e"))
    }
}

/// The `E` a return's dispute signs in a contract with the exit: no
/// exit's claim (its branch of the statement doesn't read `E`).
pub const RETURN_E: [u8; 32] = [0; 32];

/// `request`'s wire for a return's dispute of `b`: her signature on `b`;
/// with the exit, on [`RETURN_E`] too, and nothing posted.
pub fn return_wire(s: &ContractSecrets, b: u32, exit: bool) -> Result<Vec<Vec<u8>>> {
    let b = s.babe_b().sign(&b.to_be_bytes())?;
    if exit {
        Babe::request_exit_wire(&b, &s.babe_e().sign(&RETURN_E)?, &[])
    } else {
        Ok(Babe::request_wire(&b))
    }
}

impl Secrets for WalletSigner {
    fn request_wire(&self, b: u32, exit: bool) -> Result<Vec<Vec<u8>>> {
        return_wire(&self.secrets, b, exit)
    }
    fn exit_wire(&self, b: u32, e: &[u8; 32], posted: &[u8]) -> Result<Vec<Vec<u8>>> {
        Babe::request_exit_wire(&self.secrets.babe_b().sign(&b.to_be_bytes())?, &self.secrets.babe_e().sign(e)?, posted)
    }
    fn sign_pi1(&self, digits: &[u8]) -> Result<Vec<Preimage>> {
        Ok(self.secrets.babe_lamport().sign(digits))
    }
}

/// Her BABE keys for an opening request (with the exit's), and the
/// instances she keeps.
pub fn request_keys(s: &ContractSecrets, kept: Vec<u32>) -> BabeRequest {
    BabeRequest { b_key: s.babe_b().public(), lamport: s.babe_lamport().public(), adaptor: s.babe_adaptor().public(), kept, e_key: Some(s.babe_e().public()) }
}

/// Her signature on `b` as the payout's leaves take it.
pub fn b_wire(s: &ContractSecrets, b: u32) -> Result<Vec<Vec<u8>>> {
    Ok(lngap_ladder::script::wots_wire(&s.babe_b().sign(&b.to_be_bytes())?))
}

/// Where contract `cid`'s instances are kept, under the dispute's `dir`:
/// each kept one (`instance-<i>.bin`) and the opened ones' shares
/// (`opened.json`).
pub fn data_dir(dir: &Path, cid: u32) -> PathBuf {
    dir.join(format!("babe-{cid}"))
}

impl Engine<'_> {
    /// A BABE dispute ([`Engine::run`]): the withdrawal of `b` from the
    /// contract `record`, `input` her Groth16 proof (its bytes). Blocks
    /// until the dispute ends, at the payout for a win. Resumable: what is
    /// on chain is replayed, not posted again.
    ///
    /// On the real statement the proof takes the hub's signature on `b`,
    /// from `respond`: with `input` empty (and none kept) she requests,
    /// and once the hub responds the dispute stops at
    /// [`Outcome::ProofDue`]; run again with the proof.
    pub(super) fn run_babe(&mut self, chain: &Chain, record: &Record, statement: &Statement, dir: &Path, b: u32, input: &[u8]) -> Result<Outcome> {
        let cid = record.cid();
        let d = Disputed::new(record, statement)?;
        // the claim: b, and the proof once made
        let input = match self.store.claim() {
            Some((b0, i0)) => {
                ensure!(b0 == b, "contract {cid} is already disputed with a claim of {b0}");
                match (i0.is_empty(), input.is_empty()) {
                    (_, true) => hex::decode(&i0)?,
                    (true, false) => {
                        self.store.set_claim(b, input)?;
                        input.to_vec()
                    }
                    (false, false) => {
                        ensure!(i0 == hex::encode(input), "contract {cid} is already disputed with another proof");
                        input.to_vec()
                    }
                }
            }
            None => {
                self.store.set_claim(b, input)?;
                input.to_vec()
            }
        };
        let proof = if input.is_empty() { None } else { Some(proof_from_bytes(&input).context("the claim's input is not a Groth16 proof")?) };
        let w = d.babe.spec.windows;
        let secrets = self.signer.babe()?;
        // requesting waits to_self_delay after the contract's funding
        let mut stall = Stall::new(chain.height()?, chain.network);
        while chain.confirmations(&record.funding.txid)? < u32::from(d.babe.spec.params.to_self_delay) {
            ensure!(!stall.stalled(chain.height()?), "the chain stalled before the contract's funding was deep enough to request");
            std::thread::sleep(Duration::from_millis(200));
        }
        self.step(format!("requesting {b} sats, {}", d.txid("request")));
        let exit = self.store.exit();
        let wire = match &exit {
            Some(p) => secrets.exit_wire(b, &p.e()?, &p.posted()?)?,
            None => secrets.request_wire(b, record.babe()?.exit.is_some())?,
        };
        let at = self.post_link(chain, "request", d.finish("request", wire)?)?;
        if self.opts.pause_after == Some(1) {
            return Ok(Outcome::Paused);
        }
        // the hub signs the same b, or her timeout pays her
        self.step(format!("waiting for the hub's response: its window ends at block {}", at + u32::from(w.w_h)));
        match wait_link(chain, &d.txid("respond"), &OutPoint { txid: d.txid("request"), vout: 0 }, at + u32::from(w.w_h))? {
            Next::Link(_) => {}
            Next::Deadline => {
                self.step("the hub didn't respond in time: request_timeout pays the user".into());
                let txid = self.terminal(chain, &d, "request_timeout", vec![])?;
                return self.paid(Outcome::HubTimedOut(txid));
            }
            Next::Taken => return self.lost(d.txid("request")),
        }
        // her proof, before T_A; past it, respond_timeout may have taken
        // the contract
        let s_op = OutPoint { txid: d.txid("respond"), vout: 0 };
        if !chain.unspent(&s_op)? && chain.get_tx(&d.txid("assert")).is_none() {
            self.step(format!("no assertion by T_A, block {}: respond_timeout took the contract", w.t_a));
            return self.lost(s_op.txid);
        }
        let proof = match (&exit, proof) {
            (Some(plan), given) => match self.exit_proof(chain, &d, statement, dir, plan, given)? {
                Ok(p) => p,
                Err(o) => return Ok(o),
            },
            (None, Some(p)) => p,
            (None, None) => return self.proof_due(chain, &d, dir),
        };
        ensure!(chain.height()? < w.t_a || chain.get_tx(&d.txid("assert")).is_some(), "T_A, block {}, has passed: the assertion is too late", w.t_a);
        let bits = lichen_babe::gadget::input(&proof.a);
        let (pi2, pi3) = pi23_to_bytes(&proof);
        self.step(format!("the hub responded: asserting the proof, {}", d.txid("assert")));
        let asserted = self.post_link(chain, "assert", d.finish("assert", Babe::assert_wire(&secrets.sign_pi1(&digits(&bits))?, &pi2, &pi3))?)?;
        if self.opts.pause_after == Some(2) {
            return Ok(Outcome::Paused);
        }
        // the hub's challenge, or after Δ2 her success
        let deadline = asserted + u32::from(w.delta2);
        self.step(format!("asserted at {asserted}: the hub may challenge until block {deadline}"));
        let a_op = OutPoint { txid: d.txid("assert"), vout: 0 };
        let mut stall = Stall::new(chain.height()?, chain.network);
        loop {
            if confirmed_at(chain, &d.txid("challenge_assert"))?.is_some() {
                return self.answer(chain, &d, dir, &bits, &proof);
            }
            if !chain.unspent(&a_op)? && chain.get_tx(&d.txid("challenge_assert")).is_none() {
                // our success, before a restart
                return self.paid(Outcome::Unchallenged(chain.get_tx(&d.txid("success")).map(|t| t.compute_txid()).unwrap_or(d.txid("success"))));
            }
            let h = chain.height()?;
            if h >= deadline && chain.get_tx(&d.txid("challenge_assert")).is_none() {
                let txid = self.terminal(chain, &d, "success", vec![])?;
                self.step(format!("no challenge came: success pays the user, {txid}"));
                return self.paid(Outcome::Unchallenged(txid));
            }
            ensure!(!stall.stalled(h), "the chain stalled");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// On the real statement, the hub responded and her proof is due: its
    /// signature on `b`, which the proof takes, written beside the
    /// instances.
    fn proof_due(&self, chain: &Chain, d: &Disputed, dir: &Path) -> Result<Outcome> {
        let t_a = d.babe.spec.windows.t_a;
        let auth = d.hub_auth(&chain.get_tx(&d.txid("respond")).context("respond")?)?;
        let data = data_dir(dir, d.record.cid());
        std::fs::create_dir_all(&data)?;
        let path = data.join("hub-auth.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&auth)?)?;
        self.step(format!("the hub responded: its signature on b is in {}; the proof is due by T_A, block {t_a}", path.display()));
        Ok(Outcome::ProofDue(t_a))
    }

    /// An exit's proof, once the hub has responded: the statement's branch
    /// its response leaves (`fixed::check_exit`), checked natively first.
    /// After `respond_counter`, `K` proved false, or (a real counter) no
    /// way to win; after a plain `respond`, her claim, `request` in its
    /// block with the contract's work on it. On the mock, the mock's proof;
    /// on the real statement `given`, or with none the statement's input
    /// written for the prover (`lichen-r0 babe-exit`) and the proof due.
    fn exit_proof(&mut self, chain: &Chain, d: &Disputed, statement: &Statement, dir: &Path, plan: &crate::exit::ExitPlan, given: Option<ark_groth16::Proof<ark_bn254::Bn254>>) -> Result<std::result::Result<ark_groth16::Proof<ark_bn254::Bn254>, Outcome>> {
        use lichen_withdraw::fixed::{check_exit, ExitStatement, Mode};
        let record = &d.record;
        let cid = record.cid();
        let kind = statement.babe_kind().context("not a BABE statement")?;
        let keys = record.babe()?;
        let x = keys.exit.as_ref().context("a contract without the exit")?;
        let respond = chain.get_tx(&d.txid("respond")).context("respond")?;
        let w = &respond.input[0].witness;
        let counter = w.len() >= 2 && w.nth(w.len() - 2) == Some(d.set["respond_counter"].leaf.as_bytes());
        let r = Babe::read_respond_exit(&Disputed::args(&respond), counter)?;
        let e = plan.e()?;
        ensure!(r.e == e, "the hub responded to another E than the claim's");
        let b_sig = Disputed::hub_b(&respond)?.hashes.try_into().map_err(|_| anyhow::anyhow!("the hub's signature on b, of another length"))?;
        let e_sig = r.hub_e.try_into().map_err(|_| anyhow::anyhow!("the hub's signature on E, of another length"))?;
        let mode = match r.k {
            Some(k) => {
                let seal = k.message();
                let journal: lichen_babe::statement::CounterJournal = [&record.deployment[..], &e[..]].concat().try_into().expect("64 bytes");
                if kind.verify_counter(&seal, &journal) {
                    self.step("the hub countered the claim, truly: no branch of the statement holds; respond_timeout takes the contract from T_A".into());
                    return Ok(Err(Outcome::Countered));
                }
                self.step("the hub's counter isn't one: proving it false".into());
                Mode::Counter { c: cid, d: record.deployment, e, k: seal, e_sig, k_sig: k.hashes }
            }
            None => {
                let funding = chain.get_tx(&record.funding.txid).context("the funding")?;
                let request = lichen_proto::exit::request_proof(chain, &funding, &d.txid("request"))?;
                let claim = plan.input(request, vec![])?;
                let headers = self.exit_headers(chain, &claim)?;
                Mode::Claim { claim: plan.input(claim.request, headers)?, b_sig, e_sig }
            }
        };
        let stmt = ExitStatement { keys: lichen_proto::babe::exit_keys(&keys.hub_b, &x.hub), deposit: lichen_proto::babe::statement_outpoint(&x.hub.deposit), mode };
        // natively, as the guest: on the mock without the chain receipt
        let checked = match kind {
            lichen_babe::statement::Kind::Mock => check_exit(&stmt, &[0; 32], &mut |_| true, &mut |k, j| kind.verify_counter(k, j)),
            lichen_babe::statement::Kind::Risc0 => {
                let id: [u8; 32] = hex::decode(lichen_ledger::CHAIN_IMAGE_ID.trim())?.try_into().map_err(|_| anyhow::anyhow!("the chain guest's image id"))?;
                let journal = match &stmt.mode {
                    Mode::Claim { claim, .. } => Some(claim.state.chain_journal(&id).to_bytes()),
                    _ => None,
                };
                check_exit(&stmt, &id, &mut |j| journal.as_deref() == Some(j), &mut |k, j| kind.verify_counter(k, j))
            }
        };
        if let Err(r) = checked {
            ensure!(self.opts.unchecked_claims, "the exit's statement rejects the claim ({r:?}): the hub would challenge it and win");
            self.step(format!("the exit's statement rejects the claim ({r:?}), asserting anyway"));
        }
        match (kind, given) {
            (lichen_babe::statement::Kind::Mock, _) => Ok(Ok(lichen_babe::statement::mock_prove(&record.babe_journal()?))),
            (_, Some(p)) => Ok(Ok(p)),
            (_, None) => {
                let data = data_dir(dir, cid);
                std::fs::create_dir_all(&data)?;
                let path = data.join("exit-statement.bin");
                std::fs::write(&path, stmt.to_bytes())?;
                let t_a = d.babe.spec.windows.t_a;
                self.step(format!("the hub responded: the statement's input is in {} (lichen-r0 babe-exit); the proof is due by T_A, block {t_a}", path.display()));
                Ok(Err(Outcome::ProofDue(t_a)))
            }
        }
    }

    /// The headers from the claim's anchor block on, once `request`'s
    /// block has the contract's work on it (waiting for blocks until then).
    fn exit_headers(&self, chain: &Chain, claim: &lichen_withdraw::exit::ExitInput) -> Result<Vec<[u8; 80]>> {
        use bitcoin::hashes::Hash as _;
        let anchor = bitcoin::BlockHash::from_byte_array(claim.state.anchor.block);
        let at = chain.block_height(&anchor)?.context("the claim's anchor block isn't on the chain")?;
        let req = lichen_ledger::lichen_validity::btc::Header(claim.request.header).hash();
        let mut stall = Stall::new(chain.height()?, chain.network);
        loop {
            let tip = chain.height()?;
            let headers = chain.headers_after(&anchor, (tip - at) as usize)?;
            let from = headers.iter().position(|h| lichen_ledger::lichen_validity::btc::Header(*h).hash() == req);
            let work: u128 = from.map_or(0, |p| headers[p..].iter().map(|h| lichen_ledger::lichen_validity::btc::work(u32::from_le_bytes(h[72..76].try_into().unwrap()))).sum());
            if work >= claim.state.work {
                return Ok(headers);
            }
            ensure!(!stall.stalled(tip), "the chain stalled before the request's block was deep enough");
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Post the pre-signed terminal `name` with its runtime `wire`.
    fn terminal(&self, chain: &Chain, d: &Disputed, name: &str, wire: Vec<Vec<u8>>) -> Result<Txid> {
        self.post_terminal(chain, &d.finish(name, wire)?, &d.set[name].prevout)
    }

    /// The hub challenged: read π1's secrets from its challenge, open a
    /// kept instance with them, and answer with its `msg`.
    fn answer(&mut self, chain: &Chain, d: &Disputed, dir: &Path, bits: &[bool], proof: &ark_groth16::Proof<ark_bn254::Bn254>) -> Result<Outcome> {
        let cid = d.record.cid();
        let keys = d.record.babe()?;
        let tx = chain.get_tx(&d.txid("challenge_assert")).context("the challenge")?;
        let presigs: Vec<[AdaptorSig; 4]> = keys.presigs.iter().map(|s| s.each_ref().map(AdaptorSig::from)).collect();
        let (posted, revealed) = extract(&keys.lamport, &presigs, &Disputed::args(&tx)).context("the challenge's secrets")?;
        ensure!(posted == digits(bits), "the challenge reveals other digits than asserted");
        self.step("challenged: opening the kept instances with π1's secrets".into());
        let data = data_dir(dir, cid);
        let opened: Vec<Opened> = serde_json::from_slice(&std::fs::read(data.join("opened.json")).context("the opened instances' shares")?)?;
        let of_digits: Vec<(u64, Vec<Secret>)> = opened.iter().map(|o| Ok((u64::from(o.i), shares_from_hex(&o.shares)?.iter().zip(&posted).map(|(p, v)| p[*v as usize]).collect()))).collect::<Result<_>>()?;
        for (k, i) in keys.kept.iter().enumerate() {
            let inst = Instance::from_bytes(&std::fs::read(data.join(format!("instance-{i}.bin"))).with_context(|| format!("kept instance {i}"))?).with_context(|| format!("kept instance {i} is unreadable"))?;
            let Some(secrets) = interpolate(u64::from(*i), &of_digits, &revealed) else { continue };
            let r_pi1 = evaluate(&inst.gc, bits, &inst.labels(bits, &secrets));
            let msg = decrypt(&inst.ct, &r_pi1, proof);
            if inst.is_msg(&msg) {
                let name = format!("wrongly_challenged_{k}");
                self.step(format!("kept instance {i} opens: answering with its msg ({name})"));
                let txid = self.terminal(chain, d, &name, Babe::wrongly_wire(&msg))?;
                return self.paid(Outcome::Answered(txid));
            }
            self.step(format!("kept instance {i} doesn't open"));
        }
        // no instance opens: the proof is false (or every kept instance
        // was, against odds of 1 in C(N, M)); failure takes the contract
        self.step("no kept instance opens on this proof: failure will take the contract".into());
        let c_op = OutPoint { txid: d.txid("challenge_assert"), vout: 0 };
        let mut stall = Stall::new(chain.height()?, chain.network);
        while chain.unspent(&c_op)? {
            ensure!(!stall.stalled(chain.height()?), "the chain stalled");
            std::thread::sleep(Duration::from_millis(200));
        }
        self.lost(c_op.txid)
    }
}
