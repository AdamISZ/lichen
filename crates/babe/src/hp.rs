//! BABE's graph with the roles swapped, for the exit where only the hub
//! proves (docs/HUB_PROVES_PLAN.md, "On chain"): Alice claims, the hub
//! asserts a proof that her claim is false or lets her timeout pay her.
//!
//! ```text
//! request (Alice: b, the claim, each one-time signed)
//!  ├─ request_timeout (after w_H)      → Alice: b
//!  └─ correct (the hub: b_corr, its one-time key bc; its slots)
//!      ├─ correct_timeout (after w_H)  → Alice: b
//!      └─ assert (the hub: π1, Lamport)
//!          ├─ success (after Δ2)       → Alice: b_corr (by bc's
//!          │                              signature) and her reserve;
//!          │                              the rest the hub's
//!          └─ challenge_assert (Alice)
//!              ├─ wrongly_challenged_k → the hub (its proof was valid)
//!              └─ failure (after Δ1)   → Alice: b
//! ```
//!
//! The statement (the grants L2's, `lichen_withdraw::grants`) is that the
//! claim is owed at most `b_corr`: `success` pays it, bit by bit, read
//! from the hub's one-time signature in `correct`; two signatures under
//! `bc` give Alice every bit output (`equiv_corr`).
//!
//! `correct` also carries [`SLOTS`] signatures by the hub on `correct`
//! itself (64 bytes each, `SIGHASH_DEFAULT`): to cite a spend of hers
//! against her claim, the hub completes in a slot its pre-signature on
//! `correct` from the spend's grant, which reveals the spend's unlock to
//! her (`lichen_notes::Reveal`); the other slots take any signature.
//!
//! `success` and `failure` are the prover's, as in BABE: the prover is
//! the hub here. Alice garbled the kept instances (`hmsg` their
//! hashlocks), so she holds the input secrets and reveals π1's in her
//! challenge, by completing the hub's adaptor pre-signatures; the hub
//! evaluates them and answers with a `msg`. The hub keeps its signature
//! on `wrongly_challenged` from her ([`HubProves::withheld`]): she knows
//! every `msg` and could post it herself, large and at a low fee rate,
//! and pin the hub's own (papers/lichen-babe §7). It is TRUC (version
//! 3), which bounds what could pin with it.
//!
//! The contract output's `request` leaf carries her one-time signatures
//! on `b` and on the claim ([`POSTED_LEN`] bytes, signed in full so that
//! no one can swap them; the hub's statement reads its digits,
//! `lichen_withdraw::grants`). Every transaction has one input: the
//! value flows through one chain from the contract output, and each
//! output of the chain has its terminal (a terminal can't pay into a
//! pre-signed transaction: its broadcaster adds a fee input, which
//! changes its id).

use anyhow::{ensure, Context, Result};
use lichen_withdraw::grants::{POSTED_LEN, SLOTS};
use lngap_btc::bitcoin::opcodes::all::*;
use lngap_btc::bitcoin::script::Builder;
use lngap_btc::bitcoin::transaction::Version;
use lngap_btc::bitcoin::{Amount, OutPoint, TxOut};
use lngap_btc::script::BuilderExt;
use lngap_btc::secp256k1::{Message, XOnlyPublicKey};
use lngap_btc::sighash::tapscript_sighash;
use lngap_btc::taptree::{Leaf, TapTree};
use lngap_btc::tx::Timelock;
use lngap_channel::{ChannelParams, CommitCtx, PartyPubKeys, Role};
use lngap_lamport::winternitz::{WotsExt, WotsParams, WotsPublic, WotsSig};
use lngap_sessions::session::Terms;
use lngap_sessions::skeleton::{wots_shape, Core, Presign, POST_CSV};

use crate::reveal::{LamportPub, Preimage};
use crate::setup::{Hash, DIGITS, VALUES};

/// The dispute's windows: `w_H` for the hub's assertion, `Δ2` for her
/// challenge, `Δ1` for the hub's answer, relative, in blocks; `t_a` her
/// request's latest, a height (as `T_close` is).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Windows {
    pub w_h: u16,
    pub t_a: u32,
    pub delta2: u16,
    pub delta1: u16,
}

/// `assert`'s arguments: the preimages, π2, π3.
pub type Asserted<'a> = (&'a [Vec<u8>], &'a [u8], &'a [u8]);

fn ok_leaf(name: &str, b: Builder, timelock: Timelock) -> Leaf {
    Leaf::new(name, b.push_int(1).into_script(), timelock)
}

/// `Builder` with a relative lock, and the lock.
fn after(blocks: u16) -> (Builder, Timelock) {
    (Builder::new().csv(blocks), Timelock::csv(blocks))
}

/// Drop a word's 8 digits, which `wots_verify` leaves.
fn drop_digits(b: Builder) -> Builder {
    drop_n(b, 8)
}

/// Drop `n` stack items (`n` even, or one `OP_DROP` more).
fn drop_n(b: Builder, n: usize) -> Builder {
    let b = (0..n / 2).fold(b, |b, _| b.push_opcode(OP_2DROP));
    if n % 2 == 1 {
        b.push_opcode(OP_DROP)
    } else {
        b
    }
}

/// The posted claim's digits.
const CLAIM_DIGITS: usize = 2 * POSTED_LEN;

/// A contract of the swapped game: what both parties build its graph
/// from.
#[derive(Clone, Debug)]
pub struct Spec {
    pub terms: Terms,
    pub params: ChannelParams,
    /// Alice's keys, then the hub's.
    pub pubs: [PartyPubKeys; 2],
    /// Alice's one-time keys for `b` (the payout's bit outputs read it)
    /// and for the posted claim.
    pub b_key: WotsPublic,
    pub claim_key: WotsPublic,
    /// The hub's one-time key for `b_corr` (`correct`; `success`'s bit
    /// outputs read it).
    pub bc_key: WotsPublic,
    /// The hub's Lamport key for π1, in 2-bit digits, and its one-time
    /// adaptor keys, a digit and value.
    pub lamport: LamportPub,
    pub adaptor: Vec<[XOnlyPublicKey; VALUES]>,
    /// The kept instances' hashlocks, `SHA-256(msg)`: Alice's.
    pub hmsg: Vec<Hash>,
    /// `w_H` for the hub's assertion, `Δ2` for her challenge, `Δ1` for
    /// the hub's answer (`t_a` unused).
    pub windows: Windows,
}

/// A contract's graph.
pub struct HubProves {
    pub spec: Spec,
}

impl HubProves {
    pub fn new(spec: Spec) -> Result<HubProves> {
        ensure!(spec.b_key.params == WotsParams::for_bytes(4), "the key for b signs a 4-byte word");
        ensure!(spec.claim_key.params == WotsParams::for_bytes(POSTED_LEN as u32), "the key for the claim signs {POSTED_LEN} bytes");
        ensure!(spec.bc_key.params == WotsParams::for_bytes(4), "the key for b_corr signs a 4-byte word");
        ensure!(spec.lamport.0.len() == DIGITS && spec.adaptor.len() == DIGITS, "a Lamport and an adaptor key set per digit of π1");
        ensure!(!spec.hmsg.is_empty(), "a kept instance at least");
        let w = spec.windows;
        ensure!(w.w_h > POST_CSV && w.delta1 > POST_CSV && w.delta2 > POST_CSV, "each window longer than a post's lock");
        Ok(HubProves { spec })
    }
    pub fn core(&self) -> Core<'_> {
        Core { terms: &self.spec.terms, params: &self.spec.params, pubs: &self.spec.pubs }
    }
    fn ctx(&self) -> CommitCtx<'_> {
        self.core().ctx()
    }
    pub fn value(&self) -> Amount {
        self.core().value()
    }
    fn signed(&self, (b, tl): (Builder, Timelock)) -> (Builder, Timelock) {
        (self.ctx().two_of_two_verify(b), tl)
    }

    /// The contract output's tree: `fold`, `default`, and `request` (after
    /// `to_self_delay`): her signatures on `b` and on the claim (the hub's
    /// statement reads its digits).
    pub fn tree(&self) -> Result<TapTree> {
        let d = self.spec.params.to_self_delay;
        let (b, tl) = self.signed(if d > 0 { after(d) } else { (Builder::new(), Timelock::NONE) });
        let b = drop_digits(b.wots_verify(&self.spec.b_key));
        let b = drop_n(b.wots_verify(&self.spec.claim_key), CLAIM_DIGITS);
        self.core().tree(ok_leaf("request", b, tl))
    }
    /// `request`'s output: the hub's `correct`, its one-time signature on
    /// `b_corr` and its [`SLOTS`] signatures on `correct` (each exactly 64
    /// bytes: the default sighash, the message every reveal pre-signs);
    /// or, after `w_H`, `request_timeout`.
    pub fn requested(&self) -> Result<TapTree> {
        let (b, tl) = self.signed(after(POST_CSV));
        let hub = self.ctx().key(Role::Hub).payment;
        let correct = (0..SLOTS).fold(drop_digits(b.wots_verify(&self.spec.bc_key)), |b, _| b.push_opcode(OP_SIZE).push_int(64).push_opcode(OP_EQUALVERIFY).checksigverify(&hub));
        let (t, ttl) = self.signed(after(self.spec.windows.w_h));
        TapTree::new(vec![ok_leaf("correct", correct, tl), ok_leaf("request_timeout", t, ttl)])
    }
    /// `correct`'s output: the hub's `assert`, π1's digits under its
    /// Lamport key, π2 and π3 beside them (so that Alice can check the
    /// whole proof from the chain); or, after `w_H`, `correct_timeout`.
    pub fn corrected(&self) -> Result<TapTree> {
        let (b, tl) = self.signed(after(POST_CSV));
        let assert = self.spec.lamport.verify(b).push_opcode(OP_2DROP);
        let (t, ttl) = self.signed(after(self.spec.windows.w_h));
        TapTree::new(vec![ok_leaf("assert", assert, tl), ok_leaf("correct_timeout", t, ttl)])
    }
    /// `assert`'s output: Alice's `challenge_assert`, the reveal; or,
    /// after `Δ2`, `success`, the hub's.
    pub fn asserted(&self) -> Result<TapTree> {
        let (b, tl) = self.signed(after(POST_CSV));
        let b = crate::reveal::reveal_verify(b, &self.spec.lamport, &self.spec.adaptor);
        let (s, stl) = self.signed(after(self.spec.windows.delta2));
        TapTree::new(vec![ok_leaf("challenge_assert", b, tl), ok_leaf("success", s, stl)])
    }
    /// `challenge_assert`'s output: the hub's `wrongly_challenged_k`, a
    /// kept instance's `msg`; or, after `Δ1`, `failure`, hers.
    pub fn challenged(&self) -> Result<TapTree> {
        let mut leaves: Vec<Leaf> = self
            .spec
            .hmsg
            .iter()
            .enumerate()
            .map(|(k, h)| {
                let (b, tl) = self.signed(after(POST_CSV));
                ok_leaf(&format!("wrongly_challenged_{k}"), b.push_opcode(OP_SHA256).push_bytes(h).push_opcode(OP_EQUALVERIFY), tl)
            })
            .collect();
        let (f, ftl) = self.signed(after(self.spec.windows.delta1));
        leaves.push(ok_leaf("failure", f, ftl));
        TapTree::new(leaves)
    }
    /// The outputs paying `b` in bits and the reserves to Alice.
    pub fn pay_alice(&self, available: Amount) -> Result<Vec<TxOut>> {
        self.core().pay_alice(&self.spec.b_key, available)
    }
    /// `success`'s outputs: for each bit `i` an output of `u 2^i`, Alice's
    /// iff bit `i` of the hub's signed `b_corr` is set ([`corr_bit_tree`]);
    /// Alice's reserve back to her payout address; the rest the hub's
    /// (it bears the dispute's floors).
    pub fn pay_corrected(&self, available: Amount) -> Result<Vec<TxOut>> {
        let core = self.core();
        let (t, ctx) = (core.terms, core.ctx());
        let mut outs: Vec<TxOut> = (t.low_bits..t.bits).map(|i| Ok(TxOut { value: t.unit * (1u64 << i), script_pubkey: corr_bit_tree(&ctx, i, &self.spec.bc_key)?.script_pubkey() })).collect::<Result<_>>()?;
        let paid: Amount = outs.iter().map(|o| o.value).sum();
        outs.push(TxOut { value: t.reserve_alice, script_pubkey: self.spec.pubs[0].payout_spk.clone() });
        let rest = available.checked_sub(paid + t.reserve_alice).context("success can't pay V_max and Alice's reserve")?;
        if rest >= ctx.params.dust {
            outs.push(TxOut { value: rest, script_pubkey: self.spec.pubs[1].payout_spk.clone() });
        }
        Ok(outs)
    }
    /// Who posts link `name`.
    pub fn poster(name: &str) -> Role {
        match name {
            "request" | "challenge_assert" => Role::User,
            _ => Role::Hub,
        }
    }
    /// A witness of link `name`'s shape, for its floor.
    fn shape(&self, name: &str) -> Vec<Vec<u8>> {
        match name {
            "request" => wots_shape([&self.spec.claim_key, &self.spec.b_key]),
            "correct" => vec![vec![0u8; 64]; SLOTS].into_iter().chain(wots_shape([&self.spec.bc_key])).collect(),
            "assert" => vec![vec![0u8; 20]; DIGITS].into_iter().chain([vec![0u8; 64], vec![0u8; 32]]).collect(),
            _ => (0..DIGITS).flat_map(|_| [vec![0u8; 20], vec![0u8; 64]]).collect(),
        }
    }

    /// Every transaction the parties pre-sign, the contract output at
    /// `funding`: the default; the chain and each output's terminal; per
    /// kept instance, `wrongly_challenged_k`.
    pub fn presign(&self, funding: OutPoint) -> Result<Vec<Presign>> {
        let tree = self.tree()?;
        let c_out = TxOut { value: self.value(), script_pubkey: tree.script_pubkey() };
        let mut out = vec![self.core().default_tx(&tree, funding)?];
        let (mut prev, mut op, mut prev_out) = (tree, funding, c_out);
        type Terminal<'a> = &'a dyn Fn(&HubProves, Amount) -> Result<Vec<TxOut>>;
        let alice: Terminal = &|g, v| g.pay_alice(v);
        let corrected: Terminal = &|g, v| g.pay_corrected(v);
        let chain: [(&str, TapTree, &str, Terminal); 4] = [
            ("request", self.requested()?, "request_timeout", alice),
            ("correct", self.corrected()?, "correct_timeout", alice),
            ("assert", self.asserted()?, "success", corrected),
            ("challenge_assert", self.challenged()?, "failure", alice),
        ];
        for (name, next, terminal, pay) in chain {
            let link = self.core().link(name, Self::poster(name), self.shape(name), &prev, name, op, &prev_out, next.script_pubkey())?;
            let n_out = link.tx.output[0].clone();
            op = OutPoint { txid: link.tx.compute_txid(), vout: 0 };
            out.push(link);
            out.push(Presign::new(terminal, &next, terminal, op, &n_out, pay(self, n_out.value)?, false)?);
            (prev, prev_out) = (next, n_out);
        }
        for k in 0..self.spec.hmsg.len() {
            let name = format!("wrongly_challenged_{k}");
            let mut w = Presign::new(&name, &prev, &name, op, &prev_out, self.core().pay_hub(prev_out.value), false)?;
            w.tx.version = Version::non_standard(3);
            out.push(w);
        }
        Ok(out)
    }

    /// Whether the hub keeps its signature on `name` from Alice.
    pub fn withheld(name: &str) -> bool {
        name.starts_with("wrongly_challenged_")
    }

    /// `challenge_assert`'s sighash in `set`, which the hub's adaptor
    /// pre-signatures sign.
    pub fn challenge_sighash(set: &[Presign]) -> Result<Message> {
        Self::link_sighash(set, "challenge_assert")
    }
    /// Link `name`'s sighash in `set` (its one input, by its leaf, the
    /// default sighash): `correct`'s is what each grant's reveal
    /// pre-signs.
    pub fn link_sighash(set: &[Presign], name: &str) -> Result<Message> {
        let p = set.iter().find(|p| p.name == name).with_context(|| format!("no {name}"))?;
        tapscript_sighash(&p.tx, 0, std::slice::from_ref(&p.prevout), &p.leaf)
    }

    // ----- the links' witnesses, below both signatures -----

    /// `request`'s: her signatures on the claim and on `b`.
    pub fn request_wire(b: &WotsSig, claim: &WotsSig) -> Result<Vec<Vec<u8>>> {
        ensure!(claim.message().len() == POSTED_LEN, "a claim of {} bytes posted", claim.message().len());
        Ok(claim.consumption_order().into_iter().rev().chain(b.consumption_order().into_iter().rev()).collect())
    }
    /// Read `request`'s arguments (consumption order, below both
    /// signatures): her signatures on `b` and on the claim.
    pub fn read_request(args: &[Vec<u8>]) -> Result<(WotsSig, WotsSig)> {
        let (nb, nc) = (2 * WotsParams::for_bytes(4).total_digits() as usize, 2 * WotsParams::for_bytes(POSTED_LEN as u32).total_digits() as usize);
        ensure!(args.len() == nb + nc, "a request of {} arguments", args.len());
        let b = WotsSig::from_consumption_order(WotsParams::for_bytes(4), &args[..nb])?;
        let c = WotsSig::from_consumption_order(WotsParams::for_bytes(POSTED_LEN as u32), &args[nb..])?;
        Ok((b, c))
    }
    /// Her signature on `b` as the payout's leaves take it (bottom first:
    /// each digit's hash, then the digit); the hub's on `b_corr` likewise,
    /// as `correct` and `success`'s bit outputs take it.
    pub fn b_wire(b: &WotsSig) -> Vec<Vec<u8>> {
        b.consumption_order().into_iter().rev().collect()
    }
    /// `correct`'s: the slots' signatures, then the hub's on `b_corr`.
    pub fn correct_wire(b_corr: &WotsSig, slots: &[[u8; 64]]) -> Result<Vec<Vec<u8>>> {
        ensure!(slots.len() == SLOTS, "{} slot signatures, not {SLOTS}", slots.len());
        Ok(slots.iter().map(|s| s.to_vec()).chain(Self::b_wire(b_corr)).collect())
    }
    /// Read `correct`'s arguments (consumption order, below both
    /// signatures): the hub's signature on `b_corr`, and the slots'.
    pub fn read_correct(args: &[Vec<u8>]) -> Result<(WotsSig, Vec<[u8; 64]>)> {
        let n = 2 * WotsParams::for_bytes(4).total_digits() as usize;
        ensure!(args.len() == n + SLOTS, "a correct of {} arguments", args.len());
        let slots = args[n..].iter().rev().map(|s| s[..].try_into().context("a slot's signature of other than 64 bytes")).collect::<Result<_>>()?;
        Ok((WotsSig::from_consumption_order(WotsParams::for_bytes(4), &args[..n])?, slots))
    }
    /// `assert`'s: π1's digits, Lamport-signed, then π2 and π3.
    pub fn assert_wire(preimages: &[Preimage], pi2: &[u8], pi3: &[u8]) -> Vec<Vec<u8>> {
        [pi3.to_vec(), pi2.to_vec()].into_iter().chain(preimages.iter().rev().map(|p| p.to_vec())).collect()
    }
    /// Read `assert`'s arguments (consumption order, below both
    /// signatures): the preimages, π2, π3.
    pub fn read_assert(args: &[Vec<u8>]) -> Option<Asserted<'_>> {
        (args.len() == DIGITS + 2).then(|| (&args[..DIGITS], &args[DIGITS][..], &args[DIGITS + 1][..]))
    }
    /// `challenge_assert`'s: the reveal ([`crate::reveal::reveal_args`]).
    pub fn challenge_wire(args: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        args.into_iter().rev().collect()
    }
    /// `wrongly_challenged`'s: `msg`.
    pub fn wrongly_wire(msg: &[u8; 32]) -> Vec<Vec<u8>> {
        vec![msg.to_vec()]
    }
}

/// The digits of a word's one-time signature, as `wots_verify` leaves
/// them: whether bit `i` of the word is `want`, the digits dropped.
fn bit_check(b: Builder, i: u32, key: &WotsPublic, want: bool) -> Builder {
    let m = key.params.message_digits as usize;
    // digit k (0 the most significant nibble) sits at depth m - 1 - k
    let (nibble, j) = (7 - i / 4, i % 4);
    let mut b = b.wots_verify(key).push_int((m - 1 - nibble as usize) as i64).push_opcode(OP_PICK);
    // reduce the nibble mod 2^(j+1), then compare with 2^j
    for h in (j + 1..4).rev() {
        b = b.push_opcode(OP_DUP).push_int(1 << h).push_opcode(OP_GREATERTHANOREQUAL).push_opcode(OP_IF).push_int(1 << h).push_opcode(OP_SUB).push_opcode(OP_ENDIF);
    }
    b = b.push_int(1 << j).push_opcode(OP_GREATERTHANOREQUAL);
    if !want {
        b = b.push_opcode(OP_NOT);
    }
    b = b.push_opcode(OP_VERIFY);
    drop_n(b, m)
}

/// `success`'s output for bit `i` of `b_corr`, signed under the hub's
/// `key`: `alice_corr_bit_i` (her signature, the bit set), `hub_corr_bit_i`
/// (after `delta`, its signature, the bit clear: time for her to show an
/// equivocation), and `equiv_corr_i` (her signature and two different
/// signatures under `key`: the hub signed two values).
pub fn corr_bit_tree(ctx: &CommitCtx, i: u32, key: &WotsPublic) -> Result<TapTree> {
    assert_eq!(key.params.message_digits, 8, "a word's key signs 4 bytes");
    let alice = bit_check(Builder::new().checksigverify(&ctx.key(Role::User).payment), i, key, true);
    let delta = ctx.params.delta;
    let hub = bit_check(Builder::new().csv(delta).checksigverify(&ctx.key(Role::Hub).payment), i, key, false);
    let m = key.params.message_digits as usize;
    let mut e = Builder::new().push_int(i64::from(i)).push_opcode(OP_DROP).checksigverify(&ctx.key(Role::User).payment).wots_verify(key);
    for _ in 0..m {
        e = e.push_opcode(OP_TOALTSTACK);
    }
    e = e.wots_verify(key);
    for _ in 0..m {
        e = e.push_opcode(OP_FROMALTSTACK);
    }
    // count the digits that differ; at least one must
    e = e.push_int(0);
    for j in 0..m {
        e = e.push_int((m - j) as i64).push_opcode(OP_PICK).push_int((2 * m - j + 1) as i64).push_opcode(OP_PICK).push_opcode(OP_SUB).push_opcode(OP_0NOTEQUAL).push_opcode(OP_ADD);
    }
    e = e.push_opcode(OP_VERIFY);
    for _ in 0..m {
        e = e.push_opcode(OP_2DROP);
    }
    TapTree::new(vec![
        ok_leaf(&format!("alice_corr_bit_{i}"), alice, Timelock::NONE),
        ok_leaf(&format!("hub_corr_bit_{i}"), hub, Timelock::csv(delta)),
        ok_leaf(&format!("equiv_corr_{i}"), e, Timelock::NONE),
    ])
}
