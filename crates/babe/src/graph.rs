//! BABE's transaction graph on ln-gap's skeleton (docs/BABE_GADGET_PLAN.md
//! step 2; papers/lichen-babe §6).
//!
//! One chain carries the contract's value from the contract output:
//! `request` (Alice signs `b`), `respond` (the hub signs `b` too, and the
//! script checks the two agree), `assert` (π1, Lamport-signed in 2-bit
//! digits), `challenge_assert` (the hub reveals π1's secrets,
//! [`crate::reveal`]). Each output of the chain also has its terminal,
//! which a party takes when the other doesn't move: `request_timeout`
//! (after `w_H`, Alice paid her `b`), `respond_timeout` (from `T_A`, the
//! hub), `success` (after `Δ2`, Alice), `failure` (after `Δ1`, the hub).
//! Against the challenge Alice posts `wrongly_challenged_k`, `msg` of a
//! kept instance `k`, which pays her `b` in bits. (A terminal can't pay
//! into a pre-signed transaction: its broadcaster adds a fee input, which
//! changes its id.)
//!
//! BABE's own graph (its Appendix A.1) keeps the deposit apart and joins
//! it to the proving phase's connectors, `failure` spending three outputs,
//! because there `assert` starts from an outside coin. Here the dispute
//! starts from the contract output, so the value flows through one chain
//! and every transaction has one input. A challenge spends `success`'s
//! output, so the two can't race, and `Δ2 > Δ1 + 2u` is not needed.
//!
//! With the exit (docs/EXIT_PLAN.md, "Under BABE"; [`ExitKeys`]),
//! `request` also carries Alice's signature on her claim's fingerprint
//! `E` and the claim as posted (`lichen_withdraw::exit::Posted`, in its
//! first witness items), and `respond` has two leaves, one transaction:
//! `respond` (plain: the hub signs `E` under its plain key) and
//! `respond_counter` (`E` under its counter key, and the counter `K`
//! itself). Both check the hub's `E` digit for digit against Alice's, as
//! `b`'s. Which key signed `E` tells the statement which leaf ran.
//!
//! `wrongly_challenged` is 2-of-2, as every leaf here, so that its output
//! is fixed; but Alice keeps her signature on it from the hub
//! ([`Babe::withheld`]), for her towers only. The hub, which knows `msg`,
//! could otherwise post it itself, large and at a low fee rate, and pin
//! Alice's own until `failure` (papers/lichen-babe §7). It is TRUC
//! (version 3), which bounds what a tower holding it could pin with.

use anyhow::{ensure, Context, Result};
use lichen_withdraw::exit::{posted_items, POSTED_ITEMS};
use lichen_withdraw::fixed::K_LEN;
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
use lngap_lamport::winternitz::{Wots256Public, Wots256Sig, WotsExt, WotsParams, WotsPublic, WotsSig};
use lngap_sessions::session::Terms;
use lngap_sessions::skeleton::{wots_shape, Core, Presign, POST_CSV};

use crate::reveal::{LamportPub, Preimage};
use crate::setup::{Hash, DIGITS, VALUES};

/// The dispute's windows: `w_H` for the hub's `respond`, the absolute
/// deadline `T_A` for Alice's `assert`, `Δ2` for the hub's challenge,
/// `Δ1` for Alice's answer to it. Relative windows in blocks; `T_A` as
/// `T_close` is (a height, or a time from 500,000,000).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Windows {
    pub w_h: u16,
    pub t_a: u32,
    pub delta2: u16,
    pub delta1: u16,
}

/// A BABE contract: what both parties build its graph from.
#[derive(Clone, Debug)]
pub struct Spec {
    pub terms: Terms,
    pub params: ChannelParams,
    /// Alice's keys, then the hub's.
    pub pubs: [PartyPubKeys; 2],
    /// Alice's one-time key for `b` (`request`'s signature; the payout's
    /// bit outputs read it).
    pub b_key: WotsPublic,
    /// The hub's one-time key for `b`, SHA-256 chains: the key `pk_H`
    /// whose digest the statement's journal commits.
    pub hub_b: Wots256Public,
    /// Alice's Lamport key for π1, in 2-bit digits.
    pub lamport: LamportPub,
    /// Alice's one-time adaptor keys, a digit and value.
    pub adaptor: Vec<[XOnlyPublicKey; VALUES]>,
    /// The kept instances' hashlocks, `SHA-256(msg)`.
    pub hmsg: Vec<Hash>,
    pub windows: Windows,
    /// The exit's keys; none for a graph of returns only.
    pub exit: Option<ExitKeys>,
}

/// The exit's keys: Alice's one-time key for `E` (`request`'s second
/// signature, 32 bytes), and the hub's for `respond`, SHA-256 chains (the
/// statement checks them, `lichen_withdraw::fixed::ExitKeys`): `E` in the
/// plain leaf, `E` in the counter leaf, and `K` (`K_LEN` bytes).
#[derive(Clone, Debug)]
pub struct ExitKeys {
    pub e_key: WotsPublic,
    pub hub_e_plain: Wots256Public,
    pub hub_e_counter: Wots256Public,
    pub hub_k: Wots256Public,
}

/// `assert`'s arguments: the preimages, π2, π3.
pub type Asserted<'a> = (&'a [Vec<u8>], &'a [u8], &'a [u8]);

/// A contract's graph.
pub struct Babe {
    pub spec: Spec,
}

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

/// `E`'s 64 digits (32 bytes).
const E_DIGITS: usize = 64;

impl Babe {
    pub fn new(spec: Spec) -> Result<Babe> {
        let word = WotsParams::for_bytes(4);
        ensure!(spec.b_key.params == word && spec.hub_b.params == word, "the keys for b sign a 4-byte word");
        ensure!(spec.lamport.0.len() == DIGITS && spec.adaptor.len() == DIGITS, "a Lamport and an adaptor key set per digit of π1");
        ensure!(!spec.hmsg.is_empty(), "a kept instance at least");
        let w = spec.windows;
        ensure!(w.w_h > POST_CSV && w.delta1 > POST_CSV && w.delta2 > POST_CSV, "each window longer than a post's lock");
        ensure!(w.t_a < spec.terms.t_close, "T_A before T_close");
        if let Some(x) = &spec.exit {
            let e = WotsParams::for_bytes(32);
            ensure!(x.e_key.params == e && x.hub_e_plain.params == e && x.hub_e_counter.params == e, "the keys for E sign 32 bytes");
            ensure!(x.hub_k.params == WotsParams::for_bytes(K_LEN as u32), "the key for K signs {K_LEN} bytes");
        }
        Ok(Babe { spec })
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
    /// The 2-of-2 every leaf starts with, after `lock` if any.
    fn signed(&self, (b, tl): (Builder, Timelock)) -> (Builder, Timelock) {
        (self.ctx().two_of_two_verify(b), tl)
    }

    /// The contract output's tree: `fold`, `default`, and `request`, Alice's
    /// signature on `b` (after the channel's `to_self_delay`, as BitVMX's
    /// `escalate`); with the exit, her signature on `E` too, and the claim
    /// posted below them, unchecked (the statement checks it).
    pub fn tree(&self) -> Result<TapTree> {
        let d = self.spec.params.to_self_delay;
        let (b, tl) = self.signed(if d > 0 { after(d) } else { (Builder::new(), Timelock::NONE) });
        let mut b = drop_digits(b.wots_verify(&self.spec.b_key));
        if let Some(x) = &self.spec.exit {
            b = drop_n(drop_n(b.wots_verify(&x.e_key), E_DIGITS), POSTED_ITEMS);
        }
        self.core().tree(ok_leaf("request", b, tl))
    }
    /// A `respond` leaf's check of `E`: Alice's signature (from `request`)
    /// leaves its digits, and the hub's under `key` is verified tied to
    /// them, so on the same `E`.
    fn same_e(b: Builder, alice: &WotsPublic, key: &Wots256Public) -> Builder {
        let pos: Vec<usize> = (0..E_DIGITS).collect();
        drop_n(b.wots_verify(alice).wots_verify_tied(key, E_DIGITS, &pos), E_DIGITS)
    }
    /// `request`'s output: the hub's `respond`, the two signatures on `b`
    /// digit by digit equal; or, after `w_H`, `request_timeout`. With the
    /// exit, `respond` checks `E` the same way under the hub's plain key,
    /// and `respond_counter` under its counter key, with its signature on
    /// `K`.
    pub fn requested(&self) -> Result<TapTree> {
        let respond = || {
            let (mut b, tl) = self.signed(after(POST_CSV));
            b = b.wots_verify(&self.spec.hub_b);
            b = (0..8).fold(b, |b, _| b.push_opcode(OP_TOALTSTACK)).wots_verify(&self.spec.b_key);
            b = (0..8).fold(b, |b, _| b.push_opcode(OP_FROMALTSTACK));
            // Alice's digits a_0..a_7 below the hub's h_0..h_7: a_k is k + 1
            // deep under h_k
            b = (1..=8).rev().fold(b, |b, k| b.push_int(k).push_opcode(OP_ROLL).push_opcode(OP_NUMEQUALVERIFY));
            (b, tl)
        };
        let (t, ttl) = self.signed(after(self.spec.windows.w_h));
        let (b, tl) = respond();
        let mut leaves = vec![];
        match &self.spec.exit {
            None => leaves.push(ok_leaf("respond", b, tl)),
            Some(x) => {
                leaves.push(ok_leaf("respond", Self::same_e(b, &x.e_key, &x.hub_e_plain), tl));
                let (b, tl) = respond();
                let b = Self::same_e(b, &x.e_key, &x.hub_e_counter).wots_verify(&x.hub_k);
                leaves.push(ok_leaf("respond_counter", drop_n(b, 2 * K_LEN), tl));
            }
        }
        leaves.push(ok_leaf("request_timeout", t, ttl));
        TapTree::new(leaves)
    }
    /// `respond`'s output: Alice's `assert`, π1's digits under her Lamport
    /// key, then π2 and π3, unsigned (so that the hub can check the whole
    /// proof from the chain); or, from `T_A`, `respond_timeout`.
    pub fn responded(&self) -> Result<TapTree> {
        let (b, tl) = self.signed(after(POST_CSV));
        let t_a = self.spec.windows.t_a;
        let timeout = self.ctx().two_of_two_verify(Builder::new().cltv(t_a));
        let assert = self.spec.lamport.verify(b).push_opcode(OP_2DROP);
        TapTree::new(vec![ok_leaf("assert", assert, tl), ok_leaf("respond_timeout", timeout, Timelock::cltv(t_a))])
    }
    /// `assert`'s output: the hub's `challenge_assert`, the reveal; or,
    /// after `Δ2`, `success`.
    pub fn asserted(&self) -> Result<TapTree> {
        let (b, tl) = self.signed(after(POST_CSV));
        let b = crate::reveal::reveal_verify(b, &self.spec.lamport, &self.spec.adaptor);
        let (s, stl) = self.signed(after(self.spec.windows.delta2));
        TapTree::new(vec![ok_leaf("challenge_assert", b, tl), ok_leaf("success", s, stl)])
    }
    /// `challenge_assert`'s output: Alice's `wrongly_challenged_k`, a kept
    /// instance's `msg`; or, after `Δ1`, `failure`.
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
    /// The outputs paying `b` in bits and the reserves to Alice
    /// ([`Core::pay_alice`]).
    pub fn pay_alice(&self, available: Amount) -> Result<Vec<TxOut>> {
        self.core().pay_alice(&self.spec.b_key, available)
    }
    /// Who posts link `name`.
    pub fn poster(name: &str) -> Role {
        match name {
            "request" | "assert" => Role::User,
            _ => Role::Hub,
        }
    }
    /// A witness of link `name`'s shape, for its floor: with the exit, its
    /// largest (`respond_counter`'s for `respond`, the largest claim for
    /// `request`).
    fn shape(&self, name: &str) -> Vec<Vec<u8>> {
        let wots256 = |k: &Wots256Public| (0..k.params.total_digits()).flat_map(|_| [vec![0u8; 32], vec![15u8]]).collect::<Vec<_>>();
        match (name, &self.spec.exit) {
            ("request", None) => wots_shape([&self.spec.b_key]),
            ("request", Some(x)) => {
                let posted = 8 + 32 + 1 + lichen_withdraw::exit::MAX_NOTES * (1 + 76 + 64);
                posted_items(&vec![0u8; posted])
                    .expect("the largest claim fits")
                    .into_iter()
                    .map(<[u8]>::to_vec)
                    .chain(wots_shape([&x.e_key, &self.spec.b_key]))
                    .collect()
            }
            ("respond", exit) => {
                let mut w = wots256(&self.spec.hub_b).into_iter().chain(wots_shape([&self.spec.b_key])).collect::<Vec<_>>();
                if let Some(x) = exit {
                    let e = &x.hub_e_counter.params;
                    w.extend(wots_shape([&x.e_key]));
                    w.extend((0..e.total_digits()).map(|_| vec![0u8; 32]).chain((0..e.checksum_digits).map(|_| vec![15u8])));
                    w.extend(wots256(&x.hub_k));
                }
                w
            }
            ("assert", _) => vec![vec![0u8; 20]; DIGITS].into_iter().chain([vec![0u8; 64], vec![0u8; 32]]).collect(),
            _ => (0..DIGITS).flat_map(|_| [vec![0u8; 20], vec![0u8; 64]]).collect(),
        }
    }
    fn link(&self, name: &str, prev: &TapTree, op: OutPoint, prev_out: &TxOut, next: &TapTree) -> Result<Presign> {
        // with the exit, `respond`'s floor is for its counter leaf, the
        // larger, so that both leaves spend into one transaction
        let leaf = if name == "respond" && self.spec.exit.is_some() { "respond_counter" } else { name };
        let mut p = self.core().link(name, Self::poster(name), self.shape(name), prev, leaf, op, prev_out, next.script_pubkey())?;
        if leaf != name {
            let plain = Presign::new(name, prev, name, op, prev_out, p.tx.output.clone(), true)?;
            ensure!(plain.tx == p.tx, "respond's leaves spend into one transaction");
            (p.leaf, p.control) = (plain.leaf, plain.control);
        }
        Ok(p)
    }

    /// Every transaction the parties pre-sign, the contract output at
    /// `funding`: the default; the chain and each output's terminal; per
    /// kept instance, `wrongly_challenged_k`.
    pub fn presign(&self, funding: OutPoint) -> Result<Vec<Presign>> {
        let tree = self.tree()?;
        let c_out = TxOut { value: self.value(), script_pubkey: tree.script_pubkey() };
        let mut out = vec![self.core().default_tx(&tree, funding)?];
        let (mut prev, mut op, mut prev_out) = (tree, funding, c_out);
        type Terminal<'a> = &'a dyn Fn(&Babe, Amount) -> Result<Vec<TxOut>>;
        let alice: Terminal = &|b, v| b.pay_alice(v);
        let hub: Terminal = &|b, v| Ok(b.core().pay_hub(v));
        let chain: [(&str, TapTree, &str, Terminal); 4] = [
            ("request", self.requested()?, "request_timeout", alice),
            ("respond", self.responded()?, "respond_timeout", hub),
            ("assert", self.asserted()?, "success", alice),
            ("challenge_assert", self.challenged()?, "failure", hub),
        ];
        for (name, next, terminal, pay) in chain {
            let link = self.link(name, &prev, op, &prev_out, &next)?;
            let n_out = link.tx.output[0].clone();
            let counter = (name == "respond" && self.spec.exit.is_some())
                .then(|| Presign::new("respond_counter", &prev, "respond_counter", op, &prev_out, link.tx.output.clone(), true))
                .transpose()?;
            op = OutPoint { txid: link.tx.compute_txid(), vout: 0 };
            out.push(link);
            out.extend(counter);
            out.push(Presign::new(terminal, &next, terminal, op, &n_out, pay(self, n_out.value)?, false)?);
            (prev, prev_out) = (next, n_out);
        }
        // against the challenge: a kept instance's msg
        for k in 0..self.spec.hmsg.len() {
            let name = format!("wrongly_challenged_{k}");
            let mut w = Presign::new(&name, &prev, &name, op, &prev_out, self.pay_alice(prev_out.value)?, false)?;
            w.tx.version = Version::non_standard(3);
            out.push(w);
        }
        Ok(out)
    }

    /// Whether Alice keeps her signature on `name` from the hub.
    pub fn withheld(name: &str) -> bool {
        name.starts_with("wrongly_challenged_")
    }

    /// `challenge_assert`'s sighash in `set`, which Alice's adaptor
    /// pre-signatures sign.
    pub fn challenge_sighash(set: &[Presign]) -> Result<Message> {
        let p = set.iter().find(|p| p.name == "challenge_assert").context("no challenge_assert")?;
        tapscript_sighash(&p.tx, 0, std::slice::from_ref(&p.prevout), &p.leaf)
    }

    // ----- the links' witnesses, below both signatures -----

    /// `request`'s: Alice's signature on `b`.
    pub fn request_wire(b: &WotsSig) -> Vec<Vec<u8>> {
        b.consumption_order().into_iter().rev().collect()
    }
    /// `request`'s with the exit: the claim as posted (`posted`, in
    /// [`POSTED_ITEMS`] items of up to `POSTED_ITEM` bytes, its first
    /// items), then
    /// Alice's signature on `E`, then on `b`.
    pub fn request_exit_wire(b: &WotsSig, e: &WotsSig, posted: &[u8]) -> Result<Vec<Vec<u8>>> {
        let items = posted_items(posted).with_context(|| format!("a claim of {} bytes posted", posted.len()))?;
        Ok(items.into_iter().map(<[u8]>::to_vec).chain(e.consumption_order().into_iter().rev()).chain(Self::request_wire(b)).collect())
    }
    /// Read `request`'s arguments with the exit (consumption order, below
    /// both signatures): Alice's signatures on `b` and `E`, and the claim
    /// as posted.
    pub fn read_request_exit(args: &[Vec<u8>]) -> Result<(WotsSig, WotsSig, Vec<u8>)> {
        let (nb, ne) = (2 * WotsParams::for_bytes(4).total_digits() as usize, 2 * WotsParams::for_bytes(32).total_digits() as usize);
        ensure!(args.len() == nb + ne + POSTED_ITEMS, "a request of {} arguments", args.len());
        let b = WotsSig::from_consumption_order(WotsParams::for_bytes(4), &args[..nb])?;
        let e = WotsSig::from_consumption_order(WotsParams::for_bytes(32), &args[nb..nb + ne])?;
        Ok((b, e, args[nb + ne..].iter().rev().flatten().copied().collect()))
    }
    /// `respond`'s: the hub's signature on `b`, consumed first, then
    /// Alice's (from `request`).
    pub fn respond_wire(hub: &Wots256Sig, alice: &WotsSig) -> Vec<Vec<u8>> {
        hub.consumption_order().into_iter().chain(alice.consumption_order()).rev().collect()
    }
    /// `respond`'s with the exit: as [`Babe::respond_wire`], then Alice's
    /// signature on `E` (from `request`) and the hub's, tied to it (its
    /// reveals, and its checksum digits); for `respond_counter`, then the
    /// hub's signature on `K`.
    pub fn respond_exit_wire(hub_b: &Wots256Sig, alice_b: &WotsSig, alice_e: &WotsSig, hub_e: &Wots256Sig, k: Option<&Wots256Sig>) -> Vec<Vec<u8>> {
        let msg = hub_e.params.message_digits as usize;
        // the tied signature, bottom first: each reveal, a checksum digit's
        // value above its reveal
        let tied = hub_e
            .hashes
            .iter()
            .zip(&hub_e.digits)
            .enumerate()
            .flat_map(|(i, (h, d))| std::iter::once(h.to_vec()).chain((i >= msg).then(|| if *d == 0 { vec![] } else { vec![*d] })));
        let k = k.map(|k| k.consumption_order().into_iter().rev()).into_iter().flatten();
        k.chain(tied).chain(alice_e.consumption_order().into_iter().rev()).chain(Self::respond_wire(hub_b, alice_b)).collect()
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
