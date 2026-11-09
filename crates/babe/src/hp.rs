//! BABE's graph with the roles swapped, for the exit where only the hub
//! proves (docs/HUB_PROVES_PLAN.md, "On chain"): Alice claims, the hub
//! asserts a proof that her claim is false or lets her timeout pay her.
//!
//! ```text
//! request (Alice: b, E, the claim)
//!  ├─ request_timeout (after w_H)      → Alice: b
//!  └─ assert (the hub: π1, Lamport)
//!      ├─ success (after Δ2)           → the hub: the contract
//!      └─ challenge_assert (Alice)
//!          ├─ wrongly_challenged_k     → the hub (its proof was valid)
//!          └─ failure (after Δ1)       → Alice: b
//! ```
//!
//! `success` and `failure` are the prover's, as in BABE: the prover is
//! the hub here. Alice garbled the kept instances (`hmsg` their
//! hashlocks), so she holds the input secrets and reveals π1's in her
//! challenge, by completing the hub's adaptor pre-signatures; the hub
//! evaluates them and answers with a `msg`. The hub keeps its signature
//! on `wrongly_challenged` from her ([`HubProves::withheld`]), as Alice
//! does of hers in [`crate::graph`]: she knows every `msg` and could post
//! it herself, large and at a low fee rate, and pin the hub's own.
//!
//! The contract output's `request` leaf is the exit's of
//! [`crate::graph`]: her signatures on `b` and `E`, and the claim posted
//! below them (the hub's statement reads it, `lichen_withdraw::hp`).

use anyhow::{ensure, Context, Result};
use lichen_withdraw::hp::{posted_items, POSTED_ITEM, POSTED_ITEMS};
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

use crate::graph::{after, drop_digits, drop_n, ok_leaf, Windows, E_DIGITS};
use crate::reveal::{LamportPub, Preimage};
use crate::setup::{Hash, DIGITS, VALUES};

/// A contract of the swapped game: what both parties build its graph
/// from.
#[derive(Clone, Debug)]
pub struct Spec {
    pub terms: Terms,
    pub params: ChannelParams,
    /// Alice's keys, then the hub's.
    pub pubs: [PartyPubKeys; 2],
    /// Alice's one-time keys for `b` (the payout's bit outputs read it)
    /// and for `E`.
    pub b_key: WotsPublic,
    pub e_key: WotsPublic,
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
        ensure!(spec.e_key.params == WotsParams::for_bytes(32), "the key for E signs 32 bytes");
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
    /// `to_self_delay`): her signatures on `b` and `E`, the claim posted
    /// below them, unchecked (the hub's statement reads it).
    pub fn tree(&self) -> Result<TapTree> {
        let d = self.spec.params.to_self_delay;
        let (b, tl) = self.signed(if d > 0 { after(d) } else { (Builder::new(), Timelock::NONE) });
        let b = drop_digits(b.wots_verify(&self.spec.b_key));
        let b = drop_n(drop_n(b.wots_verify(&self.spec.e_key), E_DIGITS), POSTED_ITEMS);
        self.core().tree(ok_leaf("request", b, tl))
    }
    /// `request`'s output: the hub's `assert`, π1's digits under its
    /// Lamport key, π2 and π3 beside them (so that Alice can check the
    /// whole proof from the chain); or, after `w_H`, `request_timeout`.
    pub fn requested(&self) -> Result<TapTree> {
        let (b, tl) = self.signed(after(POST_CSV));
        let assert = self.spec.lamport.verify(b).push_opcode(OP_2DROP);
        let (t, ttl) = self.signed(after(self.spec.windows.w_h));
        TapTree::new(vec![ok_leaf("assert", assert, tl), ok_leaf("request_timeout", t, ttl)])
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
    /// Who posts link `name`.
    pub fn poster(name: &str) -> Role {
        match name {
            "request" | "challenge_assert" => Role::User,
            _ => Role::Hub,
        }
    }
    /// A witness of link `name`'s shape, for its floor: `request` with the
    /// largest claim.
    fn shape(&self, name: &str) -> Vec<Vec<u8>> {
        match name {
            "request" => {
                let posted = vec![0u8; POSTED_ITEMS * POSTED_ITEM];
                posted_items(&posted).expect("fits").into_iter().map(<[u8]>::to_vec).chain(wots_shape([&self.spec.e_key, &self.spec.b_key])).collect()
            }
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
        let hub: Terminal = &|g, v| Ok(g.core().pay_hub(v));
        let chain: [(&str, TapTree, &str, Terminal); 3] = [
            ("request", self.requested()?, "request_timeout", alice),
            ("assert", self.asserted()?, "success", hub),
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
        let p = set.iter().find(|p| p.name == "challenge_assert").context("no challenge_assert")?;
        tapscript_sighash(&p.tx, 0, std::slice::from_ref(&p.prevout), &p.leaf)
    }

    // ----- the links' witnesses, below both signatures -----

    /// `request`'s: the claim as posted (in [`POSTED_ITEMS`] items of up
    /// to [`POSTED_ITEM`] bytes, its first items), then her signatures on
    /// `E` and on `b`.
    pub fn request_wire(b: &WotsSig, e: &WotsSig, posted: &[u8]) -> Result<Vec<Vec<u8>>> {
        let items = posted_items(posted).with_context(|| format!("a claim of {} bytes posted", posted.len()))?;
        Ok(items.into_iter().map(<[u8]>::to_vec).chain(e.consumption_order().into_iter().rev()).chain(b.consumption_order().into_iter().rev()).collect())
    }
    /// Read `request`'s arguments (consumption order, below both
    /// signatures): her signatures on `b` and `E`, and the claim as posted.
    pub fn read_request(args: &[Vec<u8>]) -> Result<(WotsSig, WotsSig, Vec<u8>)> {
        let (nb, ne) = (2 * WotsParams::for_bytes(4).total_digits() as usize, 2 * WotsParams::for_bytes(32).total_digits() as usize);
        ensure!(args.len() == nb + ne + POSTED_ITEMS, "a request of {} arguments", args.len());
        let b = WotsSig::from_consumption_order(WotsParams::for_bytes(4), &args[..nb])?;
        let e = WotsSig::from_consumption_order(WotsParams::for_bytes(32), &args[nb..nb + ne])?;
        Ok((b, e, args[nb + ne..].iter().rev().flatten().copied().collect()))
    }
    /// `assert`'s: π1's digits, Lamport-signed, then π2 and π3.
    pub fn assert_wire(preimages: &[Preimage], pi2: &[u8], pi3: &[u8]) -> Vec<Vec<u8>> {
        crate::graph::Babe::assert_wire(preimages, pi2, pi3)
    }
}
