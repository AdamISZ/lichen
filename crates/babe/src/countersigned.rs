//! The countersigned exit's graph (papers/lichen-grants-v0.4.1, §4–5):
//! BABE with the roles swapped, where the hub proves, and every value its
//! statement reads at exit time is under one of Alice's one-time keys.
//!
//! ```text
//! request (Alice: Q and b, her SHA-256 keys)
//!  ├─ request_timeout (after w_H)       → Alice: b
//!  └─ correct (the hub: b_corr and U, its HASH160 keys)
//!      ├─ accept (after w_A)            → Alice: b_corr (by the hub's
//!      │                                   signature), her reserve; the
//!      │                                   rest the hub's
//!      └─ ack (Alice: the hub's two signatures again, and hers on the
//!          │    same values, digit by digit equal)
//!          ├─ ack_timeout (after w_H)   → Alice: b
//!          └─ assert (the hub: π1, Lamport)
//!              ├─ success (after Δ2)    → Alice: b_corr, her reserve
//!              └─ challenge_assert (Alice)
//!                  ├─ wrongly_challenged_k → the hub
//!                  └─ failure (after Δ1)   → Alice: b
//! ```
//!
//! The payouts are v0.1's: `b`'s bit outputs read her signature under
//! `K_b` (now SHA-256: the statement checks it too), `b_corr`'s the hub's
//! under `K_corr` ([`corr_bit_tree`]). The keys whose values no bit output
//! reads (`K_Q`, `K_U`, `A_corr`, `A_U`) have no equivocation leaf.
//!
//! `ack` is the countersignature: script verifies the hub's signature on
//! a value and hers, and checks their digits equal, so she can only sign
//! what the hub posted. The hub's statement reads `b_corr` and `U` from
//! her signatures, not its own: a second signature of its own, off chain,
//! no one would see.

use anyhow::{ensure, Context, Result};
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
use lngap_lamport::winternitz::{Chain, Wots256Public, Wots256Sig, WotsExt, WotsParams, WotsPublic, WotsPublicOf, WotsSig, WotsSigOf};
use lngap_sessions::session::Terms;
use lngap_sessions::skeleton::{wots_shape, Core, Presign, POST_CSV};

use crate::reveal::{LamportPub, Preimage};
use crate::setup::{Hash, DIGITS, VALUES};

/// The posted claim `Q`'s length in bytes (v0.4.1 §5.1).
pub const Q_LEN: usize = 137;
/// The unlocks `U`: four 16-byte seeds.
pub const SEEDS: usize = 4;
pub const SEED_LEN: usize = 16;
pub const U_LEN: usize = SEEDS * SEED_LEN;

/// The dispute's windows, relative, in blocks: `w_H` for the hub's moves
/// (`correct`, `assert`), `w_A` for her `ack`, `Δ2` for her challenge,
/// `Δ1` for the hub's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Windows {
    pub w_h: u16,
    pub w_a: u16,
    pub delta2: u16,
    pub delta1: u16,
}

impl Windows {
    /// The longest a dispute can run after `request`, in blocks: its
    /// windows and each link's post lock.
    pub fn span(&self) -> u32 {
        2 * u32::from(self.w_h) + u32::from(self.w_a) + u32::from(self.delta2) + u32::from(self.delta1) + 5 * u32::from(POST_CSV)
    }
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

/// Drop `n` stack items.
fn drop_n(b: Builder, n: usize) -> Builder {
    let b = (0..n / 2).fold(b, |b, _| b.push_opcode(OP_2DROP));
    if n % 2 == 1 {
        b.push_opcode(OP_DROP)
    } else {
        b
    }
}

/// Verify a one-time signature and drop its message digits.
fn verify_drop<H: Chain>(b: Builder, key: &WotsPublicOf<H>) -> Builder {
    drop_n(b.wots_verify(key), key.params.message_digits as usize)
}

/// The countersignature: verify a signature under `first` (the hub's),
/// then one under `second` (hers), and check their message digits equal,
/// one by one. Consumes both; leaves nothing.
pub fn digits_equal<H1: Chain, H2: Chain>(b: Builder, first: &WotsPublicOf<H1>, second: &WotsPublicOf<H2>) -> Builder {
    let m = first.params.message_digits as usize;
    assert_eq!(second.params.message_digits as usize, m, "both keys sign the same length");
    // the first's digits to the altstack: d_0 ends on top
    let mut b = b.wots_verify(first);
    for _ in 0..m {
        b = b.push_opcode(OP_TOALTSTACK);
    }
    // the second's digits d'_0 … d'_{m-1}, d'_{m-1} on top; before step
    // j, d'_j … d'_{m-1} remain, and d_j, from the altstack, sits on them:
    // d'_j at depth m - j
    b = b.wots_verify(second);
    for j in 0..m {
        b = b.push_opcode(OP_FROMALTSTACK).push_int((m - j) as i64).push_opcode(OP_ROLL).push_opcode(OP_EQUALVERIFY);
    }
    b
}

/// A contract's graph: what both parties build it from.
#[derive(Clone, Debug)]
pub struct Spec {
    pub terms: Terms,
    pub params: ChannelParams,
    /// Alice's keys, then the hub's.
    pub pubs: [PartyPubKeys; 2],
    /// Alice's one-time keys in `request`: `K_b` (the payout's bit
    /// outputs read it) and `K_Q`; in `ack`, `A_corr` and `A_U`. SHA-256
    /// chains: the hub's statement verifies them.
    pub b_key: Wots256Public,
    pub q_key: Wots256Public,
    pub a_corr_key: Wots256Public,
    pub a_u_key: Wots256Public,
    /// The hub's one-time keys in `correct`: `K_corr` (the bit outputs of
    /// `accept` and `success` read it) and `K_U`. HASH160: only script
    /// reads them.
    pub corr_key: WotsPublic,
    pub u_key: WotsPublic,
    /// The hub's Lamport key for π1, in 2-bit digits, and its one-time
    /// adaptor keys, a digit and value.
    pub lamport: LamportPub,
    pub adaptor: Vec<[XOnlyPublicKey; VALUES]>,
    /// The kept instances' hashlocks, `SHA-256(msg)`: Alice's.
    pub hmsg: Vec<Hash>,
    pub windows: Windows,
}

/// A contract's graph.
pub struct Countersigned {
    pub spec: Spec,
}

impl Countersigned {
    pub fn new(spec: Spec) -> Result<Countersigned> {
        let word = WotsParams::for_bytes(4);
        ensure!(spec.b_key.params == word && spec.corr_key.params == word && spec.a_corr_key.params == word, "the keys for b and b_corr sign a 4-byte word");
        ensure!(spec.q_key.params == WotsParams::for_bytes(Q_LEN as u32), "K_Q signs {Q_LEN} bytes");
        let u = WotsParams::for_bytes(U_LEN as u32);
        ensure!(spec.u_key.params == u && spec.a_u_key.params == u, "the keys for U sign {U_LEN} bytes");
        ensure!(spec.lamport.0.len() == DIGITS && spec.adaptor.len() == DIGITS, "a Lamport and an adaptor key set per digit of π1");
        ensure!(!spec.hmsg.is_empty(), "a kept instance at least");
        let w = spec.windows;
        ensure!([w.w_h, w.w_a, w.delta1, w.delta2].iter().all(|&x| x > POST_CSV), "each window longer than a post's lock");
        Ok(Countersigned { spec })
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
    /// `to_self_delay`): her signatures on `b` and on `Q`.
    pub fn tree(&self) -> Result<TapTree> {
        let d = self.spec.params.to_self_delay;
        let (b, tl) = self.signed(if d > 0 { after(d) } else { (Builder::new(), Timelock::NONE) });
        let b = verify_drop(verify_drop(b, &self.spec.b_key), &self.spec.q_key);
        self.core().tree(ok_leaf("request", b, tl))
    }
    /// `request`'s output: the hub's `correct`, its signatures on `b_corr`
    /// and `U`; or, after `w_H`, `request_timeout`.
    pub fn requested(&self) -> Result<TapTree> {
        let (b, tl) = self.signed(after(POST_CSV));
        let correct = verify_drop(verify_drop(b, &self.spec.corr_key), &self.spec.u_key);
        let (t, ttl) = self.signed(after(self.spec.windows.w_h));
        TapTree::new(vec![ok_leaf("correct", correct, tl), ok_leaf("request_timeout", t, ttl)])
    }
    /// `correct`'s output: Alice's `ack`, the hub's two signatures again
    /// and hers on the same values; or, after `w_A`, `accept`.
    pub fn corrected(&self) -> Result<TapTree> {
        let (b, tl) = self.signed(after(POST_CSV));
        let s = &self.spec;
        let ack = digits_equal(digits_equal(b, &s.corr_key, &s.a_corr_key), &s.u_key, &s.a_u_key);
        let (t, ttl) = self.signed(after(s.windows.w_a));
        TapTree::new(vec![ok_leaf("ack", ack, tl), ok_leaf("accept", t, ttl)])
    }
    /// `ack`'s output: the hub's `assert`, π1's digits under its Lamport
    /// key, π2 and π3 beside them; or, after `w_H`, `ack_timeout`.
    pub fn acked(&self) -> Result<TapTree> {
        let (b, tl) = self.signed(after(POST_CSV));
        let assert = self.spec.lamport.verify(b).push_opcode(OP_2DROP);
        let (t, ttl) = self.signed(after(self.spec.windows.w_h));
        TapTree::new(vec![ok_leaf("assert", assert, tl), ok_leaf("ack_timeout", t, ttl)])
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
    /// The outputs paying `b` in bits and both reserves to Alice.
    pub fn pay_alice(&self, available: Amount) -> Result<Vec<TxOut>> {
        self.core().pay_alice(&self.spec.b_key, available)
    }
    /// `accept`'s and `success`'s outputs: for each bit `i` an output of
    /// `u 2^i`, Alice's iff bit `i` of the hub's signed `b_corr` is set
    /// ([`corr_bit_tree`]); Alice's reserve back to her; the rest the
    /// hub's (it bears the dispute's floors).
    pub fn pay_corrected(&self, available: Amount) -> Result<Vec<TxOut>> {
        let core = self.core();
        let (t, ctx) = (core.terms, core.ctx());
        let mut outs: Vec<TxOut> = (t.low_bits..t.bits).map(|i| Ok(TxOut { value: t.unit * (1u64 << i), script_pubkey: corr_bit_tree(&ctx, i, &self.spec.corr_key)?.script_pubkey() })).collect::<Result<_>>()?;
        let paid: Amount = outs.iter().map(|o| o.value).sum();
        outs.push(TxOut { value: t.reserve_alice, script_pubkey: self.spec.pubs[0].payout_spk.clone() });
        let rest = available.checked_sub(paid + t.reserve_alice).context("a payout of b_corr can't pay V_max and Alice's reserve")?;
        if rest >= ctx.params.dust {
            outs.push(TxOut { value: rest, script_pubkey: self.spec.pubs[1].payout_spk.clone() });
        }
        Ok(outs)
    }
    /// Who posts link `name`.
    pub fn poster(name: &str) -> Role {
        match name {
            "request" | "ack" | "challenge_assert" => Role::User,
            _ => Role::Hub,
        }
    }
    /// A witness of link `name`'s shape, for its floor.
    fn shape(&self, name: &str) -> Vec<Vec<u8>> {
        let s = &self.spec;
        match name {
            "request" => wots_shape([&s.q_key, &s.b_key]),
            "correct" => wots_shape([&s.u_key, &s.corr_key]),
            "ack" => wots_shape([&s.u_key, &s.corr_key]).into_iter().chain(wots_shape([&s.a_u_key, &s.a_corr_key])).collect(),
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
        type Terminal<'a> = &'a dyn Fn(&Countersigned, Amount) -> Result<Vec<TxOut>>;
        let alice: Terminal = &|g, v| g.pay_alice(v);
        let corrected: Terminal = &|g, v| g.pay_corrected(v);
        let chain: [(&str, TapTree, &str, Terminal); 5] = [
            ("request", self.requested()?, "request_timeout", alice),
            ("correct", self.corrected()?, "accept", corrected),
            ("ack", self.acked()?, "ack_timeout", alice),
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

    /// Link `name`'s sighash in `set` (its one input, by its leaf, the
    /// default sighash): `challenge_assert`'s is what the hub's adaptor
    /// pre-signatures sign.
    pub fn link_sighash(set: &[Presign], name: &str) -> Result<Message> {
        let p = set.iter().find(|p| p.name == name).with_context(|| format!("no {name}"))?;
        tapscript_sighash(&p.tx, 0, std::slice::from_ref(&p.prevout), &p.leaf)
    }

    // ----- the links' witnesses, below both signatures -----

    /// One-time signatures as a leaf takes them, `sigs` in the order its
    /// script verifies them: the wire lists the last-verified bottom
    /// first.
    fn wire_of(sigs: &[Vec<Vec<u8>>]) -> Vec<Vec<u8>> {
        sigs.iter().rev().flat_map(|c| c.iter().rev().cloned()).collect()
    }
    /// Read `n` signatures' consumption orders off `args` (consumption
    /// order, below both signatures), of `params` each.
    fn read_sigs(args: &[Vec<u8>], params: &[WotsParams]) -> Result<Vec<Vec<Vec<u8>>>> {
        let need: usize = params.iter().map(|p| 2 * p.total_digits() as usize).sum();
        ensure!(args.len() == need, "{} arguments, not {need}", args.len());
        let mut at = 0;
        Ok(params
            .iter()
            .map(|p| {
                let n = 2 * p.total_digits() as usize;
                at += n;
                args[at - n..at].to_vec()
            })
            .collect())
    }
    fn sig_of<H: Chain>(params: WotsParams, items: &[Vec<u8>]) -> Result<WotsSigOf<H>> {
        WotsSigOf::<H>::from_consumption_order(params, items)
    }

    /// `request`'s: her signatures on `b` and on `Q`.
    pub fn request_wire(b: &Wots256Sig, q: &Wots256Sig) -> Result<Vec<Vec<u8>>> {
        ensure!(q.message().len() == Q_LEN, "a Q of {} bytes", q.message().len());
        Ok(Self::wire_of(&[b.consumption_order(), q.consumption_order()]))
    }
    /// Read `request`'s arguments: her signatures on `b` and on `Q`.
    pub fn read_request(args: &[Vec<u8>]) -> Result<(Wots256Sig, Wots256Sig)> {
        let (w, q) = (WotsParams::for_bytes(4), WotsParams::for_bytes(Q_LEN as u32));
        let s = Self::read_sigs(args, &[w, q])?;
        Ok((Self::sig_of(w, &s[0])?, Self::sig_of(q, &s[1])?))
    }
    /// `correct`'s: the hub's signatures on `b_corr` and on `U`.
    pub fn correct_wire(b_corr: &WotsSig, u: &WotsSig) -> Result<Vec<Vec<u8>>> {
        ensure!(u.message().len() == U_LEN, "a U of {} bytes", u.message().len());
        Ok(Self::wire_of(&[b_corr.consumption_order(), u.consumption_order()]))
    }
    /// Read `correct`'s arguments: the hub's signatures on `b_corr` and
    /// on `U`.
    pub fn read_correct(args: &[Vec<u8>]) -> Result<(WotsSig, WotsSig)> {
        let (w, u) = (WotsParams::for_bytes(4), WotsParams::for_bytes(U_LEN as u32));
        let s = Self::read_sigs(args, &[w, u])?;
        Ok((Self::sig_of(w, &s[0])?, Self::sig_of(u, &s[1])?))
    }
    /// `ack`'s: the hub's signature on `b_corr` and hers, then the hub's
    /// on `U` and hers.
    pub fn ack_wire(hub_corr: &WotsSig, a_corr: &Wots256Sig, hub_u: &WotsSig, a_u: &Wots256Sig) -> Vec<Vec<u8>> {
        Self::wire_of(&[hub_corr.consumption_order(), a_corr.consumption_order(), hub_u.consumption_order(), a_u.consumption_order()])
    }
    /// Read `ack`'s arguments: her signatures on `b_corr` and on `U`.
    pub fn read_ack(args: &[Vec<u8>]) -> Result<(Wots256Sig, Wots256Sig)> {
        let (w, u) = (WotsParams::for_bytes(4), WotsParams::for_bytes(U_LEN as u32));
        let s = Self::read_sigs(args, &[w, w, u, u])?;
        Ok((Self::sig_of(w, &s[1])?, Self::sig_of(u, &s[3])?))
    }
    /// A word's signature as a bit output's leaf takes it (bottom first).
    pub fn word_wire<H: Chain>(sig: &WotsSigOf<H>) -> Vec<Vec<u8>> {
        sig.consumption_order().into_iter().rev().collect()
    }
    /// `assert`'s: π1's digits, Lamport-signed, then π2 and π3.
    pub fn assert_wire(preimages: &[Preimage], pi2: &[u8], pi3: &[u8]) -> Vec<Vec<u8>> {
        [pi3.to_vec(), pi2.to_vec()].into_iter().chain(preimages.iter().rev().map(|p| p.to_vec())).collect()
    }
    /// Read `assert`'s arguments: the preimages, π2, π3.
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

/// A payout of `b_corr`'s output for bit `i`, signed under the hub's
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
