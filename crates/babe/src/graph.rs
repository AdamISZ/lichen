//! A contract's dispute graph: the L2's front, then BABE's tail with the
//! roles swapped (the hub proves).
//!
//! ```text
//! contract output (key path: the fold; leaves: default, and the front's
//! │                first link)
//! └─ front links (the L2's: request, and whatever its exit adds), each
//!     │          output with its terminal (a timeout paying the user,
//!     │          a correction's payout, ...)
//!     └─ assert (the hub: π1 under its Lamport key, π2 and π3)
//!         ├─ success (after Δ2)            → the front's choice
//!         └─ challenge_assert (the user: the reveal)
//!             ├─ wrongly_challenged_k      → the front's choice, the hub by
//!             │                              default (its proof was valid)
//!             └─ failure (after Δ1)        → the user: her claim
//! ```
//!
//! `success` and `failure` are the prover's, as in BABE, and the prover is
//! the hub. The user garbled the kept instances (`hmsg` their hashlocks),
//! so she holds the input secrets and reveals π1's in her challenge, by
//! completing the hub's adaptor pre-signatures; the hub evaluates them and
//! answers with a `msg`. The hub keeps its signature on
//! `wrongly_challenged` from her ([`Graph::withheld`]): she knows every
//! `msg` and could post it herself, large and at a low fee rate, and pin
//! the hub's own (papers/lichen-babe §7). It is TRUC (version 3), which
//! bounds what could pin with it.
//!
//! Every transaction has one input: the value flows through one chain from
//! the contract output, and each output of the chain has its terminal (a
//! terminal can't pay into a pre-signed transaction: its broadcaster adds
//! a fee input, which changes its id).
//!
//! An L2 describes its front with [`Front`]: its links (each spends the
//! output before it by a leaf of the L2's, and its own output has a
//! terminal), who gets what on each terminal, and what `success` pays.

use anyhow::{ensure, Context, Result};
use lichen_btc::bitcoin::opcodes::all::*;
use lichen_btc::bitcoin::script::Builder;
use lichen_btc::bitcoin::transaction::Version;
use lichen_btc::bitcoin::{Amount, OutPoint, Transaction, TxOut, Txid};
use lichen_btc::script::BuilderExt;
use lichen_btc::secp256k1::{Message, XOnlyPublicKey};
use lichen_btc::sighash::tapscript_sighash;
use lichen_btc::taptree::{Leaf, TapTree};
use lichen_btc::tx::Timelock;
use lichen_contract::{Core, ContractCtx, Presign, Role, POST_CSV};
use lichen_wots::{Chain, WotsExt, WotsPublicOf};

use crate::reveal::{LamportPub, Preimage};
use crate::setup::{Hash, DIGITS, VALUES};

/// BABE's tail windows, relative, in blocks: `Δ2` for her challenge, `Δ1`
/// for the hub's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Windows {
    pub delta2: u16,
    pub delta1: u16,
}

/// What BABE's tail is built from: the hub's Lamport key for π1 (2-bit
/// digits) and its one-time adaptor keys, a digit and value; the kept
/// instances' hashlocks, `SHA-256(msg)`; the windows.
#[derive(Clone, Debug)]
pub struct Tail {
    pub lamport: LamportPub,
    pub adaptor: Vec<[XOnlyPublicKey; VALUES]>,
    pub hmsg: Vec<Hash>,
    pub windows: Windows,
}

/// Who a terminal pays: the user's claim (her bit outputs read her
/// signature on `b`), everything to the hub, or another payout of the
/// front's, by name ([`Front::pay`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Payout {
    User,
    Hub,
    Other(&'static str),
}

/// A front link: its name and poster, the leaf (of the output before it)
/// it spends, a witness of its shape (each element's size, for its floor),
/// its fixed outputs after its anchor (`extra`: an L2's publication
/// slots, say; none of them dust, they come out of the value the chain
/// carries, [`Core::link_extra`]), and its own output's terminal: its
/// name, its window (relative) and what it pays.
pub struct FrontLink {
    pub name: &'static str,
    pub poster: Role,
    pub leaf: Leaf,
    pub shape: Vec<Vec<u8>>,
    pub extra: Vec<TxOut>,
    pub terminal: &'static str,
    pub window: u16,
    pub pays: Payout,
}

/// An L2's front: the links from the contract output to `assert`.
pub trait Front: Send + Sync {
    /// The contract's terms, parameters and both parties' keys.
    fn core(&self) -> Core<'_>;
    /// The links, the first spending the contract output (its leaf is the
    /// contract output's dispute leaf), the last's output what `assert`
    /// spends. Each leaf's name is its link's.
    fn links(&self) -> Result<Vec<FrontLink>>;
    /// A payout of the front's: the outputs of a terminal paying `which`
    /// from `available`. [`Payout::User`] and [`Payout::Hub`] included.
    fn pay(&self, which: Payout, available: Amount) -> Result<Vec<TxOut>>;
    /// What `success` pays (an assertion unchallenged).
    fn success(&self) -> Payout;
    /// What `wrongly_challenged_k` pays (the user challenged a valid
    /// proof): everything to the hub, by default, the cost of a challenge
    /// she could have known was wrong by checking the proof first.
    fn wrongly_challenged(&self) -> Payout {
        Payout::Hub
    }
}

/// `name`'s leaf: `b`, then `OP_1`.
pub fn ok_leaf(name: &str, b: Builder, timelock: Timelock) -> Leaf {
    Leaf::new(name, b.push_int(1).into_script(), timelock)
}

/// `Builder` with a relative lock, and the lock.
pub fn after(blocks: u16) -> (Builder, Timelock) {
    (Builder::new().csv(blocks), Timelock::csv(blocks))
}

/// Drop `n` stack items.
pub fn drop_n(b: Builder, n: usize) -> Builder {
    let b = (0..n / 2).fold(b, |b, _| b.push_opcode(OP_2DROP));
    if n % 2 == 1 {
        b.push_opcode(OP_DROP)
    } else {
        b
    }
}

/// Verify a one-time signature and drop its message digits.
pub fn verify_drop<H: Chain>(b: Builder, key: &WotsPublicOf<H>) -> Builder {
    drop_n(b.wots_verify(key), key.params.message_digits as usize)
}

/// The 2-of-2 every pre-signed path carries, after `b` (a lock).
pub fn signed(ctx: &ContractCtx, (b, tl): (Builder, Timelock)) -> (Builder, Timelock) {
    (ctx.two_of_two_verify(b), tl)
}

/// A front link's leaf, posted a block after the output before it (or,
/// for the first, `to_self_delay` after the funding): the 2-of-2, then
/// `script` on the link's own arguments.
pub fn link_leaf(ctx: &ContractCtx, name: &str, first: bool, script: impl FnOnce(Builder) -> Builder) -> Leaf {
    let lock = if first {
        let d = ctx.params.to_self_delay;
        if d > 0 {
            after(d)
        } else {
            (Builder::new(), Timelock::NONE)
        }
    } else {
        after(POST_CSV)
    };
    let (b, tl) = signed(ctx, lock);
    ok_leaf(name, script(b), tl)
}

/// A terminal's leaf, after `window`: the 2-of-2 alone.
fn terminal_leaf(ctx: &ContractCtx, name: &str, window: u16) -> Leaf {
    let (b, tl) = signed(ctx, after(window));
    ok_leaf(name, b, tl)
}

/// `assert`'s arguments: the preimages, π2, π3.
pub type Asserted<'a> = (&'a [Vec<u8>], &'a [u8], &'a [u8]);

/// A contract's graph: the L2's front, then the tail.
pub struct Graph {
    pub front: Box<dyn Front>,
    pub tail: Tail,
}

impl Graph {
    pub fn new(front: Box<dyn Front>, tail: Tail) -> Result<Graph> {
        ensure!(tail.lamport.0.len() == DIGITS && tail.adaptor.len() == DIGITS, "a Lamport and an adaptor key set per digit of π1");
        ensure!(!tail.hmsg.is_empty(), "a kept instance at least");
        ensure!(tail.windows.delta1 > POST_CSV && tail.windows.delta2 > POST_CSV, "each window longer than a post's lock");
        let g = Graph { front, tail };
        let links = g.front.links()?;
        ensure!(!links.is_empty(), "a front of one link at least");
        for l in &links {
            ensure!(l.leaf.name == l.name && l.window > POST_CSV, "{}: its leaf named as the link, its terminal's window longer than a post's lock", l.name);
        }
        Ok(g)
    }
    pub fn core(&self) -> Core<'_> {
        self.front.core()
    }
    fn ctx(&self) -> ContractCtx<'_> {
        self.core().ctx()
    }
    pub fn value(&self) -> Amount {
        self.core().value()
    }

    /// The contract output's tree: the parties' MuSig2 key (the fold), the
    /// default, and the front's first link.
    pub fn tree(&self) -> Result<TapTree> {
        let first = self.front.links()?.remove(0);
        self.core().tree(first.leaf)
    }
    /// `assert`'s leaf: π1's digits under the hub's Lamport key, π2 and π3
    /// beside them (so that the user can check the whole proof from the
    /// chain).
    fn assert_leaf(&self) -> Leaf {
        let (b, tl) = signed(&self.ctx(), after(POST_CSV));
        ok_leaf("assert", self.tail.lamport.verify(b).push_opcode(OP_2DROP), tl)
    }
    /// `assert`'s output: the user's `challenge_assert`, the reveal; or,
    /// after `Δ2`, `success`.
    pub fn asserted(&self) -> Result<TapTree> {
        let (b, tl) = signed(&self.ctx(), after(POST_CSV));
        let b = crate::reveal::reveal_verify(b, &self.tail.lamport, &self.tail.adaptor);
        TapTree::new(vec![ok_leaf("challenge_assert", b, tl), terminal_leaf(&self.ctx(), "success", self.tail.windows.delta2)])
    }
    /// `challenge_assert`'s output: the hub's `wrongly_challenged_k`, a
    /// kept instance's `msg`; or, after `Δ1`, `failure`, hers.
    pub fn challenged(&self) -> Result<TapTree> {
        let mut leaves: Vec<Leaf> = self
            .tail
            .hmsg
            .iter()
            .enumerate()
            .map(|(k, h)| {
                let (b, tl) = signed(&self.ctx(), after(POST_CSV));
                ok_leaf(&format!("wrongly_challenged_{k}"), b.push_opcode(OP_SHA256).push_bytes(h).push_opcode(OP_EQUALVERIFY), tl)
            })
            .collect();
        leaves.push(terminal_leaf(&self.ctx(), "failure", self.tail.windows.delta1));
        TapTree::new(leaves)
    }

    /// Every link of the chain: the front's, then `assert` and
    /// `challenge_assert`, each with the tree of the output it makes and
    /// that output's terminal.
    #[allow(clippy::type_complexity)]
    fn chain(&self) -> Result<Vec<(String, Role, Vec<Vec<u8>>, Vec<TxOut>, TapTree, String, Payout)>> {
        let links = self.front.links()?;
        let ctx = self.ctx();
        let mut out = vec![];
        for (k, l) in links.iter().enumerate() {
            let next = match links.get(k + 1) {
                Some(n) => n.leaf.clone(),
                None => self.assert_leaf(),
            };
            let tree = TapTree::new(vec![next, terminal_leaf(&ctx, l.terminal, l.window)])?;
            out.push((l.name.to_string(), l.poster, l.shape.clone(), l.extra.clone(), tree, l.terminal.to_string(), l.pays));
        }
        let assert_shape = vec![vec![0u8; 20]; DIGITS].into_iter().chain([vec![0u8; 64], vec![0u8; 32]]).collect();
        out.push(("assert".into(), Role::Hub, assert_shape, vec![], self.asserted()?, "success".into(), self.front.success()));
        let challenge_shape = (0..DIGITS).flat_map(|_| [vec![0u8; 20], vec![0u8; 64]]).collect();
        out.push(("challenge_assert".into(), Role::User, challenge_shape, vec![], self.challenged()?, "failure".into(), Payout::User));
        Ok(out)
    }

    /// The links' names in order, the front's then the tail's.
    pub fn link_names(&self) -> Result<Vec<String>> {
        Ok(self.chain()?.into_iter().map(|c| c.0).collect())
    }
    /// The front's links' names in order.
    pub fn front_names(&self) -> Result<Vec<&'static str>> {
        Ok(self.front.links()?.iter().map(|l| l.name).collect())
    }
    /// Who posts link `name`.
    pub fn poster(&self, name: &str) -> Result<Role> {
        self.chain()?.into_iter().find(|c| c.0 == name).map(|c| c.1).with_context(|| format!("no link {name}"))
    }
    /// The terminal on link `name`'s output.
    pub fn terminal_of(&self, name: &str) -> Result<String> {
        self.chain()?.into_iter().find(|c| c.0 == name).map(|c| c.5).with_context(|| format!("no link {name}"))
    }

    /// Every transaction the parties pre-sign, the contract output at
    /// `funding`: the default; the chain and each output's terminal; per
    /// kept instance, `wrongly_challenged_k`, paying the front's
    /// [`Front::wrongly_challenged`].
    pub fn presign(&self, funding: OutPoint) -> Result<Vec<Presign>> {
        let tree = self.tree()?;
        let c_out = TxOut { value: self.value(), script_pubkey: tree.script_pubkey() };
        let mut out = vec![self.core().default_tx(&tree, funding)?];
        let (mut prev, mut op, mut prev_out) = (tree, funding, c_out);
        for (name, poster, shape, extra, next, terminal, pays) in self.chain()? {
            let link = self.core().link_extra(&name, poster, shape, &prev, &name, op, &prev_out, next.script_pubkey(), extra)?;
            let n_out = link.tx.output[0].clone();
            op = OutPoint { txid: link.tx.compute_txid(), vout: 0 };
            out.push(link);
            out.push(Presign::new(&terminal, &next, &terminal, op, &n_out, self.front.pay(pays, n_out.value)?, false)?);
            (prev, prev_out) = (next, n_out);
        }
        for k in 0..self.tail.hmsg.len() {
            let name = format!("wrongly_challenged_{k}");
            let pays = match self.front.wrongly_challenged() {
                Payout::Hub => self.core().pay_hub(prev_out.value),
                which => self.front.pay(which, prev_out.value)?,
            };
            let mut w = Presign::new(&name, &prev, &name, op, &prev_out, pays, false)?;
            w.tx.version = Version::non_standard(3);
            out.push(w);
        }
        Ok(out)
    }

    /// Whether the hub keeps its signature on `name` from the user.
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

    // ----- the tail's witnesses, below both signatures -----

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

/// A link's arguments (consumption order), below both 2-of-2 signatures.
pub fn link_args(tx: &Transaction) -> Vec<Vec<u8>> {
    lichen_btc::witness::witness_args_consumption_order(&tx.input[0].witness).into_iter().skip(2).collect()
}

/// A link's txid in a pre-signed set.
pub fn txid_in(set: &[Presign], name: &str) -> Result<Txid> {
    Ok(set.iter().find(|p| p.name == name).with_context(|| format!("no {name}"))?.tx.compute_txid())
}
