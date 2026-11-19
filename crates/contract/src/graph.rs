//! What every contract has, whatever its dispute: the contract output
//! ([`Core::tree`]: the parties' MuSig2 key, and the leaves `default` and
//! the dispute's `escalate`), the cooperative close on its key path
//! ([`Fold`]), the default, the payout, and the machinery of the
//! pre-signed set: a link of the dispute's chain, with its floor and its
//! poster's anchor ([`Core::link`]), and [`Presign`].

use std::collections::HashMap;

use anyhow::{bail, ensure, Context, Result};
use bitcoin::key::{Keypair, XOnlyPublicKey};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{schnorr, SECP256K1};
use bitcoin::taproot::ControlBlock;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxOut, Witness};
use lichen_btc::sighash::{sign_tapscript, sign_tapscript_acp, tapscript_sighash};
use lichen_btc::taptree::{Leaf, TapTree};
use lichen_btc::tx::{build_spend, Timelock};
use lichen_btc::musig::{self, KeyAgg, Partial, PubNonce, SecNonce};
use lichen_btc::witness::tapscript_witness;
use crate::keys::{ContractCtx, ContractParams, PartyPubKeys, Role};
use lichen_wots::{Chain, WotsPublicOf};

use crate::leaves::{bit_tree_signed, default_leaf, default_outputs, payout_less_signed, reserve_tree_signed, Terms};

/// The fee a link pays of its own, sat/vB, out of the contract: enough to
/// relay alone; its poster's child pays the rest.
pub const FLOOR_RATE: u64 = 1;
/// A link's anchor output (the dust limit of a taproot output). It goes
/// to the poster, who spends it in the fee child.
pub const ANCHOR: Amount = Amount::from_sat(330);
/// The relative timelock on a move's `post`: a block, so that nothing of
/// the opponent's sits in the mempool on an unconfirmed link (no TRUC).
pub const POST_CSV: u16 = 1;

/// The output only `role`'s payment key can spend: a link's anchor, the
/// same script as that party's fee coins.
pub fn anchor_tree(ctx: &ContractCtx, role: Role) -> Result<TapTree> {
    anchor_tree_for(&ctx.key(role).payment)
}

/// The anchor's tree for a payment key: one leaf, `fee`, the key's
/// signature (its poster signs it when it spends the anchor in its fee
/// child).
pub fn anchor_tree_for(key: &XOnlyPublicKey) -> Result<TapTree> {
    let script = Builder::new().push_x_only_key(key).push_opcode(bitcoin::opcodes::all::OP_CHECKSIG).into_script();
    TapTree::new(vec![Leaf::new("fee".to_string(), script, Timelock::NONE)])
}

/// The vbytes to add to a link's size for its floor, spending `tree`'s
/// leaf `leaf`: what a leaf at the tree's greatest depth would add, so the
/// floors (and the hub's reserve that covers them) are the statement's,
/// not the keys'.
pub fn slack_vbytes(tree: &TapTree, leaf: &str) -> Result<u64> {
    Ok((tree.depth_slack(leaf)? as u64).div_ceil(4))
}

/// What every contract has: its terms, its parameters and both parties'
/// keys (Alice's, then the hub's). A view, built from a dispute's own
/// spec.
#[derive(Clone, Copy)]
pub struct Core<'a> {
    pub terms: &'a Terms,
    pub params: &'a ContractParams,
    pub pubs: &'a [PartyPubKeys; 2],
}

impl<'a> Core<'a> {
    pub fn ctx(&self) -> ContractCtx<'a> {
        ContractCtx { params: self.params, keys: self.pubs }
    }
    /// What the contract output holds: `V_max` and both reserves (it funds
    /// no fees).
    pub fn value(&self) -> Amount {
        self.terms.v_max() + self.terms.reserves()
    }
    /// Both parties' payment keys aggregated (MuSig2, Alice's first): the
    /// contract output's internal key.
    pub fn musig(&self) -> Result<KeyAgg> {
        KeyAgg::new(&[self.pubs[0].payment, self.pubs[1].payment])
    }
    /// The contract output's tree: the parties' MuSig2 key (the fold), and
    /// the leaves `default` and the dispute's `escalate`.
    pub fn tree(&self, escalate: Leaf) -> Result<TapTree> {
        let ctx = self.ctx();
        TapTree::with_internal_key(self.musig()?.internal_key(), vec![default_leaf(&ctx, self.terms.t_close), escalate])
    }
    /// The cooperative close for a withdrawal of `b` sats, the contract
    /// output (`tree`) at `funding`: Alice `b + r_A`, the hub the rest
    /// less `fee`. Both sign it when it happens, on the key path.
    pub fn fold(&self, tree: &TapTree, funding: OutPoint, b: Amount, fee: Amount) -> Result<Fold> {
        let t = self.terms;
        ensure!(b <= t.v_max(), "{b} is above the cap {}", t.v_max());
        let c_out = TxOut { value: self.value(), script_pubkey: tree.script_pubkey() };
        let alice = b + t.reserve_alice;
        let hub = (c_out.value - alice).checked_sub(fee).context("the fee")?;
        let mut outs = vec![TxOut { value: alice, script_pubkey: self.pubs[0].payout_spk.clone() }];
        if hub >= self.params.dust {
            outs.push(TxOut { value: hub, script_pubkey: self.pubs[1].payout_spk.clone() });
        }
        // its fee comes from the hub's output: signed with plain ALL
        // (SIGHASH_DEFAULT), nothing is added to it
        let mut tx = build_spend(funding, &Timelock::NONE, outs);
        tx.version = Version::TWO;
        let key = self.musig()?.taproot(tree.merkle_root())?;
        ensure!(key.output_key() == tree.output_key().to_x_only_public_key(), "the MuSig2 key isn't the tree's output key");
        Ok(Fold { tx, prevout: c_out, key })
    }
    /// The default, the contract output (`tree`) at `funding`: after
    /// `T_close` the hub takes `V_max` and its reserve, Alice her reserve.
    pub fn default_tx(&self, tree: &TapTree, funding: OutPoint) -> Result<Presign> {
        let c_out = TxOut { value: self.value(), script_pubkey: tree.script_pubkey() };
        let outs = default_outputs(&self.ctx(), self.terms, c_out.value, Amount::ZERO)?;
        Presign::new("default", tree, "default", funding, &c_out, outs, false)
    }
    /// The outputs paying `b` in bits (read from Alice's signature under
    /// `b_key`) and both reserves to Alice, the rest to the hub;
    /// `available` is what the output carries, the contract's value less
    /// the floors and anchors of the links played, which come out of the
    /// hub's forfeited reserve (D-J2).
    pub fn pay_alice<H: Chain>(&self, b_key: &WotsPublicOf<H>, available: Amount) -> Result<Vec<TxOut>> {
        self.pay_signed(b_key, Role::User, available)
    }
    /// The outputs paying `b′` in bits (read from the hub's signature
    /// under `hub_b`: what it proved she is owed), Alice's reserve to her
    /// payout address, and the hub's less the floors
    /// ([`payout_less_signed`]), for an L2 where the hub proves.
    ///
    /// Alice must take her set bits, or post `equiv_b` with a second value
    /// the hub signed, within `delta` of this payout confirming: after it,
    /// a hub that signed two values can take her bits by its own leaves
    /// (the duty the hub has on [`Core::pay_alice`]'s). The hub's reserve
    /// less the floors goes to its payout address with the rest, outside
    /// `equiv_b`, when it is dust.
    pub fn pay_reduced<H: Chain>(&self, hub_b: &WotsPublicOf<H>, available: Amount) -> Result<Vec<TxOut>> {
        self.pay_signed(hub_b, Role::Hub, available)
    }
    fn pay_signed<H: Chain>(&self, key: &WotsPublicOf<H>, signer: Role, available: Amount) -> Result<Vec<TxOut>> {
        let floors = self.value().checked_sub(available).context("an output carries more than the contract")?;
        payout_less_signed(&self.ctx(), self.terms, key, signer, available, Amount::ZERO, floors)
    }
    /// `party`'s outputs of `payout`, a terminal paying the value `value`
    /// that `signer` signed under `key` ([`payout_less_signed`]): for each
    /// bit of the value, the set ones Alice's and the clear ones the hub's;
    /// and the signer's reserve output, if any. The signer's wait `delta`
    /// (the other's window on a second signed value); the other's don't.
    /// In output order; an output not of its script (none paid) is
    /// skipped. Not the other party's outputs by `equiv_b`.
    pub fn owned<H: Chain>(&self, payout: &Transaction, key: &WotsPublicOf<H>, signer: Role, value: u32, party: Role) -> Result<Vec<Owned>> {
        let (t, ctx) = (self.terms, self.ctx());
        let txid = payout.compute_txid();
        let sequence = if party == signer { Sequence::from_height(self.params.delta) } else { Sequence::ENABLE_RBF_NO_LOCKTIME };
        let mut outs: Vec<(u32, TapTree, String, bool)> = vec![];
        for i in t.low_bits..t.bits {
            let set = (value >> i) & 1 == 1;
            if set == (party == Role::User) {
                let name = if set { format!("alice_bit_{i}") } else { format!("hub_bit_{i}") };
                outs.push((i - t.low_bits, bit_tree_signed(&ctx, i, key, signer)?, name, true));
            }
        }
        if party == signer {
            let (vout, name) = match signer {
                Role::User => (t.bits - t.low_bits, "alice_reserve"),
                Role::Hub => (t.bits - t.low_bits + 1, "hub_reserve"),
            };
            outs.push((vout, reserve_tree_signed(&ctx, t, key, signer)?, name.into(), false));
        }
        Ok(outs
            .into_iter()
            .filter_map(|(vout, tree, leaf, with_value)| {
                let out = payout.output.get(vout as usize).filter(|o| o.script_pubkey == tree.script_pubkey())?.clone();
                Some(Owned { op: OutPoint { txid, vout }, out, tree, leaf, with_value, sequence })
            })
            .collect())
    }
    /// Everything to the hub.
    pub fn pay_hub(&self, available: Amount) -> Vec<TxOut> {
        vec![TxOut { value: available, script_pubkey: self.pubs[1].payout_spk.clone() }]
    }
    /// A link of the dispute's chain, posted by `poster`, spending
    /// `(op, prev_out)` under `prev_tree`'s leaf `prev_leaf` into `next`
    /// (the next output's script): its output carries the input less its
    /// floor and the poster's anchor. `shape` is a witness of the shape the
    /// link carries (each element's size), for its floor.
    #[allow(clippy::too_many_arguments)]
    pub fn link(&self, name: &str, poster: Role, shape: Vec<Vec<u8>>, prev_tree: &TapTree, prev_leaf: &str, op: OutPoint, prev_out: &TxOut, next: ScriptBuf) -> Result<Presign> {
        let anchor = TxOut { value: ANCHOR, script_pubkey: anchor_tree(&self.ctx(), poster)?.script_pubkey() };
        let mut p = Presign::new(name, prev_tree, prev_leaf, op, prev_out, vec![TxOut { value: prev_out.value, script_pubkey: next }, anchor], true)?;
        let vsize = p.finish(shape, &[0u8; 64], &[0u8; 64]).vsize() as u64 + slack_vbytes(prev_tree, prev_leaf)?;
        let floor = Amount::from_sat(vsize * FLOOR_RATE);
        let carried = prev_out.value.checked_sub(floor + ANCHOR).context("the contract can't carry the floors")?;
        p.tx.output[0].value = carried;
        Ok(p)
    }
}

/// An output of a payout that a party spends alone ([`Core::owned`]).
#[derive(Clone, Debug)]
pub struct Owned {
    pub op: OutPoint,
    pub out: TxOut,
    pub tree: TapTree,
    pub leaf: String,
    /// Whether its leaf reads the signature on the value.
    pub with_value: bool,
    /// What its spend's input waits.
    pub sequence: Sequence,
}

impl Owned {
    /// Its witness as input `n` of `tx`, which spends `prevouts`: `wire`
    /// (the signature on the value, as the payout's leaves take it) where
    /// its leaf reads it, under `kp`'s signature.
    pub fn witness(&self, tx: &Transaction, n: usize, prevouts: &[TxOut], kp: &Keypair, wire: &[Vec<u8>]) -> Result<Witness> {
        let leaf = self.tree.leaf(&self.leaf).with_context(|| format!("no leaf {}", self.leaf))?;
        let mut w = if self.with_value { wire.to_vec() } else { vec![] };
        w.push(sign_tapscript(kp, tx, n, prevouts, &leaf.script)?.as_ref().to_vec());
        Ok(tapscript_witness(&w, &leaf.script, &self.tree.control_block(&self.leaf)?))
    }
}

/// The fold: the cooperative close, the contract output spent on its key
/// path by both parties' MuSig2 signature (BIP327; `lichen_btc::musig`).
/// Each party makes a nonce for it ([`Fold::nonce`]) and, with both
/// public nonces, its partial signature ([`Fold::sign`]); the partials
/// make the signature ([`Fold::finish`]).
#[derive(Clone, Debug)]
pub struct Fold {
    pub tx: Transaction,
    pub prevout: TxOut,
    /// The parties' aggregate, tweaked for the contract output's tree.
    pub key: KeyAgg,
}

impl Fold {
    /// What both sign: the key-path sighash (SIGHASH_DEFAULT).
    pub fn sighash(&self) -> Result<[u8; 32]> {
        let h = bitcoin::sighash::SighashCache::new(&self.tx).taproot_key_spend_signature_hash(0, &bitcoin::sighash::Prevouts::All(&[&self.prevout]), bitcoin::sighash::TapSighashType::Default)?;
        Ok(bitcoin::hashes::Hash::to_byte_array(h))
    }
    /// A fresh nonce for `kp` (a party's payment key) on this contract
    /// output; `extra` salts it with the session's context.
    pub fn nonce(&self, kp: &Keypair, extra: &[u8]) -> Result<(SecNonce, PubNonce)> {
        musig::nonce(&self.key, kp, extra)
    }
    /// `kp`'s partial signature, its nonce `sec` (spent) among `nonces`
    /// (Alice's, then the hub's).
    pub fn sign(&self, kp: &Keypair, sec: SecNonce, nonces: &[PubNonce; 2]) -> Result<Partial> {
        musig::sign(&self.key, kp, sec, nonces, &self.sighash()?)
    }
    /// Check `pk`'s partial signature, its nonce `nonce`.
    pub fn verify_partial(&self, pk: &XOnlyPublicKey, nonce: &PubNonce, nonces: &[PubNonce; 2], partial: &Partial) -> Result<()> {
        musig::verify_partial(&self.key, pk, nonce, nonces, partial, &self.sighash()?)
    }
    /// The transaction ready to broadcast: the partials (Alice's, then the
    /// hub's) aggregated, the signature checked, as its witness.
    pub fn finish(&self, nonces: &[PubNonce; 2], partials: &[Partial; 2]) -> Result<Transaction> {
        let sig = musig::aggregate(&self.key, nonces, partials, &self.sighash()?)?;
        let mut tx = self.tx.clone();
        tx.input[0].witness = bitcoin::Witness::p2tr_key_spend(&bitcoin::taproot::Signature { signature: sig, sighash_type: bitcoin::sighash::TapSighashType::Default });
        Ok(tx)
    }
}

/// The witness shape of one-time signatures under `keys`, for a link's
/// size: each digit's elements (a chain hash, and a digit of one byte).
pub fn wots_shape<'k, H: Chain + 'k>(keys: impl IntoIterator<Item = &'k WotsPublicOf<H>>) -> Vec<Vec<u8>> {
    keys.into_iter().flat_map(|k| (0..k.params.total_digits()).flat_map(|_| [vec![0u8; std::mem::size_of::<H>()], vec![15u8]])).collect()
}

/// One pre-signed transaction: unsigned, with what its signatures cover.
/// Most have one input; a link may have several (`extra`).
#[derive(Clone, Debug)]
pub struct Presign {
    pub name: String,
    pub tx: Transaction,
    pub prevout: TxOut,
    pub leaf: ScriptBuf,
    pub control: ControlBlock,
    /// Inputs after the first: each its prevout, leaf and control block.
    pub extra: Vec<(TxOut, ScriptBuf, ControlBlock)>,
    /// A link of the chain (plain ALL signatures, its poster's anchor at
    /// output 1); otherwise a terminal transaction (ALL|ANYONECANPAY).
    pub link: bool,
}

/// The name an input's signatures go by: the transaction's for input 0,
/// `name#i` for input `i`.
pub fn sig_name(name: &str, i: usize) -> String {
    if i == 0 {
        name.to_string()
    } else {
        format!("{name}#{i}")
    }
}

impl Presign {
    /// A transaction spending `(op, prevout)` under `tree`'s leaf `leaf`
    /// (its timelock) into `outputs`: a link, or a terminal.
    pub fn new(name: &str, tree: &TapTree, leaf: &str, op: OutPoint, prevout: &TxOut, outputs: Vec<TxOut>, link: bool) -> Result<Presign> {
        let l = tree.leaf(leaf).with_context(|| format!("{name}: no leaf {leaf}"))?;
        let tx = build_spend(op, &l.timelock, outputs);
        Ok(Presign { name: name.to_string(), tx, prevout: prevout.clone(), leaf: l.script.clone(), control: tree.control_block(leaf)?, extra: vec![], link })
    }
    /// A link with several inputs, each `(outpoint, prevout, tree, leaf)`.
    pub fn new_multi(name: &str, inputs: &[(OutPoint, TxOut, TapTree, &str)], outputs: Vec<TxOut>) -> Result<Presign> {
        let mut ins = vec![];
        let mut info = vec![];
        for (op, out, tree, leaf) in inputs {
            let l = tree.leaf(leaf).with_context(|| format!("{name}: no leaf {leaf}"))?;
            ins.push((*op, l.timelock.sequence()));
            info.push((out.clone(), l.script.clone(), tree.control_block(leaf)?));
        }
        let tx = lichen_btc::tx::build_tx(&ins, outputs, bitcoin::absolute::LockTime::ZERO);
        let (prevout, leaf, control) = info.remove(0);
        Ok(Presign { name: name.to_string(), tx, prevout, leaf, control, extra: info, link: true })
    }
    /// The inputs.
    pub fn inputs(&self) -> usize {
        1 + self.extra.len()
    }
    fn prevouts(&self) -> Vec<TxOut> {
        std::iter::once(self.prevout.clone()).chain(self.extra.iter().map(|e| e.0.clone())).collect()
    }
    fn leaf_of(&self, i: usize) -> &ScriptBuf {
        if i == 0 {
            &self.leaf
        } else {
            &self.extra[i - 1].1
        }
    }
    /// This party's signature (on input 0).
    pub fn sign(&self, kp: &Keypair) -> Result<Vec<u8>> {
        self.sign_input(kp, 0)
    }
    /// This party's signature on input `i`.
    pub fn sign_input(&self, kp: &Keypair, i: usize) -> Result<Vec<u8>> {
        if self.link {
            Ok(sign_tapscript(kp, &self.tx, i, &self.prevouts(), self.leaf_of(i))?.as_ref().to_vec())
        } else {
            ensure!(i == 0, "a terminal transaction has one input");
            sign_tapscript_acp(kp, &self.tx, 0, &self.prevout, &self.leaf)
        }
    }
    /// Check the other party's signature (on input 0).
    pub fn verify(&self, pk: &XOnlyPublicKey, sig: &[u8]) -> Result<()> {
        self.verify_input(pk, 0, sig)
    }
    /// Check the other party's signature on input `i`.
    pub fn verify_input(&self, pk: &XOnlyPublicKey, i: usize, sig: &[u8]) -> Result<()> {
        if self.link {
            let s = schnorr::Signature::from_slice(sig)?;
            let msg = tapscript_sighash(&self.tx, i, &self.prevouts(), self.leaf_of(i))?;
            SECP256K1.verify_schnorr(&s, &msg, pk).map_err(|e| anyhow::anyhow!("{}: {e}", self.name))
        } else {
            ensure!(i == 0, "a terminal transaction has one input");
            ensure!(sig.len() == 65 && sig[64] == bitcoin::sighash::TapSighashType::AllPlusAnyoneCanPay as u8, "{}: not an ALL|ANYONECANPAY signature", self.name);
            let s = schnorr::Signature::from_slice(&sig[..64])?;
            let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(&self.leaf, bitcoin::taproot::LeafVersion::TapScript);
            let h = bitcoin::sighash::SighashCache::new(&self.tx).taproot_script_spend_signature_hash(0, &bitcoin::sighash::Prevouts::One(0, &self.prevout), leaf_hash, bitcoin::sighash::TapSighashType::AllPlusAnyoneCanPay)?;
            let msg = bitcoin::secp256k1::Message::from_digest(bitcoin::hashes::Hash::to_byte_array(h));
            SECP256K1.verify_schnorr(&s, &msg, pk).map_err(|e| anyhow::anyhow!("{}: {e}", self.name))
        }
    }
    /// The transaction ready to broadcast: `wire` (the leaf's own witness,
    /// such as a move) below the hub's and Alice's signatures.
    pub fn finish(&self, wire: Vec<Vec<u8>>, hub_sig: &[u8], alice_sig: &[u8]) -> Transaction {
        self.finish_multi(vec![wire], &[hub_sig.to_vec()], &[alice_sig.to_vec()])
    }
    /// [`Presign::finish`] for each input: its wire and both signatures.
    pub fn finish_multi(&self, wires: Vec<Vec<Vec<u8>>>, hub_sigs: &[Vec<u8>], alice_sigs: &[Vec<u8>]) -> Transaction {
        let mut tx = self.tx.clone();
        for (i, wire) in wires.into_iter().enumerate() {
            let mut w = wire;
            w.push(hub_sigs[i].clone());
            w.push(alice_sigs[i].clone());
            let control = if i == 0 { &self.control } else { &self.extra[i - 1].2 };
            tx.input[i].witness = tapscript_witness(&w, self.leaf_of(i), control);
        }
        tx
    }
}

/// Both parties' signatures on a contract's pre-signed set, by name
/// ([`sig_name`]).
#[derive(Clone, Debug, Default)]
pub struct Signed {
    pub hub: HashMap<String, Vec<u8>>,
    pub alice: HashMap<String, Vec<u8>>,
}

impl Signed {
    /// Check every signature of both parties on `set`.
    pub fn verify(&self, set: &[Presign], pubs: &[PartyPubKeys; 2]) -> Result<()> {
        for p in set {
            for i in 0..p.inputs() {
                let n = sig_name(&p.name, i);
                let (Some(h), Some(a)) = (self.hub.get(&n), self.alice.get(&n)) else {
                    bail!("{n}: a signature is missing");
                };
                p.verify_input(&pubs[1].payment, i, h)?;
                p.verify_input(&pubs[0].payment, i, a)?;
            }
        }
        Ok(())
    }
}

/// One party's signatures on the whole set (every input).
pub fn sign_all(set: &[Presign], kp: &Keypair) -> Result<HashMap<String, Vec<u8>>> {
    let mut out = HashMap::new();
    for p in set {
        for i in 0..p.inputs() {
            out.insert(sig_name(&p.name, i), p.sign_input(kp, i)?);
        }
    }
    Ok(out)
}
