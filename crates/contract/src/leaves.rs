//! The contract's terms, its leaves (`default`, and the payout's bit and
//! reserve leaves), and the outputs that pay a withdrawal `b` on the
//! dispute path or end the contract by default at `T_close`.
//!
//! The contract output's key path is both parties' MuSig2 key: the fold,
//! the cooperative withdrawal, signed when it happens ([`crate::Fold`]).
//! Its leaves are `default` and the dispute's `escalate` (BABE's
//! `request`, `lichen_babe`):
//! - `default`: after `T_close`, a pre-signed transaction paying the hub
//!   and returning Alice's reserve (not withdrawing is not a lie);
//! - `escalate`: Alice's claim on chain, the dispute's first move.

use anyhow::{ensure, Result};
use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use bitcoin::{Amount, TxOut};
use lichen_btc::script::BuilderExt;
use lichen_btc::taptree::{Leaf, TapTree};
use lichen_btc::tx::Timelock;
use crate::keys::{ContractCtx, Role};
use lichen_wots::{Chain, WotsExt, WotsPublicOf};

/// A contract's terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Terms {
    /// The contract's identifier `c`, the memo a return must carry.
    pub id: u32,
    /// The payout's granularity `u`.
    pub unit: Amount,
    /// `K`: a withdrawal is `b < 2^K` units, so `V_max = (2^K - 1) u`.
    pub bits: u32,
    /// On the dispute path, bits below this get no output (they would be
    /// dust): `b` is paid rounded down to a multiple of `2^low_bits` units,
    /// the remainder to the hub. 0 pays every bit; with sats as the unit,
    /// 9 (512 sats).
    pub low_bits: u32,
    /// Alice's deposit `D`, in units.
    pub deposit: u32,
    /// `T_close`: after it, with no claim, everything goes to the hub.
    pub t_close: u32,
    /// The contract reserves `r_A`, `r_H`: returned in every honest
    /// outcome, forfeited to the other side by losing a dispute.
    pub reserve_alice: Amount,
    pub reserve_hub: Amount,
}

impl Terms {
    pub fn v_max_units(&self) -> u32 {
        (1 << self.bits) - 1
    }
    pub fn v_max(&self) -> Amount {
        self.unit * u64::from(self.v_max_units())
    }
    /// Both reserves: what the winner of a dispute takes on top of its
    /// share of `V_max`.
    pub fn reserves(&self) -> Amount {
        self.reserve_alice + self.reserve_hub
    }
}

/// Bit `i` of `b`'s input-word signature (the prover's depth-1 key for
/// word 0, which signs `b` big-endian): `want` 1 for Alice's leaf, 0 for
/// the hub's. Alice's leaf waits `delta`, so that if she signed two values
/// of `b` the hub's `equiv_b` takes the output first. Witness, wire order:
/// the word's reveal, the spender's signature. [`bit_leaf_signed`] by
/// Alice.
pub fn bit_leaf<H: Chain>(ctx: &ContractCtx, i: u32, b_key: &WotsPublicOf<H>, want: bool) -> Leaf {
    bit_leaf_signed(ctx, i, b_key, Role::User, want)
}

/// Bit `i` of the value `signer` signed under `b_key` (a one-time key for
/// a 4-byte word, the value big-endian): `want` 1 for Alice's leaf, 0 for
/// the hub's. The signer's leaf waits `delta`, so that if it signed two
/// values the other party's `equiv_b` takes the output first; the other's
/// is immediate. Alice signs her claim `b`; a hub that proves signs what
/// it says she is owed, `b′` (an L2's front, `lichen_babe::graph`).
/// Witness, wire order: the word's reveal, the spender's signature.
pub fn bit_leaf_signed<H: Chain>(ctx: &ContractCtx, i: u32, b_key: &WotsPublicOf<H>, signer: Role, want: bool) -> Leaf {
    let who = if want { Role::User } else { Role::Hub };
    let m = b_key.params.message_digits as usize;
    assert_eq!(m, 8, "a word's key signs 4 bytes");
    // digit k (0 the most significant nibble) sits at depth m - 1 - k
    let (nibble, j) = (7 - i / 4, i % 4);
    let (mut b, tl) = if who == signer { (Builder::new().csv(ctx.params.delta), Timelock::csv(ctx.params.delta)) } else { (Builder::new(), Timelock::NONE) };
    b = b.checksigverify(&ctx.key(who).payment).wots_verify(b_key);
    b = b.push_int((m - 1 - nibble as usize) as i64).push_opcode(OP_PICK);
    // reduce the nibble mod 2^(j+1), then compare with 2^j
    for h in (j + 1..4).rev() {
        b = b.push_opcode(OP_DUP).push_int(1 << h).push_opcode(OP_GREATERTHANOREQUAL).push_opcode(OP_IF).push_int(1 << h).push_opcode(OP_SUB).push_opcode(OP_ENDIF);
    }
    b = b.push_int(1 << j).push_opcode(OP_GREATERTHANOREQUAL);
    if !want {
        b = b.push_opcode(OP_NOT);
    }
    b = b.push_opcode(OP_VERIFY);
    for _ in 0..m / 2 {
        b = b.push_opcode(OP_2DROP);
    }
    let name = if want { format!("alice_bit_{i}") } else { format!("hub_bit_{i}") };
    Leaf::new(name, b.push_int(1).into_script(), tl)
}

/// `equiv_b` on each bit output: two different signatures under `b`'s
/// one-time key (Alice signed two values of `b`); the hub takes the
/// output. `i` only makes the leaf distinct per output. Witness, wire
/// order: one reveal, the other, the hub's signature.
/// [`equiv_b_leaf_signed`] by Alice.
pub fn equiv_b_leaf<H: Chain>(ctx: &ContractCtx, i: u32, b_key: &WotsPublicOf<H>) -> Leaf {
    equiv_b_leaf_signed(ctx, i, b_key, Role::User)
}

/// `equiv_b` on each output of a payout of a value `signer` signed: two
/// different signatures under `b_key` (it signed two values); the other
/// party takes the output. `i` only makes the leaf distinct per output.
/// Witness, wire order: one reveal, the other, the taker's signature.
pub fn equiv_b_leaf_signed<H: Chain>(ctx: &ContractCtx, i: u32, b_key: &WotsPublicOf<H>, signer: Role) -> Leaf {
    let m = b_key.params.message_digits as usize;
    let mut b = Builder::new().push_int(i64::from(i)).push_opcode(OP_DROP).checksigverify(&ctx.key(signer.other()).payment).wots_verify(b_key);
    for _ in 0..m {
        b = b.push_opcode(OP_TOALTSTACK);
    }
    b = b.wots_verify(b_key);
    for _ in 0..m {
        b = b.push_opcode(OP_FROMALTSTACK);
    }
    // count the digits that differ; at least one must
    b = b.push_int(0);
    for j in 0..m {
        b = b
            .push_int((m - j) as i64)
            .push_opcode(OP_PICK)
            .push_int((2 * m - j + 1) as i64)
            .push_opcode(OP_PICK)
            .push_opcode(OP_SUB)
            .push_opcode(OP_0NOTEQUAL)
            .push_opcode(OP_ADD);
    }
    b = b.push_opcode(OP_VERIFY);
    for _ in 0..m {
        b = b.push_opcode(OP_2DROP);
    }
    Leaf::new(format!("equiv_b_{i}"), b.push_int(1).into_script(), Timelock::NONE)
}

/// The output for bit `i`: Alice's leaf, the hub's, and `equiv_b`.
/// [`bit_tree_signed`] by Alice.
pub fn bit_tree<H: Chain>(ctx: &ContractCtx, i: u32, b_key: &WotsPublicOf<H>) -> Result<TapTree> {
    bit_tree_signed(ctx, i, b_key, Role::User)
}

/// The output for bit `i` of the value `signer` signed: Alice's leaf, the
/// hub's, and `equiv_b`.
pub fn bit_tree_signed<H: Chain>(ctx: &ContractCtx, i: u32, b_key: &WotsPublicOf<H>, signer: Role) -> Result<TapTree> {
    TapTree::new(vec![bit_leaf_signed(ctx, i, b_key, signer, true), bit_leaf_signed(ctx, i, b_key, signer, false), equiv_b_leaf_signed(ctx, i, b_key, signer)])
}

/// `alice_reserve` on the reserve output: Alice, after `delta` (the hub's
/// chance to show an equivocation on `b`). Witness: her signature.
/// [`reserve_leaf_signed`] by Alice.
pub fn reserve_leaf(ctx: &ContractCtx) -> Leaf {
    reserve_leaf_signed(ctx, Role::User)
}

/// The signer's leaf on the reserve output (`alice_reserve`,
/// `hub_reserve`): the signer, after `delta` (the other party's chance to
/// show an equivocation). Witness: its signature.
pub fn reserve_leaf_signed(ctx: &ContractCtx, signer: Role) -> Leaf {
    let b = Builder::new().csv(ctx.params.delta).checksig(&ctx.key(signer).payment);
    let name = match signer {
        Role::User => "alice_reserve",
        Role::Hub => "hub_reserve",
    };
    Leaf::new(name, b.into_script(), Timelock::csv(ctx.params.delta))
}

/// The reserve output of a payout to Alice: both reserves, hers after
/// `delta`, the hub's with `equiv_b` (index `K`, after the bit outputs').
/// [`reserve_tree_signed`] by Alice.
pub fn reserve_tree<H: Chain>(ctx: &ContractCtx, t: &Terms, b_key: &WotsPublicOf<H>) -> Result<TapTree> {
    reserve_tree_signed(ctx, t, b_key, Role::User)
}

/// The reserve output of a payout of a value `signer` signed: the
/// signer's after `delta`, the other party's with `equiv_b` (index `K`,
/// after the bit outputs').
pub fn reserve_tree_signed<H: Chain>(ctx: &ContractCtx, t: &Terms, b_key: &WotsPublicOf<H>, signer: Role) -> Result<TapTree> {
    TapTree::new(vec![reserve_leaf_signed(ctx, signer), equiv_b_leaf_signed(ctx, t.bits, b_key, signer)])
}

/// The outputs of every transaction that pays Alice's withdrawal (her
/// proof, the hub's timeout): for each bit `i` from `low_bits` to `K - 1`,
/// an output of `u 2^i`, Alice's iff bit `i` of her signed `b` is set; then
/// both reserves, Alice's; the rest of `available` (less `fee`) to the
/// hub.
pub fn payout<H: Chain>(ctx: &ContractCtx, t: &Terms, b_key: &WotsPublicOf<H>, available: Amount, fee: Amount) -> Result<Vec<TxOut>> {
    payout_less(ctx, t, b_key, available, fee, Amount::ZERO)
}

/// [`payout`] after a dispute whose links carried fee floors totalling
/// `floors` out of the contract: the hub, the loser, forfeits its reserve
/// less them (Alice receives `r_A + r_H - floors` with her bits; the hub
/// still `V_max - b`). [`payout_less_signed`] by Alice.
pub fn payout_less<H: Chain>(ctx: &ContractCtx, t: &Terms, b_key: &WotsPublicOf<H>, available: Amount, fee: Amount, floors: Amount) -> Result<Vec<TxOut>> {
    payout_less_signed(ctx, t, b_key, Role::User, available, fee, floors)
}

/// The outputs paying the value `signer` signed under `b_key`, after a
/// dispute whose links carried fee floors totalling `floors` out of the
/// contract (they come from the hub's reserve): for each bit `i` from
/// `low_bits` to `K - 1`, an output of `u 2^i`, Alice's iff bit `i` is set,
/// then:
/// - Alice signed (her claim stood, [`payout_less`]): both reserves less
///   the floors, hers after `delta` (the hub, the loser, forfeits its
///   own; it still gets `V_max - b`);
/// - the hub signed (what it proved she is owed): `r_A` to Alice's payout
///   address (she risked nothing), then the hub's reserve less the floors
///   in its reserve output, after `delta`. Below dust, that remainder goes
///   with the rest to the hub's payout address, outside `equiv_b`: a hub
///   that signs a second value then loses its bits but not that dust.
///
/// The rest of `available` (less `fee`) to the hub, if not dust.
///
/// Whoever did not sign must take its outputs, or post `equiv_b` with a
/// second signed value, within `delta` of the payout confirming: after
/// it, a signer that signed a second value can take the other's bits by
/// its own leaves. Paying the hub's value, that duty is Alice's.
pub fn payout_less_signed<H: Chain>(ctx: &ContractCtx, t: &Terms, b_key: &WotsPublicOf<H>, signer: Role, available: Amount, fee: Amount, floors: Amount) -> Result<Vec<TxOut>> {
    let total = available.checked_sub(fee).ok_or_else(|| anyhow::anyhow!("the fee exceeds the output"))?;
    let reserves = t.reserves().checked_sub(floors).filter(|r| *r >= t.reserve_alice).ok_or_else(|| anyhow::anyhow!("the floors {floors} exceed the hub's reserve"))?;
    ensure!(total >= t.v_max() + reserves, "{total} cannot pay V_max {} and the reserves less the floors", t.v_max());
    let mut outs: Vec<TxOut> = (t.low_bits..t.bits).map(|i| Ok(TxOut { value: t.unit * (1u64 << i), script_pubkey: bit_tree_signed(ctx, i, b_key, signer)?.script_pubkey() })).collect::<Result<_>>()?;
    let reserve = |value| -> Result<TxOut> { Ok(TxOut { value, script_pubkey: reserve_tree_signed(ctx, t, b_key, signer)?.script_pubkey() }) };
    match signer {
        Role::User => outs.push(reserve(reserves)?),
        Role::Hub => {
            ensure!(t.reserve_alice >= ctx.params.dust, "Alice's reserve {} is dust", t.reserve_alice);
            outs.push(TxOut { value: t.reserve_alice, script_pubkey: ctx.key(Role::User).payout_spk.clone() });
            let hub = reserves - t.reserve_alice;
            if hub >= ctx.params.dust {
                outs.push(reserve(hub)?);
            }
        }
    }
    let paid: Amount = outs.iter().map(|o| o.value).sum();
    let rest = total - paid;
    if rest >= ctx.params.dust {
        outs.push(TxOut { value: rest, script_pubkey: ctx.key(Role::Hub).payout_spk.clone() });
    }
    Ok(outs)
}

/// The outputs of the transaction that ends the contract by default after
/// `T_close`: Alice's reserve back to her, the rest (less `fee`) to the
/// hub.
pub fn default_outputs(ctx: &ContractCtx, t: &Terms, available: Amount, fee: Amount) -> Result<Vec<TxOut>> {
    let total = available.checked_sub(fee).ok_or_else(|| anyhow::anyhow!("the fee exceeds the output"))?;
    ensure!(total > t.reserve_alice, "{total} cannot return the reserve");
    Ok(vec![
        TxOut { value: t.reserve_alice, script_pubkey: ctx.key(Role::User).payout_spk.clone() },
        TxOut { value: total - t.reserve_alice, script_pubkey: ctx.key(Role::Hub).payout_spk.clone() },
    ])
}

/// `default` on the contract output: after `T_close`, 2-of-2 pre-signed
/// at the opening, paying [`default_outputs`]. Witness: the hub's
/// signature, the user's.
pub fn default_leaf(ctx: &ContractCtx, t_close: u32) -> Leaf {
    let b = ctx.two_of_two_verify(Builder::new().cltv(t_close));
    Leaf::new("default", b.push_int(1).into_script(), Timelock::cltv(t_close))
}
