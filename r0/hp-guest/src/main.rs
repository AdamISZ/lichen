//! The hub's statement guest, the grants L2's (`lichen_withdraw::accounts::
//! check`, papers/lichen-grants-v0.5.6 §6.3): "the claim Alice signed is
//! owed at most the `b_corr` she countersigned". It reads no chain: her
//! four one-time signatures (on `Q` and `b` from `request`, on `b_corr` and
//! `U` from `ack`) under the keys the journal binds, and at most one cited
//! spend. Its input, read raw (as the other guests'): the statement's input
//! in bytes (`Input::to_bytes`). Its journal: `c ‖ D`, fixed at the
//! contract's opening.

use lichen_withdraw::accounts::{check, Input};
use risc0_zkvm::guest::env;

fn main() {
    let n: u32 = env::read();
    let mut words = vec![0u32; (n as usize).div_ceil(4)];
    env::read_slice(&mut words);
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).take(n as usize).collect();
    let input = Input::from_bytes(&bytes).expect("the statement's input");
    let journal = check(&input).expect("the hub's statement");
    env::commit_slice(&journal);
}
