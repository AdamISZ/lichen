//! The hub's statement guest, the grants L2's (`lichen_withdraw::grants::
//! check`, docs/GRANTS_PLAN.md): "the claim posted in `request` is owed at
//! most the `b_corr` the hub signed in `correct`". Its input, read raw (as
//! the other guests'): the statement's input in bytes
//! (`GrantsInput::to_bytes`). Its journal: `c ‖ D ‖ H(O_D ‖ margin)`,
//! fixed at the contract's opening.

use lichen_withdraw::grants::{check, GrantsInput};
use risc0_zkvm::guest::env;

fn main() {
    let n: u32 = env::read();
    let mut words = vec![0u32; (n as usize).div_ceil(4)];
    env::read_slice(&mut words);
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).take(n as usize).collect();
    let input = GrantsInput::from_bytes(&bytes).expect("the statement's input");
    let journal = check(&input).expect("the hub's statement");
    env::commit_slice(&journal);
}
