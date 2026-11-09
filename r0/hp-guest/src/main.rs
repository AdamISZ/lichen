//! The hub's statement guest (`lichen_withdraw::hp::check`): "the claim
//! posted in `request` is false". Its input, read raw (as the other
//! guests'): the statement's input in bytes (`HubInput::to_bytes`). The
//! chain receipt at `A*`'s chain height is checked against the chain
//! guest's image id, an assumption the prover resolves. Its journal:
//! `c ‖ D ‖ H(O_D ‖ margin)`, fixed at the contract's opening.

use lichen_withdraw::hp::{check, HubInput};
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::Digest;

/// The committed chain guest's image id.
const CHAIN_ID: &str = include_str!("../../guests/chain.id");

fn hex32(s: &str) -> [u8; 32] {
    let s = s.trim().as_bytes();
    assert_eq!(s.len(), 64, "an image id");
    let nib = |c: u8| (c as char).to_digit(16).expect("hex") as u8;
    core::array::from_fn(|i| nib(s[2 * i]) << 4 | nib(s[2 * i + 1]))
}

fn main() {
    let n: u32 = env::read();
    let mut words = vec![0u32; (n as usize).div_ceil(4)];
    env::read_slice(&mut words);
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).take(n as usize).collect();
    let chain_id = hex32(CHAIN_ID);
    let verify_chain = &mut |j: &[u8]| env::verify(Digest::from_bytes(chain_id), j).is_ok();
    let input = HubInput::from_bytes(&bytes).expect("the statement's input");
    let journal = check(&input, &chain_id, verify_chain).expect("the hub's statement");
    env::commit_slice(&journal);
}
