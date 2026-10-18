//! The chain guest: the chain statement of `lichen-validity`. Its input is
//! a length, then words (read raw, as the spend guest's): its own image id
//! (32 bytes; a guest can't hold its own), then the block statement's
//! input in bytes. Each shielded transaction's receipt is checked against
//! the spend guest's image id, the previous chain receipt against the
//! given one; both are assumptions the prover resolves. Its journal, the
//! chain journal.

use lichen_validity::{chain, BlockInput};
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::Digest;

/// The committed spend guest's image id.
const SPEND_ID: &str = include_str!("../../guests/spend.id");

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
    let (id, block) = bytes.split_at(32);
    let chain_id: [u8; 32] = id.try_into().unwrap();
    let input = BlockInput::from_bytes(block).expect("the block statement's input");
    let spend = Digest::from_bytes(hex32(SPEND_ID));
    let journal = chain(&chain_id, &input, &mut |j| env::verify(spend, j).is_ok(), &mut |j| env::verify(Digest::from_bytes(chain_id), j).is_ok()).expect("the chain statement");
    env::commit_slice(&journal.to_bytes());
}
