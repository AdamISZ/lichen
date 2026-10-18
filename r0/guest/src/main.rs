//! The spend guest: the spend statement of `lichen-shielded`. Its input is
//! the statement's input in bytes, read raw (a length, then words: serde
//! would take a word a byte); its journal, the statement's journal.

use lichen_shielded::{check, SpendInput};
use risc0_zkvm::guest::env;

fn main() {
    let n: u32 = env::read();
    let mut words = vec![0u32; (n as usize).div_ceil(4)];
    env::read_slice(&mut words);
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).take(n as usize).collect();
    let input = SpendInput::from_bytes(&bytes).expect("the statement's input");
    let journal = check(&input).expect("the spend statement");
    env::commit_slice(&journal.to_bytes());
}
