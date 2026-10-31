//! What an exit's statements read of Bitcoin, from a chain
//! (docs/EXIT_PLAN.md, "Under BABE"): `request` in its block with its
//! witness (where the claim is posted), and the contract's funding
//! transaction, whose output 0 it spends.

use anyhow::{Context, Result};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::{Transaction, Txid, Witness};
use lichen_chain::Chain;
use lichen_ledger::lichen_validity::btc::sha256d;

/// The Merkle path of the leaf at `index` among `leaves` (internal
/// order), siblings from the leaves up; a level's odd last node pairs
/// with itself.
pub fn merkle_path(leaves: &[[u8; 32]], mut index: usize) -> Vec<[u8; 32]> {
    let mut level = leaves.to_vec();
    let mut path = vec![];
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        path.push(level[index ^ 1]);
        level = level.chunks(2).map(|p| sha256d(&[p[0], p[1]].concat())).collect();
        index /= 2;
    }
    path
}

/// A transaction's non-witness serialization (its txid's).
pub fn bare(t: &Transaction) -> Vec<u8> {
    let mut t = t.clone();
    t.input.iter_mut().for_each(|i| i.witness = Witness::new());
    serialize(&t)
}

/// `request` (`request_id`) in its block, with its witness, and the
/// funding transaction `funding` it spends: what the statements take.
pub fn request_proof(chain: &Chain, funding: &Transaction, request_id: &Txid) -> Result<lichen_withdraw::Request> {
    let request = chain.get_tx(request_id).context("the request")?;
    let block = chain.block_of(request_id)?.context("the request is not in a block")?;
    let header = chain.header(&block)?;
    let txids = chain.block_txids(&block)?;
    let index = txids.iter().position(|t| t == request_id).context("the request is not among its block's transactions")?;
    let coinbase = chain.get_tx(&txids[0]).context("the block's coinbase")?;
    // the witness tree: the coinbase's leaf is zero
    let mut wtxids = vec![[0u8; 32]];
    for t in &txids[1..] {
        wtxids.push(chain.get_tx(t).context("a transaction of the request's block")?.compute_wtxid().to_byte_array());
    }
    let ids: Vec<[u8; 32]> = txids.iter().map(|t| t.to_byte_array()).collect();
    let reserved: [u8; 32] = coinbase.input[0].witness.nth(0).and_then(|w| w.try_into().ok()).unwrap_or([0; 32]);
    Ok(lichen_withdraw::Request {
        funding: bare(funding),
        tx: serialize(&request),
        header,
        index: index as u32,
        path: merkle_path(&wtxids, index),
        coinbase: bare(&coinbase),
        coinbase_path: merkle_path(&ids, 0),
        reserved,
    })
}
