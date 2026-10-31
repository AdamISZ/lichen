//! What the statements read of a transaction's witness
//! (`lichen_validity::btc`'s `parse_witness_tx` and `witness_in_block`),
//! against rust-bitcoin's serialization and BIP141 commitment. (Here, not
//! in `lichen-validity`: the guests build that crate alone.)

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::transaction::Version;
use bitcoin::{Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Txid, Witness};
use lichen_ledger::lichen_validity::btc;

type Hash = [u8; 32];

fn input(txid: [u8; 32], vout: u32, items: &[&[u8]]) -> TxIn {
    TxIn { previous_output: OutPoint { txid: Txid::from_byte_array(txid), vout }, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::from_slice(items) }
}

fn tx(inputs: Vec<TxIn>) -> Transaction {
    Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: inputs, output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::from_bytes(vec![0x51]) }] }
}

fn pair(a: &Hash, b: &Hash) -> Hash {
    btc::sha256d(&[&a[..], b].concat())
}

/// A block of a coinbase and two transactions with witnesses, committed
/// as BIP141 asks: each transaction is in it with its witness, at its
/// index by its path, and its witness reads back.
#[test]
fn a_witness_in_a_block() {
    let big = vec![0xab; 520];
    let funding = ([12; 32], 2);
    let txs = [tx(vec![input([1; 32], 0, &[b"other"]), input(funding.0, funding.1, &[&big, b"two", b""])]), tx(vec![input([2; 32], 5, &[b"x"])])];
    let reserved = [0x5a; 32];
    let mut coinbase = tx(vec![input([0; 32], u32::MAX, &[&reserved])]);
    coinbase.input[0].script_sig = ScriptBuf::from_bytes(vec![1, 7]);
    let mut block = Block {
        header: Header { version: BlockVersion::TWO, prev_blockhash: BlockHash::all_zeros(), merkle_root: TxMerkleNode::all_zeros(), time: 0, bits: CompactTarget::from_consensus(0x207fffff), nonce: 0 },
        txdata: [vec![coinbase], txs.to_vec()].concat(),
    };
    let commitment = Block::compute_witness_commitment(&block.witness_root().unwrap(), &reserved);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(commitment.as_byte_array());
    block.txdata[0].output.push(TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(script) });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    assert!(block.check_merkle_root() && block.check_witness_commitment());

    let header = btc::Header(serialize(&block.header).try_into().unwrap());
    let mut stripped = block.txdata[0].clone();
    stripped.input[0].witness = Witness::new();
    let cb = serialize(&stripped);
    let txid = |i: usize| block.txdata[i].compute_txid().to_byte_array();
    let wtxid = |i: usize| block.txdata[i].compute_wtxid().to_byte_array();
    let coinbase_path = [txid(1), pair(&txid(2), &txid(2))];
    let paths = [(1, [[0; 32], pair(&wtxid(2), &wtxid(2))]), (2, [wtxid(2), pair(&[0; 32], &wtxid(1))])];
    assert_eq!(btc::witness_commitment(&cb), Some(commitment.to_byte_array()));
    for (i, path) in paths {
        let raw = serialize(&block.txdata[i]);
        assert!(btc::witness_in_block(&raw, &header, i as u32, &path, &cb, &coinbase_path, &reserved));
        // the wrong index, reserved value or path; the non-witness serialization
        assert!(!btc::witness_in_block(&raw, &header, 3 - i as u32, &path, &cb, &coinbase_path, &reserved));
        assert!(!btc::witness_in_block(&raw, &header, i as u32, &path, &cb, &coinbase_path, &[0; 32]));
        assert!(!btc::witness_in_block(&raw, &header, i as u32, &path[..1], &cb, &coinbase_path, &reserved));
        let mut bare = block.txdata[i].clone();
        bare.input.iter_mut().for_each(|t| t.witness = Witness::new());
        assert!(btc::parse_witness_tx(&serialize(&bare)).is_none());
        assert!(!btc::witness_in_block(&serialize(&bare), &header, i as u32, &path, &cb, &coinbase_path, &reserved));
    }
    // the witness, input by input, as rust-bitcoin wrote it
    let raw = serialize(&block.txdata[1]);
    let w = btc::parse_witness_tx(&raw).unwrap();
    assert_eq!(w.tx.inputs[1], btc::OutPoint { txid: funding.0, vout: funding.1 });
    assert_eq!(w.witness, vec![vec![&b"other"[..]], vec![&big[..], b"two", b""]]);
    assert!(btc::parse_witness_tx(&raw[..raw.len() - 1]).is_none());
}
