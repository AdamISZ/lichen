//! The formats a refactor must keep: a contract's record (the wallet's
//! and the hub's files), the opening's request and offer (the wire). The
//! fixtures in `tests/data/formats` were written by the code of
//! 2026-10-27 (`write_fixtures`); every later version must read them back
//! unchanged, and rebuild the same contract from the record: its address,
//! its pre-signed set, the signatures on it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{SecretKey, SECP256K1};
use bitcoin::{Amount, OutPoint, Transaction, TxOut, Txid};
use lichen_proto::{all_moves, params, tail_keys, windows, Checkpoint, Net, OpenOffer, OpenRequest, Record, Statement};
use lngap_btc::keys::Seed;
use lngap_channel::{PartyKeys, Role};
use lngap_lamport::winternitz::{WotsParams, WotsSecret};
use lngap_sessions::contract::{sign_all, Program};
use serde_json::Value;

fn data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/formats")
}

fn statement() -> Statement {
    Statement::Mock { session: 0, returns: vec![] }
}

fn key(label: &str, n: u32) -> WotsSecret {
    WotsSecret::from_entropy(WotsParams::for_bytes(n), Seed::from_label(label).derive_bytes("wots"))
}

/// A mock contract opened on regtest with every optional part: windows,
/// a checkpoint, the jump list's tail; its request and offer.
fn build(program: &Program) -> (Record, OpenRequest, OpenOffer) {
    let (alice, hub) = (PartyKeys::from_seed(Role::User, Seed::from_label("fmt/alice")), PartyKeys::from_seed(Role::Hub, Seed::from_label("fmt/hub")));
    let m = program.depths();
    let side = |who: &str, odd: bool| -> Vec<Vec<lngap_lamport::winternitz::WotsPublic>> {
        (1..=m).filter(|d| (d % 2 == 1) == odd).map(|d| program.field_bytes(d).into_iter().enumerate().map(|(f, n)| key(&format!("fmt/{who}/move/{d}/{f}"), n).public()).collect()).collect()
    };
    let (a_moves, h_moves) = (side("alice", true), side("hub", false));
    let inputs: Vec<_> = (0..program.info.input_words).map(|j| WotsSecret::from_entropy(lngap_zk::final_d60::input_key_params(), Seed::from_label(&format!("fmt/input/{j}")).derive_bytes("wots")).public()).collect();
    use lngap_ladder::tail::{chunk_fields, CHUNKS};
    let path: Vec<Vec<_>> = (0..CHUNKS).map(|c| chunk_fields(c).iter().enumerate().map(|(f, n)| key(&format!("fmt/path/{c}/{f}"), *n as u32).public()).collect()).collect();
    let hops: Vec<_> = (0..CHUNKS).map(|c| key(&format!("fmt/hop/{c}"), 1).public()).collect();
    let req = OpenRequest {
        alice: alice.public(),
        l2_address: [7; 32],
        deposit: 30_000,
        bits: 16,
        reserve: 250_000,
        moves: a_moves.clone(),
        inputs: inputs.clone(),
        hops: hops.clone(),
        cid: 1000,
        deposit_coin: (OutPoint { txid: Txid::from_byte_array([3; 32]), vout: 0 }, TxOut { value: Amount::from_sat(311_000), script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51, 0x20, 1, 2]) }),
        fee_spk: bitcoin::ScriptBuf::from_bytes(vec![0x51, 0x20, 4, 5]),
    };
    let terms = lichen_proto::terms(1000, &req, 5_000, 300_000).unwrap();
    let checkpoint = Checkpoint { height: 101, hash: bitcoin::BlockHash::from_byte_array([9; 32]), bits: 0x207fffff };
    let mut record = Record {
        statement: statement().id().to_string(),
        network: Net::Regtest,
        deployment: [5; 32],
        checkpoint: Some(checkpoint),
        terms,
        pubs: [alice.public(), hub.public()],
        moves: all_moves(&a_moves, &h_moves),
        inputs,
        tail: tail_keys(program, &path, &hops).unwrap(),
        l2_address: req.l2_address,
        funding: OutPoint { txid: Txid::from_byte_array([8; 32]), vout: 0 },
        hub_sigs: HashMap::new(),
        alice_sigs: HashMap::new(),
        windows: Some(windows(Net::Regtest)),
    };
    let c = record.contract(&statement(), program).unwrap();
    let set = c.presign(record.funding).unwrap();
    record.hub_sigs = sign_all(&set, &hub.payment).unwrap();
    record.alice_sigs = sign_all(&set, &alice.payment).unwrap();
    let funding = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn { previous_output: req.deposit_coin.0, ..Default::default() }],
        output: vec![TxOut { value: c.value(), script_pubkey: c.tree().unwrap().script_pubkey() }],
    };
    let offer = OpenOffer {
        cid: 1000,
        t_close: 5_000,
        reserve_hub: 300_000,
        hub: hub.public(),
        moves: h_moves,
        path,
        funding,
        hub_coins: vec![],
        hub_sigs: record.hub_sigs.clone(),
        mint_point: SecretKey::from_slice(&[0x11; 32]).unwrap().public_key(SECP256K1),
        mint_index: 4,
        windows: record.windows,
        checkpoint: Some(checkpoint),
    };
    let _ = params(Net::Regtest);
    (record, req, offer)
}

/// The contract a record rebuilds: its address and its pre-signed set,
/// hashed.
fn contract_of(record: &Record, program: &Program) -> String {
    let c = record.contract(&statement(), program).unwrap();
    let set = record.presigned(&c).unwrap();
    let mut e = sha256::Hash::engine();
    for p in &set {
        e.input(p.name.as_bytes());
        e.input(&bitcoin::consensus::encode::serialize(&p.tx));
    }
    format!("{} {} {}", c.tree().unwrap().script_pubkey().to_hex_string(), set.len(), sha256::Hash::from_engine(e))
}

/// Writes the fixtures (run once, on the code whose formats they record).
#[test]
#[ignore]
fn write_fixtures() {
    let dir = std::env::temp_dir().join(format!("lichen-formats-{}", std::process::id()));
    let program = statement().program(&dir).unwrap();
    let (record, req, offer) = build(&program);
    std::fs::create_dir_all(data()).unwrap();
    let write = |name: &str, v: String| std::fs::write(data().join(name), v + "\n").unwrap();
    write("record.json", serde_json::to_string(&record).unwrap());
    write("open-request.json", serde_json::to_string(&req).unwrap());
    write("open-offer.json", serde_json::to_string(&offer).unwrap());
    write("contract.txt", contract_of(&record, &program));
    let _ = std::fs::remove_dir_all(&dir);
}

fn read(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(data().join(name)).unwrap()).unwrap()
}

/// Each fixture reads, and writes back as it was.
fn round_trip<T: serde::de::DeserializeOwned + serde::Serialize>(name: &str) -> T {
    let v = read(name);
    let t: T = serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(serde_json::to_value(&t).unwrap(), v, "{name} written back differently");
    t
}

#[test]
fn the_formats_kept() {
    let dir = std::env::temp_dir().join(format!("lichen-formats-read-{}", std::process::id()));
    let program = statement().program(&dir).unwrap();
    let record: Record = round_trip("record.json");
    round_trip::<OpenRequest>("open-request.json");
    round_trip::<OpenOffer>("open-offer.json");
    // a record from before windows, checkpoints and the network field
    // reads, its missing fields defaulted
    let mut old = read("record.json");
    for k in ["windows", "checkpoint", "network"] {
        old.as_object_mut().unwrap().remove(k);
    }
    let old: Record = serde_json::from_value(old).unwrap();
    assert!(old.windows.is_none() && old.checkpoint.is_none() && old.network == Net::default());
    // the record rebuilds the same contract, and its signatures verify
    let want = std::fs::read_to_string(data().join("contract.txt")).unwrap();
    assert_eq!(contract_of(&record, &program), want.trim());
    let _ = std::fs::remove_dir_all(&dir);
}
