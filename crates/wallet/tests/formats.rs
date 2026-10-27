//! The tower's package, a format a refactor must keep (as
//! crates/proto/tests/formats.rs for the record and the wire). The
//! fixture was written by the code of 2026-10-27 (`write_fixture`), on the
//! proto fixture's record; every later version must read it back
//! unchanged.

use std::path::{Path, PathBuf};

use lichen_proto::Record;
use lichen_wallet::tower::{Package, VERSION};
use serde_json::Value;

fn data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

/// Writes the fixture (run once, on the code whose format it records).
#[test]
#[ignore]
fn write_fixture() {
    let record: Record = serde_json::from_str(&std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../proto/tests/data/formats/record.json")).unwrap()).unwrap();
    let h = |i: usize| hex::encode([i as u8; 32]);
    let pkg = Package {
        version: VERSION,
        sequencer: "http://127.0.0.1:1".into(),
        b: 5_120,
        note: 3,
        b_wire: (0..20).map(|i| hex::encode([i as u8; 20])).collect(),
        inputs: (0..record.bitvmx().unwrap().inputs.len()).map(|j| (j != 0).then(|| h(j))).collect(),
        moves: record.bitvmx().unwrap().moves.iter().enumerate().map(|(d, fs)| if d % 2 == 0 { (0..fs.len()).map(|f| h(100 + d * 4 + f)).collect() } else { vec![] }).collect(),
        hops: (0..8).map(|c| h(200 + c)).collect(),
        fee_key: h(250),
        claim: Some("00".into()),
        input: None,
        chain: None,
        anchor: None,
        record,
    };
    std::fs::write(data().join("package.json"), serde_json::to_string(&pkg).unwrap() + "\n").unwrap();
}

#[test]
fn the_package_kept() {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(data().join("package.json")).unwrap()).unwrap();
    let p: Package = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(serde_json::to_value(&p).unwrap(), v, "the package written back differently");
}
