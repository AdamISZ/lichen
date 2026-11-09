//! The fixed statement's signature on `b` (`lichen_withdraw::fixed`) has
//! ln-gap's digits and checksum, as `request`'s signature on `b` (an
//! input word's: 4 bytes, big-endian), so that `respond`'s script can
//! compare the two digit by digit, whatever each chain's hash. (Here, not
//! in `lichen-withdraw`: the guests build that crate alone.)

use lichen_withdraw::fixed::{digits, verify, HubAuth};
use lngap_lamport::winternitz::{Wots256Secret, WotsParams, WotsSecret};

#[test]
fn the_digits_are_ln_gaps() {
    let sk = WotsSecret::from_entropy(WotsParams::for_bytes(4), [3; 32]);
    for b in [0u32, 9, 0x0102_0304, 1_000_000, u32::MAX] {
        assert_eq!(sk.sign(&b.to_be_bytes()).unwrap().digits, digits(b));
    }
}

/// ln-gap's SHA-256 Winternitz signer is the hub's: what `respond`'s
/// script checks, the guest checks.
#[test]
fn the_hubs_signer_is_ln_gaps() {
    let sk = Wots256Secret::from_entropy(WotsParams::for_bytes(4), [5; 32]);
    let key = sk.public().digits.try_into().unwrap();
    for b in [0u32, 60, 1_000_000, u32::MAX] {
        let auth = HubAuth { key, sig: sk.sign(&b.to_be_bytes()).unwrap().hashes.try_into().unwrap() };
        assert!(verify(&auth, b));
        assert!(!verify(&auth, b ^ 1));
    }
}

/// The hub's statement reads `b`, `E` and the claim from `request`'s
/// witness as ln-gap's Winternitz signatures lay them out: what the
/// swapped game's `request` posts, the statement reads back.
#[test]
fn the_hubs_statement_reads_the_request() {
    let b_key = WotsSecret::from_entropy(WotsParams::for_bytes(4), [3; 32]);
    let e_key = WotsSecret::from_entropy(WotsParams::for_bytes(32), [4; 32]);
    let posted: Vec<u8> = (0..700u32).map(|i| i as u8).collect();
    for (b, e) in [(0u32, [0u8; 32]), (60, [0x5a; 32]), (u32::MAX, [0xff; 32])] {
        let mut wire = lichen_babe::hp::HubProves::request_wire(&b_key.sign(&b.to_be_bytes()).unwrap(), &e_key.sign(&e).unwrap(), &posted).unwrap();
        // the 2-of-2's signatures, the script, the control block
        wire.extend([vec![1; 64], vec![2; 64], vec![0x51], vec![0xc0; 33]]);
        let items: Vec<&[u8]> = wire.iter().map(Vec::as_slice).collect();
        let r = lichen_withdraw::hp::requested(&items).unwrap();
        assert_eq!((r.b, r.e, &r.posted[..]), (b, e, &posted[..]));
    }
}
