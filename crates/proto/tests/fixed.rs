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

/// So are its digits and signatures on `E` and `K`, the exit's (32 and
/// 128 bytes).
#[test]
fn e_and_k_are_ln_gaps() {
    use lichen_withdraw::fixed::{digits_of, verify_msg, E_DIGITS, K_DIGITS, K_LEN};
    for (len, n) in [(32, E_DIGITS), (K_LEN, K_DIGITS)] {
        let sk = Wots256Secret::from_entropy(WotsParams::for_bytes(len as u32), [7; 32]);
        let key = sk.public().digits;
        assert_eq!(key.len(), n);
        for fill in [0u8, 0x5a, 0xff] {
            let msg = vec![fill; len];
            let sig = sk.sign(&msg).unwrap();
            assert_eq!(sig.digits, digits_of(&msg));
            assert!(verify_msg(&key, &sig.hashes, &msg));
            let mut other = msg.clone();
            other[len - 1] ^= 1;
            assert!(!verify_msg(&key, &sig.hashes, &other));
        }
    }
}
