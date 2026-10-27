//! The fixed statement's signature on `b` (`lichen_withdraw::fixed`) has
//! ln-gap's digits and checksum, as `request`'s signature on `b` (an
//! input word's: 4 bytes, big-endian), so that `respond`'s script can
//! compare the two digit by digit, whatever each chain's hash. (Here, not
//! in `lichen-withdraw`: the guests build that crate alone.)

use lichen_withdraw::fixed::digits;
use lngap_lamport::winternitz::{WotsParams, WotsSecret};

#[test]
fn the_digits_are_ln_gaps() {
    let sk = WotsSecret::from_entropy(WotsParams::for_bytes(4), [3; 32]);
    for b in [0u32, 9, 0x0102_0304, 1_000_000, u32::MAX] {
        assert_eq!(sk.sign(&b.to_be_bytes()).unwrap().digits, digits(b));
    }
}
