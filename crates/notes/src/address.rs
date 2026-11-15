//! L2 addresses as people see them: bech32m (BIP350), `tlc1…` on the test
//! networks and `lc1…` on mainnet. The data: a version byte (0), the
//! account's owner (32 bytes, an x-only key) and a 4-byte tag of the
//! deployment, the first 4 bytes of `SHA256("lichen/grants/hub" ‖
//! x(P_iss))`. 70 characters, within bech32m's 90, so any error of up to
//! four characters is caught. A wallet refuses an unknown version and
//! another deployment's tag: paid there, the money would be credit at a
//! hub where the payee has no contract. The tag is against mistakes, not
//! attack. (The API and the hub's book keep the owner, hex.)

use anyhow::{bail, ensure, Context, Result};
use bitcoin::bech32::{self, Bech32m, Hrp};
use sha2::{Digest, Sha256};

use crate::Hash;

/// The version this build writes and reads.
pub const VERSION: u8 = 0;
/// The tag's length, bytes.
pub const TAG_LEN: usize = 4;
/// The human-readable part: mainnet's, and the test networks'.
pub const HRP_MAIN: &str = "lc";
pub const HRP_TEST: &str = "tlc";

/// The deployment's tag: the first [`TAG_LEN`] bytes of
/// `SHA256("lichen/grants/hub" ‖ issuer)`.
pub fn tag(issuer: &Hash) -> [u8; TAG_LEN] {
    let mut s = Sha256::new();
    s.update(b"lichen/grants/hub");
    s.update(issuer);
    s.finalize()[..TAG_LEN].try_into().unwrap()
}

fn hrp(test: bool) -> Hrp {
    Hrp::parse_unchecked(if test { HRP_TEST } else { HRP_MAIN })
}

/// `owner`'s address in the deployment of `issuer`, lower case.
pub fn encode(owner: &Hash, issuer: &Hash, test: bool) -> String {
    let mut data = Vec::with_capacity(1 + 32 + TAG_LEN);
    data.push(VERSION);
    data.extend_from_slice(owner);
    data.extend_from_slice(&tag(issuer));
    bech32::encode::<Bech32m>(hrp(test), &data).expect("37 bytes are within bech32m's length")
}

/// The owner an address names, if it's a valid address of the deployment
/// of `issuer` on this kind of network (either case; spaces around it
/// ignored).
pub fn decode(text: &str, issuer: &Hash, test: bool) -> Result<Hash> {
    let text = text.trim();
    let (hrp_got, data) = match bech32::decode(text) {
        Ok(d) => d,
        Err(e) => {
            if text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!("a bare key, not an address: addresses start {}1 (with a checksum and the hub's tag)", hrp(test));
            }
            return Err(anyhow::anyhow!("not an address: {e}"));
        }
    };
    // bech32::decode takes bech32 and bech32m alike: insist on bech32m
    let want = hrp(test);
    if hrp_got != want {
        let other = hrp(!test);
        ensure!(hrp_got != other, "a {} address, and this wallet is on {}", if test { "mainnet" } else { "test network" }, if test { "a test network" } else { "mainnet" });
        bail!("not a lichen address (it starts {}1, not {}1)", hrp_got, want);
    }
    bech32::primitives::decode::CheckedHrpstring::new::<Bech32m>(text).map_err(|e| anyhow::anyhow!("not an address: {e}"))?;
    let (&version, rest) = data.split_first().context("an empty address")?;
    ensure!(version == VERSION, "an address of version {version}: this wallet reads version {VERSION}; update it");
    ensure!(rest.len() == 32 + TAG_LEN, "an address of {} bytes, not {}", rest.len() + 1, 1 + 32 + TAG_LEN);
    let (owner, t) = rest.split_at(32);
    ensure!(t == tag(issuer), "an address for another hub (its tag {}, this hub's {}): paid here, it would be credit where the payee has no contract", hex::encode(t), hex::encode(tag(issuer)));
    Ok(owner.try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: Hash = [7; 32];
    const ISSUER: Hash = [9; 32];

    #[test]
    fn round_trips_and_is_70_characters() {
        let a = encode(&OWNER, &ISSUER, true);
        assert!(a.starts_with("tlc1"), "{a}");
        assert_eq!(a.len(), 70);
        assert_eq!(decode(&a, &ISSUER, true).unwrap(), OWNER);
        // either case, as a QR code carries it upper case
        assert_eq!(decode(&a.to_uppercase(), &ISSUER, true).unwrap(), OWNER);
        assert_eq!(decode(&format!("  {a}\n"), &ISSUER, true).unwrap(), OWNER);
        let m = encode(&OWNER, &ISSUER, false);
        assert!(m.starts_with("lc1") && m.len() == 69, "{m}");
        assert_eq!(decode(&m, &ISSUER, false).unwrap(), OWNER);
    }

    #[test]
    fn catches_typos() {
        let a = encode(&OWNER, &ISSUER, true);
        let alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        // every single-character substitution in the data part
        for i in 4..a.len() {
            for c in alphabet.chars() {
                if a.as_bytes()[i] as char == c {
                    continue;
                }
                let mut b = a.clone().into_bytes();
                b[i] = c as u8;
                assert!(decode(std::str::from_utf8(&b).unwrap(), &ISSUER, true).is_err(), "{i} {c}");
            }
        }
        // two adjacent characters swapped
        for i in 4..a.len() - 1 {
            let mut b = a.clone().into_bytes();
            if b[i] != b[i + 1] {
                b.swap(i, i + 1);
                assert!(decode(std::str::from_utf8(&b).unwrap(), &ISSUER, true).is_err());
            }
        }
    }

    #[test]
    fn refuses_another_deployment_network_version_or_encoding() {
        let a = encode(&OWNER, &ISSUER, true);
        assert!(decode(&a, &[8; 32], true).unwrap_err().to_string().contains("another hub"));
        assert!(decode(&a, &ISSUER, false).unwrap_err().to_string().contains("mainnet"));
        let mut data = vec![1u8];
        data.extend_from_slice(&OWNER);
        data.extend_from_slice(&tag(&ISSUER));
        let v1 = bech32::encode::<Bech32m>(hrp(true), &data).unwrap();
        assert!(decode(&v1, &ISSUER, true).unwrap_err().to_string().contains("version 1"));
        // the same data under bech32 (not m): refused
        data[0] = 0;
        let b32 = bech32::encode::<bech32::Bech32>(hrp(true), &data).unwrap();
        assert!(decode(&b32, &ISSUER, true).is_err());
        // a bare key: told what an address is
        assert!(decode(&hex::encode(OWNER), &ISSUER, true).unwrap_err().to_string().contains("bare key"));
        assert!(decode("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", &ISSUER, true).is_err());
    }
}
