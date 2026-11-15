//! Byte strings as hex in JSON (`#[serde(with = "...")]` on a field),
//! where serde's default writes `[u8; N]` and `Vec<u8>` as arrays of byte
//! values. Reading takes either, so files written before (a hub's book and
//! contracts, a wallet's) still load. A format that isn't human-readable
//! keeps serde's default encoding, unchanged.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

/// Bytes read from hex or from an array of byte values.
fn any_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("bytes as hex, or an array of byte values")
        }
        fn visit_str<E: de::Error>(self, s: &str) -> Result<Vec<u8>, E> {
            hex::decode(s).map_err(|e| E::custom(format!("hex: {e}")))
        }
        fn visit_bytes<E: de::Error>(self, b: &[u8]) -> Result<Vec<u8>, E> {
            Ok(b.to_vec())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Vec<u8>, A::Error> {
            let mut v = Vec::with_capacity(a.size_hint().unwrap_or(0));
            while let Some(b) = a.next_element::<u8>()? {
                v.push(b);
            }
            Ok(v)
        }
    }
    d.deserialize_any(V)
}

/// `N` bytes, as hex in a human-readable format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx<const N: usize>(pub [u8; N]);

impl<const N: usize> Serialize for Hx<N>
where
    [u8; N]: Serialize,
{
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(self.0))
        } else {
            self.0.serialize(s)
        }
    }
}

impl<'de, const N: usize> Deserialize<'de> for Hx<N>
where
    [u8; N]: Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let v = any_bytes(d)?;
            let n = v.len();
            v.try_into().map(Hx).map_err(|_| de::Error::custom(format!("{n} bytes, not {N}")))
        } else {
            <[u8; N]>::deserialize(d).map(Hx)
        }
    }
}

/// Bytes of any length, as hex in a human-readable format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HxVec(pub Vec<u8>);

impl Serialize for HxVec {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(&self.0))
        } else {
            self.0.serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for HxVec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            any_bytes(d).map(HxVec)
        } else {
            Vec::<u8>::deserialize(d).map(HxVec)
        }
    }
}

/// `[u8; N]`.
pub mod fixed {
    use super::*;
    pub fn serialize<S: Serializer, const N: usize>(b: &[u8; N], s: S) -> Result<S::Ok, S::Error>
    where
        [u8; N]: Serialize,
    {
        Hx(*b).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error>
    where
        [u8; N]: Deserialize<'de>,
    {
        Hx::<N>::deserialize(d).map(|h| h.0)
    }
}

/// `Option<[u8; N]>`.
pub mod opt_fixed {
    use super::*;
    pub fn serialize<S: Serializer, const N: usize>(b: &Option<[u8; N]>, s: S) -> Result<S::Ok, S::Error>
    where
        [u8; N]: Serialize,
    {
        b.map(Hx).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<Option<[u8; N]>, D::Error>
    where
        [u8; N]: Deserialize<'de>,
    {
        Option::<Hx<N>>::deserialize(d).map(|o| o.map(|h| h.0))
    }
}

/// `Vec<u8>`.
pub mod bytes {
    use super::*;
    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        HxVec(b.to_vec()).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        HxVec::deserialize(d).map(|h| h.0)
    }
}

/// `Vec<[u8; N]>`.
pub mod vec_fixed {
    use super::*;
    pub fn serialize<S: Serializer, const N: usize>(v: &[[u8; N]], s: S) -> Result<S::Ok, S::Error>
    where
        [u8; N]: Serialize,
    {
        s.collect_seq(v.iter().map(|b| Hx(*b)))
    }
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<Vec<[u8; N]>, D::Error>
    where
        [u8; N]: Deserialize<'de>,
    {
        Vec::<Hx<N>>::deserialize(d).map(|v| v.into_iter().map(|h| h.0).collect())
    }
}

/// `Vec<[[u8; N]; M]>` (a Lamport key: per digit, a hash per value).
pub mod vec_rows {
    use super::*;
    pub fn serialize<S: Serializer, const N: usize, const M: usize>(v: &[[[u8; N]; M]], s: S) -> Result<S::Ok, S::Error>
    where
        [u8; N]: Serialize,
    {
        s.collect_seq(v.iter().map(|row| row.map(Hx).to_vec()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize, const M: usize>(d: D) -> Result<Vec<[[u8; N]; M]>, D::Error>
    where
        [u8; N]: Deserialize<'de>,
    {
        let rows = Vec::<Vec<Hx<N>>>::deserialize(d)?;
        rows.into_iter()
            .map(|r| {
                let n = r.len();
                <[Hx<N>; M]>::try_from(r).map(|a| a.map(|h| h.0)).map_err(|_| de::Error::custom(format!("a row of {n}, not {M}")))
            })
            .collect()
    }
}

/// `HashMap<String, Vec<u8>>` (signatures by name).
pub mod map_bytes {
    use super::*;
    pub fn serialize<S: Serializer>(m: &HashMap<String, Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        // in name order, so the same map writes the same text
        let sorted: BTreeMap<&String, HxVec> = m.iter().map(|(k, v)| (k, HxVec(v.clone()))).collect();
        sorted.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<HashMap<String, Vec<u8>>, D::Error> {
        HashMap::<String, HxVec>::deserialize(d).map(|m| m.into_iter().map(|(k, v)| (k, v.0)).collect())
    }
}

/// `BTreeMap<K, [u8; N]>`.
pub mod btree_fixed {
    use super::*;
    pub fn serialize<S: Serializer, K: Serialize + Ord, const N: usize>(m: &BTreeMap<K, [u8; N]>, s: S) -> Result<S::Ok, S::Error>
    where
        [u8; N]: Serialize,
    {
        s.collect_map(m.iter().map(|(k, v)| (k, Hx(*v))))
    }
    pub fn deserialize<'de, D: Deserializer<'de>, K: Deserialize<'de> + Ord, const N: usize>(d: D) -> Result<BTreeMap<K, [u8; N]>, D::Error>
    where
        [u8; N]: Deserialize<'de>,
    {
        BTreeMap::<K, Hx<N>>::deserialize(d).map(|m| m.into_iter().map(|(k, v)| (k, v.0)).collect())
    }
}

/// A Winternitz public key (ln-gap's `WotsPublicOf<[u8; N]>`): its
/// parameters, and its chains' ends as hex.
pub mod wots {
    use super::*;
    use lngap_lamport::winternitz::{WotsParams, WotsPublicOf};

    #[derive(Serialize)]
    struct Out<'a, const N: usize>
    where
        [u8; N]: Serialize,
    {
        params: &'a WotsParams,
        #[serde(with = "super::vec_fixed")]
        digits: &'a Vec<[u8; N]>,
    }
    #[derive(Deserialize)]
    #[serde(bound(deserialize = "[u8; N]: Deserialize<'de>"))]
    struct In<const N: usize> {
        params: WotsParams,
        #[serde(with = "super::vec_fixed")]
        digits: Vec<[u8; N]>,
    }

    pub fn serialize<S: Serializer, const N: usize>(k: &WotsPublicOf<[u8; N]>, s: S) -> Result<S::Ok, S::Error>
    where
        [u8; N]: Serialize,
    {
        Out { params: &k.params, digits: &k.digits }.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<WotsPublicOf<[u8; N]>, D::Error>
    where
        [u8; N]: Deserialize<'de>,
    {
        In::<N>::deserialize(d).map(|i| WotsPublicOf { params: i.params, digits: i.digits })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct T {
        #[serde(with = "fixed")]
        a: [u8; 4],
        #[serde(with = "opt_fixed")]
        o: Option<[u8; 2]>,
        #[serde(with = "bytes")]
        v: Vec<u8>,
        #[serde(with = "vec_rows")]
        r: Vec<[[u8; 2]; 2]>,
        #[serde(with = "map_bytes")]
        m: HashMap<String, Vec<u8>>,
        #[serde(with = "btree_fixed")]
        b: BTreeMap<u32, [u8; 1]>,
    }

    fn t() -> T {
        T { a: [1, 2, 3, 255], o: Some([9, 10]), v: vec![0, 171], r: vec![[[1, 2], [3, 4]]], m: HashMap::from([("x".into(), vec![1])]), b: BTreeMap::from([(7, [8])]) }
    }

    #[test]
    fn writes_hex() {
        let j = serde_json::to_string(&t()).unwrap();
        assert_eq!(j, r#"{"a":"010203ff","o":"090a","v":"00ab","r":[["0102","0304"]],"m":{"x":"01"},"b":{"7":"08"}}"#);
        assert_eq!(serde_json::from_str::<T>(&j).unwrap(), t());
    }

    #[test]
    fn reads_the_old_arrays() {
        let old = r#"{"a":[1,2,3,255],"o":[9,10],"v":[0,171],"r":[[[1,2],[3,4]]],"m":{"x":[1]},"b":{"7":[8]}}"#;
        assert_eq!(serde_json::from_str::<T>(old).unwrap(), t());
    }

    #[test]
    fn refuses_a_wrong_length() {
        assert!(serde_json::from_str::<T>(r#"{"a":"0102","o":null,"v":"","r":[],"m":{},"b":{}}"#).is_err());
        assert!(serde_json::from_str::<T>(r#"{"a":"01020304","o":null,"v":"zz","r":[],"m":{},"b":{}}"#).is_err());
    }
}
