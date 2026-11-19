//! What a front chooses of the graph: fixed outputs after a link's anchor
//! (`FrontLink::extra`), and what `wrongly_challenged_k` pays
//! (`Front::wrongly_challenged`, the hub by default).

use lichen_babe::graph::{link_leaf, Front, FrontLink, Graph, Payout, Tail, Windows};
use lichen_babe::reveal::{AdaptorKeys, LamportKey};
use lichen_babe::setup::DIGITS;
use lichen_btc::bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};
use lichen_btc::keys::Seed;
use lichen_contract::{ContractParams, Core, PartyKeys, PartyPubKeys, Presign, Role, Terms, ANCHOR};

/// A front of one link, `request`, with `extra` outputs; its other
/// payout, "half", pays everything to the user.
struct OneLink {
    terms: Terms,
    params: ContractParams,
    pubs: [PartyPubKeys; 2],
    extra: Vec<TxOut>,
    wrongly: Option<Payout>,
}

impl Front for OneLink {
    fn core(&self) -> Core<'_> {
        Core { terms: &self.terms, params: &self.params, pubs: &self.pubs }
    }
    fn links(&self) -> anyhow::Result<Vec<FrontLink>> {
        let ctx = self.core().ctx();
        Ok(vec![FrontLink { name: "request", poster: Role::User, leaf: link_leaf(&ctx, "request", true, |b| b), shape: vec![], extra: self.extra.clone(), terminal: "request_timeout", window: 3, pays: Payout::User }])
    }
    fn pay(&self, which: Payout, available: Amount) -> anyhow::Result<Vec<TxOut>> {
        let to = |r: Role| vec![TxOut { value: available, script_pubkey: self.pubs[r.idx()].payout_spk.clone() }];
        Ok(match which {
            Payout::Hub => to(Role::Hub),
            Payout::User | Payout::Other("half") => to(Role::User),
            Payout::Other(other) => anyhow::bail!("no payout {other}"),
        })
    }
    fn success(&self) -> Payout {
        Payout::Other("half")
    }
    fn wrongly_challenged(&self) -> Payout {
        self.wrongly.unwrap_or(Payout::Hub)
    }
}

fn graph(extra: Vec<TxOut>, wrongly: Option<Payout>) -> anyhow::Result<Graph> {
    let alice = PartyKeys::from_seed(Role::User, Seed::from_label("alice"));
    let hub = PartyKeys::from_seed(Role::Hub, Seed::from_label("hub"));
    let terms = Terms { id: 1, unit: Amount::from_sat(1_000), bits: 10, low_bits: 0, deposit: 400, t_close: 100_000, reserve_alice: Amount::from_sat(20_000), reserve_hub: Amount::from_sat(100_000) };
    let front = OneLink { terms, params: ContractParams::regtest(Amount::ZERO), pubs: [alice.public(), hub.public()], extra, wrongly };
    let seed = Seed::from_label("hub/prover");
    let tail = Tail { lamport: LamportKey::new(&seed, DIGITS).public(), adaptor: AdaptorKeys::new(&seed, DIGITS).public(), hmsg: vec![[1; 32], [2; 32]], windows: Windows { delta2: 3, delta1: 3 } };
    Graph::new(Box::new(front), tail)
}

fn presign(g: &Graph) -> anyhow::Result<Vec<Presign>> {
    g.presign(OutPoint { txid: Txid::from_raw_hash(lichen_btc::bitcoin::hashes::Hash::all_zeros()), vout: 0 })
}

fn named<'a>(set: &'a [Presign], name: &str) -> &'a Presign {
    set.iter().find(|p| p.name == name).unwrap()
}

fn slot(sats: u64) -> TxOut {
    TxOut { value: Amount::from_sat(sats), script_pubkey: ScriptBuf::new_op_return([7u8; 4]) }
}

#[test]
fn a_links_extra_outputs_follow_its_anchor() {
    let plain = presign(&graph(vec![], None).unwrap()).unwrap();
    let with = presign(&graph(vec![slot(330), slot(1_000)], None).unwrap()).unwrap();
    let (p, w) = (named(&plain, "request"), named(&with, "request"));
    assert_eq!(p.tx.output.len(), 2, "the chain's output and the anchor");
    assert_eq!(w.tx.output.len(), 4);
    assert_eq!(w.tx.output[1].value, ANCHOR);
    assert_eq!(&w.tx.output[2..], &[slot(330), slot(1_000)]);
    // they come out of what the chain carries, and the link is larger
    // with them: a floor of its size
    let less = p.tx.output[0].value - w.tx.output[0].value;
    assert!(less > Amount::from_sat(1_330) && less < Amount::from_sat(1_330 + 100), "{less}");
    // a dust extra output, or one the chain can't carry, is refused
    assert!(presign(&graph(vec![slot(329)], None).unwrap()).is_err());
    assert!(presign(&graph(vec![slot(2_000_000)], None).unwrap()).is_err());
}

#[test]
fn wrongly_challenged_pays_the_hub_unless_the_front_chooses() {
    let g = graph(vec![], None).unwrap();
    let hub = g.core().pubs[1].payout_spk.clone();
    let set = presign(&g).unwrap();
    for k in 0..2 {
        let w = named(&set, &format!("wrongly_challenged_{k}"));
        assert_eq!(w.tx.output.len(), 1);
        assert_eq!(w.tx.output[0].script_pubkey, hub, "everything to the hub");
    }
    let g = graph(vec![], Some(Payout::Other("half"))).unwrap();
    let alice = g.core().pubs[0].payout_spk.clone();
    let set = presign(&g).unwrap();
    for name in ["wrongly_challenged_1", "success"] {
        let outs = &named(&set, name).tx.output;
        assert_eq!((outs.len(), &outs[0].script_pubkey), (1, &alice), "{name}: as success");
    }
}
