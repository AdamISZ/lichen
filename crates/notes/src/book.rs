//! The hub's book: every note it issued, which are spent and by what, the
//! spends it recorded with their grants and owners' signatures (the
//! evidence a dispute cites), and each owner's mailbox of notes to
//! collect. Kept whole in one file, written atomically after each change
//! (a prototype's ledger: its size grows with the notes).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{bail, ensure, Context, Result};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use lngap_btc::adaptor::adaptor_sign;
use serde::{Deserialize, Serialize};

use crate::{auth_msg, issue, tagged, unlock, verify, xonly, Claim, Delivery, Grant, Hash, Note, Presig, Settled, Spend};

/// What spent a note.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Spent {
    /// A recorded spend, by its id.
    Spend(String),
    /// A claim on contract `cid` (a withdrawal, or an exit), by its `E`.
    Claim { cid: u32, e: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    note: Note,
    #[serde(default)]
    spent: Option<Spent>,
}

/// A spend the hub recorded: with its grant and the owners' signatures on
/// both (what a counter cites), and its unlock.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Recorded {
    pub spend: Spend,
    pub grant: Grant,
    pub sigs: Vec<String>,
    pub t: SecretKey,
}

/// A claim the hub took (a withdrawal's), and the change it issued.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Taken {
    cid: u32,
    change: Option<Settled>,
}

#[derive(Default, Serialize, Deserialize)]
struct St {
    notes: BTreeMap<String, Entry>,
    /// Granted, not yet signed by the owners.
    pending: BTreeMap<String, (Spend, Grant)>,
    recorded: BTreeMap<String, Recorded>,
    /// Claims taken, by `E`.
    claims: BTreeMap<String, Taken>,
    /// Each owner's notes to collect, in the order made.
    mailbox: BTreeMap<String, Vec<Delivery>>,
}

pub struct Book {
    path: PathBuf,
    issuer: Keypair,
    s: Mutex<St>,
}

impl Book {
    /// The book at `path` (a new one if there's none), of the hub whose
    /// issuer key is `issuer`.
    pub fn open(path: PathBuf, issuer: Keypair) -> Result<Book> {
        let s = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("the book at {}", path.display()))?,
            Err(_) => St::default(),
        };
        Ok(Book { path, issuer, s: Mutex::new(s) })
    }

    pub fn issuer(&self) -> Hash {
        xonly(&self.issuer)
    }

    fn save(&self, s: &St) -> Result<()> {
        lichen_ledger::files::write_atomic(&self.path, &serde_json::to_vec(s)?)?;
        Ok(())
    }

    fn deliver(s: &mut St, settled: &Settled, from: Hash) {
        let mb = s.mailbox.entry(hex::encode(settled.note.owner)).or_default();
        if !mb.iter().any(|d| d.settled.note.id == settled.note.id) {
            mb.push(Delivery { settled: settled.clone(), from });
        }
    }

    /// Issue `value` to `owner` outright, as the note named by `tag` (asked
    /// again, the same note).
    pub fn issue(&self, tag: &[u8], owner: Hash, value: u64) -> Result<Settled> {
        let note = Note { id: tagged("lichen/notes/issue", &[tag]), owner, value };
        let mut s = self.s.lock().unwrap();
        if let Some(e) = s.notes.get(&hex::encode(note.id)) {
            ensure!(e.note == note, "note {} issued already, otherwise", hex::encode(note.id));
        } else {
            s.notes.insert(hex::encode(note.id), Entry { note, spent: None });
        }
        let settled = issue(&self.issuer, note);
        Book::deliver(&mut s, &settled, note.id);
        self.save(&s)?;
        Ok(settled)
    }

    /// A note named by `tag` for `value` to `owner`, pre-signed under `T`:
    /// settled once `t` is known (a contract's deposit, whose `t` its
    /// funding puts on chain). Not in the book until [`Book::activate`].
    pub fn pre_issue(&self, tag: &[u8], owner: Hash, value: u64, t_point: &PublicKey) -> (Note, Presig) {
        let note = Note { id: tagged("lichen/notes/issue", &[tag]), owner, value };
        let p = adaptor_sign(&self.issuer, &bitcoin::secp256k1::Message::from_digest(note.digest()), t_point);
        (note, Presig::from(&p))
    }

    /// A pre-issued note made good: in the book, and its owner's to collect.
    pub fn activate(&self, note: Note) -> Result<Settled> {
        let mut s = self.s.lock().unwrap();
        match s.notes.get(&hex::encode(note.id)) {
            Some(e) => ensure!(e.note == note, "note {} issued already, otherwise", hex::encode(note.id)),
            None => {
                s.notes.insert(hex::encode(note.id), Entry { note, spent: None });
            }
        }
        let settled = issue(&self.issuer, note);
        Book::deliver(&mut s, &settled, note.id);
        self.save(&s)?;
        Ok(settled)
    }

    /// Each input in the book as given, unspent.
    fn inputs_live(s: &St, spend: &Spend) -> Result<()> {
        for n in &spend.inputs {
            let e = s.notes.get(&hex::encode(n.id)).with_context(|| format!("no note {}", hex::encode(n.id)))?;
            ensure!(e.note == *n, "note {} isn't as the spend says", hex::encode(n.id));
            ensure!(e.spent.is_none(), "note {} is spent", hex::encode(n.id));
        }
        Ok(())
    }

    /// A grant on `spend` (`POST /grant`): its inputs live, its totals
    /// equal. Asked again, the same grant.
    pub fn grant(&self, spend: Spend) -> Result<Grant> {
        spend.check()?;
        let sid = spend.id();
        let mut s = self.s.lock().unwrap();
        if let Some(r) = s.recorded.get(&hex::encode(sid)) {
            return Ok(r.grant.clone());
        }
        Book::inputs_live(&s, &spend)?;
        let g = Grant::make(&self.issuer, &spend, &unlock(&self.issuer, &sid));
        s.pending.insert(hex::encode(sid), (spend, g.clone()));
        Ok(g)
    }

    /// Record a granted spend, its owners having signed it with the grant
    /// (`POST /spend`): its inputs spent, its outputs in the book and in
    /// their owners' mailboxes, and `t`, which opens them. Asked again, the
    /// same `t`.
    pub fn record(&self, sid: &Hash, sigs: &[String]) -> Result<SecretKey> {
        let mut s = self.s.lock().unwrap();
        if let Some(r) = s.recorded.get(&hex::encode(sid)) {
            return Ok(r.t);
        }
        let (spend, grant) = s.pending.get(&hex::encode(sid)).cloned().context("no grant on that spend: ask for one")?;
        ensure!(sigs.len() == spend.inputs.len(), "{} signatures for {} inputs", sigs.len(), spend.inputs.len());
        let msg = auth_msg(sid, &grant.commitment());
        for (n, sig) in spend.inputs.iter().zip(sigs) {
            let sig: [u8; 64] = hex::decode(sig).ok().and_then(|v| v.try_into().ok()).context("a signature of other than 64 bytes")?;
            ensure!(verify(&n.owner, &msg, &sig), "note {}'s owner didn't sign the spend", hex::encode(n.id));
        }
        Book::inputs_live(&s, &spend)?;
        for n in &spend.inputs {
            s.notes.get_mut(&hex::encode(n.id)).expect("live").spent = Some(Spent::Spend(hex::encode(sid)));
        }
        let t = unlock(&self.issuer, sid);
        for settled in grant.open(&self.issuer(), &spend, &t)? {
            s.notes.insert(hex::encode(settled.note.id), Entry { note: settled.note, spent: None });
            Book::deliver(&mut s, &settled, *sid);
        }
        s.pending.remove(&hex::encode(sid));
        s.recorded.insert(hex::encode(sid), Recorded { spend, grant, sigs: sigs.to_vec(), t });
        self.save(&s)?;
        Ok(t)
    }

    /// `owner`'s deliveries from the `from`th on.
    pub fn mailbox(&self, owner: &Hash, from: usize) -> Vec<Delivery> {
        let s = self.s.lock().unwrap();
        s.mailbox.get(&hex::encode(owner)).map(|v| v.iter().skip(from).cloned().collect()).unwrap_or_default()
    }

    /// `owner`'s unspent notes, settled (a wallet restored from its key).
    pub fn unspent_of(&self, owner: &Hash) -> Vec<Settled> {
        let s = self.s.lock().unwrap();
        s.notes.values().filter(|e| e.note.owner == *owner && e.spent.is_none()).map(|e| issue(&self.issuer, e.note)).collect()
    }

    /// What spent note `id`, if anything.
    pub fn spent(&self, id: &Hash) -> Option<Spent> {
        self.s.lock().unwrap().notes.get(&hex::encode(id)).and_then(|e| e.spent.clone())
    }

    /// A spend recorded.
    pub fn recorded(&self, sid: &Hash) -> Option<Recorded> {
        self.s.lock().unwrap().recorded.get(&hex::encode(sid)).cloned()
    }

    /// Take a claim (`claim`, checked by the caller against its contract,
    /// worth `total` sats, `paid` of them paid out): its notes spent, and
    /// what they hold beyond `paid` issued back to the owner as change.
    /// Taken again, the same change.
    pub fn take_claim(&self, claim: &Claim, total: u64, paid: u64) -> Result<Option<Settled>> {
        let e = claim.e();
        let mut s = self.s.lock().unwrap();
        if let Some(t) = s.claims.get(&hex::encode(e)) {
            ensure!(t.cid == claim.cid, "that claim was taken on contract {}", t.cid);
            return Ok(t.change.clone());
        }
        for n in &claim.notes {
            let entry = s.notes.get(&hex::encode(n.note.id)).with_context(|| format!("no note {}", hex::encode(n.note.id)))?;
            ensure!(entry.note == n.note, "note {} isn't as the claim says", hex::encode(n.note.id));
            if let Some(sp) = &entry.spent {
                bail!("note {} is spent ({sp:?})", hex::encode(n.note.id));
            }
        }
        for n in &claim.notes {
            s.notes.get_mut(&hex::encode(n.note.id)).expect("checked").spent = Some(Spent::Claim { cid: claim.cid, e: hex::encode(e) });
        }
        let change = (total > paid).then(|| {
            let note = Note { id: tagged("lichen/notes/change", &[&e]), owner: claim.owner, value: total - paid };
            s.notes.insert(hex::encode(note.id), Entry { note, spent: None });
            let settled = issue(&self.issuer, note);
            Book::deliver(&mut s, &settled, e);
            settled
        });
        s.claims.insert(hex::encode(e), Taken { cid: claim.cid, change: change.clone() });
        self.save(&s)?;
        Ok(change)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{keypair, sign, Output};

    #[test]
    fn a_payment_through_the_book() {
        let dir = std::env::temp_dir().join(format!("lichen-notes-book-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (hub, alice, bob) = (keypair(&[1; 32]).unwrap(), keypair(&[2; 32]).unwrap(), keypair(&[3; 32]).unwrap());
        let book = Book::open(dir.join("book.json"), hub).unwrap();
        let n = book.issue(b"mint", xonly(&alice), 1000).unwrap();
        let spend = Spend { inputs: vec![n.note], outputs: vec![Output { owner: xonly(&bob), value: 700 }, Output { owner: xonly(&alice), value: 300 }] };
        let g = book.grant(spend.clone()).unwrap();
        g.verify(&book.issuer(), &spend).unwrap();
        // the wrong signer is refused, the right one recorded
        let msg = auth_msg(&g.sid, &g.commitment());
        assert!(book.record(&g.sid, &[hex::encode(sign(&bob, &msg))]).is_err());
        let t = book.record(&g.sid, &[hex::encode(sign(&alice, &msg))]).unwrap();
        assert_eq!(g.open(&book.issuer(), &spend, &t).unwrap().len(), 2);
        // spent: no second grant on it
        assert!(book.grant(Spend { inputs: vec![n.note], outputs: vec![Output { owner: xonly(&bob), value: 1000 }] }).is_err());
        let bobs = book.mailbox(&xonly(&bob), 0);
        assert_eq!(bobs.len(), 1);
        assert_eq!(bobs[0].settled.note.value, 700);
        // reopened from its file: the same
        drop(book);
        let book = Book::open(dir.join("book.json"), keypair(&[1; 32]).unwrap()).unwrap();
        assert_eq!(book.unspent_of(&xonly(&bob)).len(), 1);
        assert_eq!(book.unspent_of(&xonly(&alice)).iter().map(|s| s.note.value).sum::<u64>(), 300);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
