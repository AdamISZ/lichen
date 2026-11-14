//! What the wallet and the hub send each other for a payment
//! (papers/lichen-grants-v0.5.6, §4.1, live receipt).
//!
//! 1. The payer: `POST /pay` ([`PayRequest`]: her half, the payee, the
//!    amount). The hub checks her half takes her live note.
//! 2. The payee finds it in `GET /incoming/<owner>` and answers with its
//!    half, `POST /half` ([`HalfRequest`]). The hub checks it, and grants
//!    the spend: the [`Payment`] now carries the sides and the grant.
//! 3. Each party reads it (`GET /payment/<id>`), checks its own new note's
//!    pre-signature and that the other side is the right owner, and signs
//!    `α`: `POST /sign` ([`SignRequest`]).
//! 4. With both signatures the hub records the spend, both accounts one
//!    step on, and releases the seed in the [`Payment`].
//!
//! `POST /cancel` ([`CancelRequest`]): a party in flight asks to cancel. If
//! the hub holds both signatures, the answer is the seed; otherwise it
//! refuses the spend from then on and reissues the note of each party
//! that signed, one step on. `GET /account/<owner>` ([`Account`]): an
//! account's live note.

use serde::{Deserialize, Serialize};

use crate::{hex32, hex64, Grant, Half, Hash, Settled, Sides};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayRequest {
    pub half: Half,
    #[serde(with = "hex32")]
    pub to: Hash,
    pub amount: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HalfRequest {
    pub id: String,
    pub half: Half,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub id: String,
    #[serde(with = "hex32")]
    pub owner: Hash,
    #[serde(with = "hex64")]
    pub psi: [u8; 64],
}

/// A cancel, signed by the party asking ([`cancel_msg`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CancelRequest {
    pub id: String,
    #[serde(with = "hex32")]
    pub owner: Hash,
    #[serde(with = "hex64")]
    pub sig: [u8; 64],
}

/// What a party signs to cancel payment `id`.
pub fn cancel_msg(id: &str) -> Hash {
    crate::core::tagged("cancel", &[id.as_bytes()])
}

/// One side of a spend: its owner, its half's digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Side {
    #[serde(with = "hex32")]
    pub owner: Hash,
    #[serde(with = "hex32")]
    pub h: Hash,
}

pub fn sides_to(s: &Sides) -> [Side; 2] {
    s.map(|(owner, h)| Side { owner, h })
}

pub fn sides_from(s: &[Side; 2]) -> Sides {
    s.map(|x| (x.owner, x.h))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    /// The payer's half in; the payee's awaited.
    Proposed,
    /// Both halves in, granted: signatures awaited.
    Granted,
    /// Both signed, recorded: both accounts one step on.
    Recorded,
    /// Refused from now on.
    Cancelled,
}

/// A payment as the hub shows it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payment {
    pub id: String,
    #[serde(with = "hex32")]
    pub from: Hash,
    #[serde(with = "hex32")]
    pub to: Hash,
    pub amount: u64,
    pub state: State,
    /// Once granted: the sides in owner order, the grant.
    #[serde(default)]
    pub sides: Option<[Side; 2]>,
    #[serde(default)]
    pub grant: Option<Grant>,
    /// The owners who have signed.
    #[serde(default)]
    pub signed: Vec<String>,
    /// Once recorded and released: the seed (hex).
    #[serde(default)]
    pub seed: Option<String>,
    /// Once cancelled: the reissued notes of the parties that signed.
    #[serde(default)]
    pub reissued: Vec<Settled>,
}

/// An account as the hub shows it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub live: Settled,
    /// A payment pending on it.
    #[serde(default)]
    pub busy: Option<String>,
    /// Closed by a claim (a withdrawal, an exit).
    #[serde(default)]
    pub closed: bool,
}
