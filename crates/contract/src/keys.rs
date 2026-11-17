//! The two parties, their keys, the contract's parameters, and the view a
//! leaf is built from ([`ContractCtx`]).

use bitcoin::key::{Keypair, XOnlyPublicKey};
use bitcoin::script::Builder;
use bitcoin::{Amount, ScriptBuf};
use lichen_btc::keys::{xonly, Seed};
use lichen_btc::script::BuilderExt;
use lichen_btc::taptree::{Leaf, TapTree};
use lichen_btc::tx::Timelock;
use serde::{Deserialize, Serialize};

/// Which party. Index 0 is Alice (the user), 1 the hub, everywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    User = 0,
    Hub = 1,
}

impl Role {
    pub const BOTH: [Role; 2] = [Role::User, Role::Hub];
    pub fn other(self) -> Role {
        match self {
            Role::User => Role::Hub,
            Role::Hub => Role::User,
        }
    }
    pub fn idx(self) -> usize {
        self as usize
    }
    pub fn name(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Hub => "hub",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Constants agreed at the opening (per network: `lichen_proto::params`).
/// Some fields date from ln-gap's channels and are unused here; they stay
/// so the structure, as serialized, is unchanged.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ContractParams {
    pub funding_amount: Amount,
    pub to_self_delay: u16,
    pub commit_fee: Amount,
    pub presign_fee: Amount,
    /// Outputs below this are omitted.
    pub dust: Amount,
    /// The window after a dispute's move, and Alice's wait on her payout
    /// (relative, `OP_CSV`).
    pub delta: u16,
    pub delta_prime: u16,
    /// Blocks of slack added when computing absolute deadlines.
    pub deadline_margin: u32,
}

impl ContractParams {
    pub fn regtest(funding_amount: Amount) -> ContractParams {
        ContractParams {
            funding_amount,
            to_self_delay: 6,
            commit_fee: Amount::from_sat(1_000),
            presign_fee: Amount::from_sat(1_000),
            dust: Amount::from_sat(330),
            delta: 6,
            delta_prime: 6,
            deadline_margin: 8,
        }
    }
    /// How far ahead of the current height an off-chain deadline is set.
    pub fn deadline_offset(&self) -> u32 {
        u32::from(self.to_self_delay) + u32::from(self.delta) + self.deadline_margin
    }
}

/// A party's public keys as the other sees them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartyPubKeys {
    pub funding: XOnlyPublicKey,
    /// Signs every 2-of-2 leaf.
    pub payment: XOnlyPublicKey,
    pub delayed: XOnlyPublicKey,
    /// Where this party's payouts go.
    pub payout_spk: ScriptBuf,
}

/// A party's secret keys, from its own seed. The labels are fixed: the
/// keys a seed gives must not change.
pub struct PartyKeys {
    pub role: Role,
    seed: Seed,
    pub funding: Keypair,
    pub payment: Keypair,
    pub delayed: Keypair,
    pub payout: Keypair,
}

impl std::fmt::Debug for PartyKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PartyKeys({})", self.role)
    }
}

impl PartyKeys {
    pub fn from_seed(role: Role, seed: Seed) -> PartyKeys {
        PartyKeys {
            role,
            funding: seed.keypair("funding"),
            payment: seed.keypair("payment"),
            delayed: seed.keypair("delayed"),
            payout: seed.keypair("payout"),
            seed,
        }
    }
    pub fn seed(&self) -> &Seed {
        &self.seed
    }
    pub fn payout_tree(&self) -> TapTree {
        payout_tree(&xonly(&self.payout))
    }
    pub fn public(&self) -> PartyPubKeys {
        PartyPubKeys {
            funding: xonly(&self.funding),
            payment: xonly(&self.payment),
            delayed: xonly(&self.delayed),
            payout_spk: self.payout_tree().script_pubkey(),
        }
    }
}

/// A single-leaf `<key> OP_CHECKSIG` taproot output.
pub fn payout_tree(key: &XOnlyPublicKey) -> TapTree {
    TapTree::new(vec![Leaf::new("claim", Builder::new().checksig(key).into_script(), Timelock::NONE)])
        .expect("one leaf")
}

/// What a leaf is built from: the parameters and both parties' keys
/// (Alice's, then the hub's).
#[derive(Clone, Debug)]
pub struct ContractCtx<'a> {
    pub params: &'a ContractParams,
    pub keys: &'a [PartyPubKeys; 2],
}

impl<'a> ContractCtx<'a> {
    pub fn key(&self, r: Role) -> &PartyPubKeys {
        &self.keys[r.idx()]
    }
    /// The 2-of-2 fragment of every pre-signed path: Alice's key first,
    /// the hub's second.
    pub fn two_of_two(&self, b: Builder) -> Builder {
        b.two_of_two(&self.keys[0].payment, &self.keys[1].payment)
    }
    pub fn two_of_two_verify(&self, b: Builder) -> Builder {
        b.two_of_two_verify(&self.keys[0].payment, &self.keys[1].payment)
    }
}
