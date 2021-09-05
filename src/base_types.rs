//! Defines the basic types to do crypto, committees and hold basic information.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::convert::TryInto;
use std::iter::FromIterator;

use rand::rngs::OsRng;

use ed25519_dalek::Digest;
use ed25519_dalek::Keypair;
use ed25519_dalek::Sha512;
use ed25519_dalek::{KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

use serde::{Deserialize, Serialize};

use crate::BigArray;

pub const DIGEST_SIZE: usize = 64;

pub type Address = [u8; PUBLIC_KEY_LENGTH];

#[derive(Clone, Serialize, Deserialize)]
pub struct BlockData {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

impl From<Vec<u8>> for BlockData {
    fn from(data: Vec<u8>) -> Self {
        BlockData { data }
    }
}

impl Borrow<[u8]> for BlockData {
    fn borrow(&self) -> &[u8] {
        &self.data[..]
    }
}

pub type InstanceID = [u8; 16];
pub type RoundID = u64;

pub type BlockDataDigest = [u8; DIGEST_SIZE];
pub type BlockHeaderDigest = [u8; DIGEST_SIZE];

pub type SigningSecretKey = [u8; KEYPAIR_LENGTH];

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureBytes {
    #[serde(with = "BigArray")]
    pub bytes: [u8; SIGNATURE_LENGTH],
}

impl SignatureBytes {
    pub fn new(bytes: [u8; SIGNATURE_LENGTH]) -> SignatureBytes {
        SignatureBytes { bytes }
    }
}

pub fn gen_keypair() -> (Address, SigningSecretKey) {
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);

    let public_key_bytes: Address = keypair.public.to_bytes();
    let secret_key_bytes: SigningSecretKey = keypair.to_bytes();

    (public_key_bytes, secret_key_bytes)
}

#[derive(Clone)]
pub struct VotingPower {
    total_votes: u64,
    votes: HashMap<Address, u64>,
}

impl VotingPower {
    pub fn get_votes(&self, a: &Address) -> Option<u64> {
        return self.votes.get(a).cloned();
    }

    /// The amount of stake to ensure that any two sets with that amount
    /// intersect on an honest node (honest unit of stake.)
    pub fn quorum_size(&self) -> u64 {
        let one_third = self.total_votes / 3;
        2 * one_third + 1
    }

    /// The amount of stake to ensure at least one unit of stake is
    /// controlled by an honest node (honest vote).
    pub fn one_honest_size(&self) -> u64 {
        let one_third = self.total_votes / 3;
        one_third + 1
    }

    /// Checks if an iterator of the form (Addr, _) represents
    /// votes forming a quorum
    pub fn sum_stake<'a, X, I>(&self, vals: I) -> u64
    where
        I: Iterator<Item = (&'a Address, X)>,
    {
        let mut votes = 0;
        for (addr, _) in vals {
            if !self.votes.contains_key(addr) {
                continue;
            }
            votes += self.votes[addr];
        }

        votes
    }

    /// Checks if an iterator of the form (Addr, _) represents
    /// votes forming a quorum
    pub fn has_quorum<'a, X, I>(&self, vals: I) -> bool
    where
        I: Iterator<Item = (&'a Address, X)>,
    {
        self.sum_stake(vals) >= self.quorum_size()
    }

    /// Checks if an iterator of the form (Addr, _) represents
    /// votes containing at least one honest node.
    pub fn has_one_honest<'a, X, I>(&self, vals: I) -> bool
    where
        I: Iterator<Item = (&'a Address, X)>,
    {
        self.sum_stake(vals) >= self.one_honest_size()
    }
}

impl FromIterator<(Address, u64)> for VotingPower {
    fn from_iter<I: IntoIterator<Item = (Address, u64)>>(iter: I) -> Self {
        let mut votes = HashMap::new();
        let mut total_votes = 0;

        for (addr, vote) in iter {
            if votes.contains_key(&addr) {
                // Skip duplicate keys
                continue;
            }

            votes.insert(addr, vote);
            total_votes += vote;
        }

        VotingPower { total_votes, votes }
    }
}

pub struct RoundPseudoRandom {
    pub rand_seed: [u8; 64],
}

impl RoundPseudoRandom {
    pub fn new(instance: InstanceID, committee: &VotingPower) -> RoundPseudoRandom {
        let mut hasher = Sha512::default();
        hasher.update("SEED");
        hasher.update(instance);
        for (address, voting_power) in &committee.votes {
            hasher.update(address);
            hasher.update(voting_power.to_le_bytes());
        }

        let mut seed = RoundPseudoRandom { rand_seed: [0; 64] };
        seed.rand_seed
            .clone_from_slice(hasher.finalize().as_slice());
        seed
    }

    pub fn pick_leader<'a>(&self, round: RoundID, committee: &'a VotingPower) -> &'a Address {
        let mut hasher = Sha512::default();
        hasher.update(self.rand_seed);
        hasher.update(round.to_le_bytes());
        let index = u64::from_le_bytes(
            hasher.finalize().as_slice()[0..8]
                .try_into()
                .expect("slice with incorrect length"),
        ) % committee.total_votes;

        let mut current_total = 0;
        for (address, voting_power) in &committee.votes {
            current_total += voting_power;
            if current_total > index {
                return address;
            }
        }
        unreachable!();
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn voting_power() {
        let votes: VotingPower = vec![([0; 32], 1), ([1; 32], 1), ([2; 32], 1), ([3; 32], 1)]
            .into_iter()
            .collect();
        assert!(votes.quorum_size() == 3);
    }

    #[test]
    fn voting_quorum() {
        let votes: VotingPower = vec![([0; 32], 1), ([1; 32], 1), ([2; 32], 1), ([3; 32], 1)]
            .into_iter()
            .collect();
        assert!(votes.quorum_size() == 3);
        assert!(votes.one_honest_size() == 2);

        let hm: HashMap<Address, _> = vec![([0; 32], 'a'), ([1; 32], 'b'), ([2; 32], 'c')]
            .into_iter()
            .collect();
        assert!(votes.has_quorum(hm.iter()));

        let hm: HashMap<Address, _> = vec![([2; 32], 'b'), ([3; 32], 'c')].into_iter().collect();
        assert!(!votes.has_quorum(hm.iter()));
    }
}
