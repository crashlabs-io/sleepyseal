
//! Defines the state of the passive consensus core.

use crate::base_types::*;
use crate::core_types::*;
use crate::messages::*;

use failure::{ensure, Fallible};
use std::collections::{BTreeMap, HashMap};
use std::mem::replace;

pub struct SealCoreState {
    pub my_address: Address,
    pub my_secret: SigningSecretKey,
    pub committee: VotingPower,
    pub current_round_data: DriverRequest,
    // TODO: add transaction data mempool

    // TODO: eventually add persistence, and restarts.
    pub old_state_db: HashMap<RoundID, DriverRequest>,
}

impl SealCoreState {
    /// Initialize a core consensus state for round zero.
    pub fn init(
        my_address: Address,
        my_secret: SigningSecretKey,
        committee: VotingPower,
        instance: InstanceID,
        data: BlockData,
    ) -> SealCoreState {
        let mut core = SealCoreState {
            my_address,
            my_secret,
            committee,
            current_round_data: DriverRequest::empty(instance, 0),
            old_state_db: HashMap::new(),
        };

        let md0 = BlockMetadata::new(instance, 0, my_address, 101);
        let block = BlockHeader::empty(md0, digest_block_data(&data.data[..]));
        let cert = block.creator_sign_header(&my_secret).expect("No errors");

        core.current_round_data
            .insert_block(&data, &block, &cert)
            .expect("Cannot err for empty state");
        core
    }

    /// Store an old state in the archive.
    pub fn store_archive_state(&mut self, state: &DriverRequest) {
        self.old_state_db.insert(state.round, state.clone());
    }

    /// Get an old state from the archive.
    pub fn get_archive_state(&self, round: RoundID) -> Option<&DriverRequest> {
        self.old_state_db.get(&round)
    }

    /// Insert own block into state for current round.
    pub fn insert_own_block(
        &mut self,
        data: BlockData,
        prev: BTreeMap<Address, BlockCertificate>,
    ) -> Fallible<()> {
        let md0 = BlockMetadata::new(
            self.current_round_data.instance,
            self.current_round_data.round,
            self.my_address,
            101,
        );
        let mut block = BlockHeader::empty(md0, digest_block_data(&data.data[..]));
        block.block_certificates = prev;
        let cert = block.creator_sign_header(&self.my_secret)?;
        self.current_round_data.insert_block(&data, &block, &cert)?;

        Ok(())
    }

    /// Update the state given a driver request.
    pub fn update_state(&mut self, request: &DriverRequest) -> Fallible<&DriverRequest> {
        // Check fuller invarients for driver messages.
        let state = request.check_request_valid(&self.committee)?;
        ensure!(request.instance == self.current_round_data.instance);

        // Old round request cannot update current state.
        if request.round < self.current_round_data.round {
            return Ok(&self.current_round_data);
        }

        // Newer round request moves state to new round
        if request.round > self.current_round_data.round {
            match state {
                RequestValidState::None => unreachable!(),
                RequestValidState::HeaderQuorum(round) => {
                    // Make new certs.
                    let mut new_round_certs = request.extract_prev_certs();

                    // Check if we have some more full certs:
                    if round == self.current_round_data.round + 1 {
                        let certs = self.current_round_data.extract_full_certs(&self.committee);
                        new_round_certs.extend(certs);
                    }

                    let data = BlockData::from(b"XXX".to_vec());
                    let new_current_round_data = DriverRequest::empty(request.instance, round);

                     // Save the current state here
                    let old_current_round_data = replace(&mut self.current_round_data, new_current_round_data);
                    self.store_archive_state(&old_current_round_data);

                    self.insert_own_block(data, new_round_certs)?;
                }
                RequestValidState::CertQuorum(round) => {
                    // Make new certs.
                    let new_round_certs = request.extract_full_certs(&self.committee);

                    // Save the current state here
                    self.store_archive_state(&self.current_round_data.clone());

                    let data = BlockData::from(b"XXX".to_vec());
                    self.current_round_data = DriverRequest::empty(request.instance, round + 1);
                    self.insert_own_block(data, new_round_certs)?;
                }
            }
        }

        // Sign new headers
        if self.current_round_data.round == request.round {
            match state {
                RequestValidState::None => unreachable!(),
                RequestValidState::HeaderQuorum(_round) => {
                    for (a, _bh) in &request.block_headers {
                        if !self.current_round_data.block_headers.contains_key(a) {
                            // Insert and sign this header.
                            self.current_round_data.merge_block_from(request, a)?;
                            self.current_round_data
                                .block_certificates
                                .get_mut(a)
                                .unwrap()
                                .add_own_signature(&self.my_address, &self.my_secret)?;
                        }
                    }
                }
                RequestValidState::CertQuorum(round) => {
                    // Make new certs.
                    let mut new_round_certs = request.extract_full_certs(&self.committee);
                    // Add certs we have stored so far
                    let certs = self.current_round_data.extract_full_certs(&self.committee);
                    new_round_certs.extend(certs);

                    // Update the certs I have for this state
                    self.current_round_data.block_certificates = new_round_certs
                        .clone()
                        .into_iter()
                        .map(|(a, c)| (a, c.0))
                        .collect();

                    // Save the current state here
                    self.store_archive_state(&self.current_round_data.clone());

                    let data = BlockData::from(b"XXX".to_vec());
                    self.current_round_data = DriverRequest::empty(request.instance, round + 1);
                    self.insert_own_block(data, new_round_certs)?;
                }
            }
        }

        // Save the current state here
        self.store_archive_state(&self.current_round_data.clone());
        Ok(&self.current_round_data)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn sim_four_authorities() {
        let (pk0, sk0) = gen_keypair();
        let (pk1, sk1) = gen_keypair();
        let (pk2, sk2) = gen_keypair();
        let (pk3, sk3) = gen_keypair();

        let votes: VotingPower = vec![(pk0, 1), (pk1, 1), (pk2, 1), (pk3, 1)]
            .into_iter()
            .collect();

        let instance = [0; 16];
        let mut core0 = SealCoreState::init(
            pk0,
            sk0,
            votes.clone(),
            instance,
            BlockData::from(b"ABC0".to_vec()),
        );
        assert!(core0.current_round_data.check_basic_valid(&votes).is_ok());
        let core1 = SealCoreState::init(
            pk1,
            sk1,
            votes.clone(),
            instance,
            BlockData::from(b"ABC1".to_vec()),
        );
        let core2 = SealCoreState::init(
            pk2,
            sk2,
            votes.clone(),
            instance,
            BlockData::from(b"ABC2".to_vec()),
        );
        let core3 = SealCoreState::init(
            pk3,
            sk3,
            votes.clone(),
            instance,
            BlockData::from(b"ABC3".to_vec()),
        );

        let mut client0 = DriverRequest::empty(instance, 0);
        client0
            .merge_block_from(&core0.current_round_data, &pk0)
            .expect("No problem merging");
        client0
            .merge_block_from(&core1.current_round_data, &pk1)
            .expect("No problem merging");
        client0
            .merge_block_from(&core2.current_round_data, &pk2)
            .expect("No problem merging");
        client0
            .merge_block_from(&core3.current_round_data, &pk3)
            .expect("No problem merging");
        assert!(client0.check_request_valid(&votes).is_ok());

        // Now insert it into the state
        core0.update_state(&client0).expect("All good");
    }
}
