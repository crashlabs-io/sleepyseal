//! Defines the state of the passive consensus core.

use crate::base_types::*;
use crate::core_types::*;
use crate::messages::*;

use failure::{ensure, Fallible};
use std::collections::{BTreeMap, HashMap};
use std::mem::replace;

/// A structure to keep track of the progress resulting from a driver operation.
#[derive(Default)]
pub struct ProgressMeasure {
    rounds_ahead: u64,
    new_bytes: u64,
    new_headers: u64,
    new_certs: u64,
}

/// The core state of a passive seal channel.
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
        let block = BlockHeader::empty(md0, digest_block_data(&data.data[..]), data.data.len());
        let cert = block.creator_sign_header(&my_secret).expect("No errors");

        core.current_round_data
            .insert_block(data, block, cert, HashMap::new())
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
        prev: HashMap<Address, BlockCertificate>,
    ) -> Fallible<()> {
        let md0 = BlockMetadata::new(
            self.current_round_data.instance,
            self.current_round_data.round,
            self.my_address,
            101,
        );
        let mut block = BlockHeader::empty(md0, digest_block_data(&data.data[..]), data.data.len());
        block.block_certificates = prev
            .iter()
            .map(|(a, c)| (*a, c.0.block_header_digest.clone()))
            .collect();
        let cert = block.creator_sign_header(&self.my_secret)?;
        self.current_round_data
            .insert_block(data, block, cert, prev)?;

        Ok(())
    }

    fn switch_and_archive_state(&mut self, new_state: DriverRequest) {
        let old_current_round_data = replace(&mut self.current_round_data, new_state);
        self.store_archive_state(&old_current_round_data);
    }

    /// Update the state given a driver request.
    pub fn update_state(
        &mut self,
        request: &DriverRequest,
    ) -> Fallible<(&DriverRequest, ProgressMeasure)> {
        // Check fuller invariants for driver messages.
        let state = request.check_request_valid(&self.committee)?;
        ensure!(request.instance == self.current_round_data.instance);

        let mut progress_meter = ProgressMeasure::default();

        // Old round request cannot update current state.
        if request.round < self.current_round_data.round {
            return Ok((&self.current_round_data, progress_meter));
        }

        // Newer round request moves state to new round
        if request.round > self.current_round_data.round {
            // When we receive a header or cert quorum from a future round
            // we also always receive enough evidence to enter the future round.
            // Furthermore, we should enter the round and produce a block as quickly
            // as possible, and without waiting potentially for a leader block, since
            // at least 2f+1 others would have waited (incl. f+1 honest.) -- so its
            // likely the leader for this round was dead.

            // When we are late we also do not include any data into the new block
            // we create, since it is very likely that it may not be included in any
            // consensus (if we are very late).

            progress_meter.rounds_ahead = self.current_round_data.round - request.round;

            match state {
                RequestValidState::None => unreachable!(),
                RequestValidState::HeaderQuorum(round) => {
                    // Make new certs.
                    let mut new_round_certs = request.extract_prev_certs().clone();
                    progress_meter.new_certs = new_round_certs.len() as u64;

                    // Check if we have some more full certs:
                    if round == self.current_round_data.round + 1 {
                        let certs = self.current_round_data.extract_full_certs(&self.committee);
                        let certs_len = certs.len();
                        new_round_certs.extend(certs);
                        progress_meter.new_certs = (new_round_certs.len() - certs_len) as u64;
                    }

                    let data = BlockData::from(vec![]);
                    let new_current_round_data = DriverRequest::empty(request.instance, round);

                    // Save the current state here
                    self.switch_and_archive_state(new_current_round_data);
                    self.insert_own_block(data, new_round_certs.into_iter().collect())?;
                }
                RequestValidState::CertQuorum(round) => {
                    // Make new certs.
                    let new_round_certs = request.extract_full_certs(&self.committee);
                    progress_meter.new_certs = new_round_certs.len() as u64;

                    let data = BlockData::from(vec![]);
                    let new_current_round_data = DriverRequest::empty(request.instance, round + 1);
                    self.switch_and_archive_state(new_current_round_data);
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
                            progress_meter.new_headers += 1;
                            progress_meter.new_bytes += _bh.data_length as u64;

                            self.current_round_data.merge_block_from(request, a)?;
                            self.current_round_data
                                .block_certificates
                                .get_mut(a)
                                .unwrap()
                                .add_own_signature(
                                    &self.committee,
                                    &self.my_address,
                                    &self.my_secret,
                                )?;
                        }
                    }
                }
                RequestValidState::CertQuorum(_round) => {
                    // Make new certs.
                    let mut new_round_certs = request.extract_full_certs(&self.committee);
                    // Add certs we have stored so far
                    let certs = self.current_round_data.extract_full_certs(&self.committee);
                    let cert_len = certs.len();
                    new_round_certs.extend(certs);

                    progress_meter.new_certs += (new_round_certs.len() - cert_len) as u64;

                    // Update the certs I have for this state
                    let new_full_certs: BTreeMap<Address, PartialCertificate> =
                        new_round_certs.into_iter().map(|(a, c)| (a, c.0)).collect();
                    self.current_round_data
                        .block_certificates
                        .extend(new_full_certs.into_iter());

                    // Note: do not automatically advance to next round -- this is to allow the passive core
                    // to wait a bit until it may get and include the certificate of this round leader in
                    // a Tusk-like construction.
                }
            }
        }

        // Save the current state here
        self.store_archive_state(&self.current_round_data.clone());
        Ok((&self.current_round_data, progress_meter))
    }

    /// Advance to new round and insert new block to initiate it.
    pub fn advance_to_new_round(&mut self, new_round: RoundID) -> Fallible<()> {
        // Check that we are not already past the round, this can happen if we receive
        // lots and lots of updates at the same time.
        ensure!(
            new_round == self.current_round_data.round + 1,
            "Not correct round any more"
        );

        // Ensure we have enough certificates to move to next round
        let prev_round_certs = self.current_round_data.extract_full_certs(&self.committee);
        ensure!(
            self.committee.has_quorum(prev_round_certs.iter()),
            "Ensure we have a quorum to move to next round."
        );

        // Make a new block and advance the round.
        let data = BlockData::from(b"XXX".to_vec());
        let new_current_round_data =
            DriverRequest::empty(self.current_round_data.instance, new_round);
        self.switch_and_archive_state(new_current_round_data);
        self.insert_own_block(data, prev_round_certs)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::crypto::key_gen;

    #[test]
    fn sim_four_authorities() {
        let (pk0, sk0) = key_gen();
        let (pk1, sk1) = key_gen();
        let (pk2, sk2) = key_gen();
        let (pk3, sk3) = key_gen();

        let votes: VotingPower = vec![(pk0, 1), (pk1, 1), (pk2, 1), (pk3, 1)]
            .into_iter()
            .collect();

        let instance = [0; 16];
        let mut core0 = SealCoreState::init(
            0,
            sk0,
            votes.clone(),
            instance,
            BlockData::from(b"ABC0".to_vec()),
        );
        assert!(core0.current_round_data.check_basic_valid(&votes).is_ok());
        let core1 = SealCoreState::init(
            1,
            sk1,
            votes.clone(),
            instance,
            BlockData::from(b"ABC1".to_vec()),
        );
        let core2 = SealCoreState::init(
            2,
            sk2,
            votes.clone(),
            instance,
            BlockData::from(b"ABC2".to_vec()),
        );
        let core3 = SealCoreState::init(
            3,
            sk3,
            votes.clone(),
            instance,
            BlockData::from(b"ABC3".to_vec()),
        );

        let mut client0 = DriverRequest::empty(instance, 0);
        client0
            .merge_block_from(&core0.current_round_data, &0)
            .expect("No problem merging");
        client0
            .merge_block_from(&core1.current_round_data, &1)
            .expect("No problem merging");
        client0
            .merge_block_from(&core2.current_round_data, &2)
            .expect("No problem merging");
        client0
            .merge_block_from(&core3.current_round_data, &3)
            .expect("No problem merging");
        assert!(client0.check_request_valid(&votes).is_ok());

        // Now insert it into the state
        core0.update_state(&client0).expect("All good");
    }
}
