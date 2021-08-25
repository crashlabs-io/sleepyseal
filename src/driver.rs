// A driver is the active element that relays and aggregates messages between passive cores.

//! Functions to build driver logic, that activelly drive the passive consensus cores.

use failure::Fallible;
use std::collections::{BTreeMap, HashMap};

use crate::base_types::*;
use crate::core_types::*;
use crate::messages::*;

/// Keeps all the state needed to drive the state of Sleepy Seal forward.
pub struct DriverCore {
    /// The instance this structure is driving.
    instance: InstanceID,
    /// The committee voting structure.
    committee: VotingPower,
    /// The latest round seen.
    latest_round: RoundID,
    /// The driver responses received about the latest round.
    latest_states: HashMap<Address, DriverRequest>,
}

impl DriverCore {
    pub fn new(instance: InstanceID, committee: VotingPower) -> DriverCore {
        DriverCore {
            instance,
            committee,
            latest_round: 0,
            latest_states: HashMap::new(),
        }
    }

    /// Adds a received response to the driver structure for processing.
    pub fn add_response(&mut self, source: Address, response: &DriverRequest) -> Fallible<()> {
        // Check the basic state invarients.
        response.check_basic_valid(&self.committee)?;

        // No need to process old responses.
        if response.round < self.latest_round {
            // TODO return a response to advance the state.
            return Ok(());
        }

        // If we lag behind, then advance.
        if response.round > self.latest_round {
            self.latest_round = response.round;
            self.latest_states.clear();
            // TODO: keep track of old to updates them.
        }

        assert!(response.round == self.latest_round);
        let resp_copy: DriverRequest = response.clone();
        self.latest_states.insert(source, resp_copy);

        Ok(())
    }

    /// Use the states received to make a driver request that will eventually
    /// move any lagging passive core to the current round.
    pub fn move_to_latest_round_request(&self) -> Option<DriverRequest> {
        let mut all_certs = BTreeMap::new();
        for (_, state) in &self.latest_states {
            for (_, block) in &state.block_headers {
                all_certs.extend(block.block_certificates.clone())
            }
        }

        // If the available certs do not make a quorum, then return None.
        if !self.committee.has_quorum(all_certs.iter()) {
            return None;
        }

        // Make a request for the previous round, with this quorum of certs, to 
        // move a passive core forward.

        // Note: it is safe to take round-1, since a round = 0 state cannot have
        //       and previous cert in its header (see check_basic_valid.)
        let mut empty = DriverRequest::empty(self.instance, self.latest_round - 1);
        empty.block_certificates = all_certs.into_iter().map(|(a, c)| (a, c.0)).collect();
        Some(empty)
    }

    /// Aggregate all core responses, and construct a request to help them
    /// make progress.
    pub fn create_aggregate_response(&self) -> Option<DriverRequest> {
        let mut empty = DriverRequest::empty(self.instance, self.latest_round);

        // First create a list of all the full certificates.
        let mut aggregate_certs: HashMap<BlockHeaderDigest, PartialCertificate> = HashMap::new();
        for (_, state) in &self.latest_states {
            for (_, cert) in &state.block_certificates {
                if aggregate_certs.contains_key(&cert.block_header_digest) {
                    let _err = aggregate_certs
                        .get_mut(&cert.block_header_digest)
                        .unwrap()
                        .merge_from(cert);
                } else {
                    aggregate_certs.insert(cert.block_header_digest, cert.clone());
                }
            }
        }

        // Do we have a quorum of full certs?
        let full_certs: HashMap<Address, PartialCertificate> = aggregate_certs
            .iter()
            .filter(|(_h, c)| self.committee.has_quorum(c.signatures.iter()))
            .map(|(_h, c)| (c.block_metadata.creator, c.clone()))
            .collect();

        // If we have a quorum of full certificates the request simply lists them
        // to move passive cores to the next round.
        if self.committee.has_quorum(full_certs.iter()) {
            empty.block_certificates = full_certs;
            return Some(empty);
        }

        // We may need to send a list of blocks, instead
        for (_, state) in &self.latest_states {
            for (a, block) in &state.block_headers {
                let creator = &block.block_metadata.creator;

                // If we have a cert for another block from the same sender, ignore:
                if full_certs.contains_key(creator) {
                    if !full_certs[creator].matches_block(&block) {
                        continue;
                    }
                }

                // Strip all the signatures.
                let mut cert = state.block_certificates.get(a).unwrap().clone();
                cert.strip_other_signatures();

                // We ignore errors.
                let _ = empty.insert_block(
                    &state.block_data.get(a).unwrap(),
                    state.block_headers.get(a).unwrap(),
                    &cert,
                );
            }
        }

        // Do we have a quorum of headers?
        if self.committee.has_quorum(empty.block_headers.iter()) {
            return Some(empty); // Return the quorum of headers to gather more signatures.
        }

        None
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::core_state::*;

    #[test]
    fn sim_four_authorities_client() {
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
        let mut core1 = SealCoreState::init(
            pk1,
            sk1,
            votes.clone(),
            instance,
            BlockData::from(b"ABC1".to_vec()),
        );
        let mut core2 = SealCoreState::init(
            pk2,
            sk2,
            votes.clone(),
            instance,
            BlockData::from(b"ABC2".to_vec()),
        );
        let mut core3 = SealCoreState::init(
            pk3,
            sk3,
            votes.clone(),
            instance,
            BlockData::from(b"ABC3".to_vec()),
        );

        let mut driver = DriverCore::new(instance, votes.clone());
        assert!(driver.add_response(pk0, &core0.current_round_data).is_ok());
        assert!(driver.create_aggregate_response().is_none());
        assert!(driver.add_response(pk1, &core1.current_round_data).is_ok());
        assert!(driver.create_aggregate_response().is_none());
        assert!(driver.add_response(pk2, &core2.current_round_data).is_ok());
        let header_message = driver.create_aggregate_response().expect("Header message");
        assert!(
            header_message
                .check_request_valid(&votes)
                .expect("No error")
                == RequestValidState::HeaderQuorum(0)
        );

        assert!(core0.update_state(&header_message).is_ok());
        assert!(core1.update_state(&header_message).is_ok());
        assert!(core2.update_state(&header_message).is_ok());

        assert!(driver.add_response(pk0, &core0.current_round_data).is_ok());
        assert!(driver.add_response(pk1, &core1.current_round_data).is_ok());
        assert!(driver.add_response(pk2, &core2.current_round_data).is_ok());
        let cert_message = driver.create_aggregate_response().expect("Header message");
        assert!(
            cert_message.check_request_valid(&votes).expect("No error")
                == RequestValidState::CertQuorum(0)
        );

        assert!(core3.update_state(&cert_message).is_ok());
        assert!(core3.current_round_data.round == 1);

        // Now add the response from 1
        assert!(driver.add_response(pk0, &core3.current_round_data).is_ok());
        assert!(driver.latest_states.len() == 1);

        // Check we do not have enough data to drive the next round yet.
        assert!(driver.create_aggregate_response().is_none());
        // But we have enough to make a response to advance to this round.
        let move_to_1 = driver.move_to_latest_round_request().unwrap();
        assert!(move_to_1.check_request_valid(&votes).is_ok());
        assert!(move_to_1.check_request_valid(&votes).unwrap() == RequestValidState::CertQuorum(0));
        

    }


    
    #[test] 
    fn test_progress_at_random() {

        let mut keys_vec = Vec::new();
        let mut states_vec = Vec::new();

        for _ in 0..4 {
            let (pk, sk) = gen_keypair();
            keys_vec.push((pk, sk))

        }

        let votes: VotingPower = keys_vec
            .iter()
            .map(|(pk, _)| (*pk, 1))
            .collect();

        let instance = [0; 16];

        for i in 0..keys_vec.len() {

            let core = SealCoreState::init(
                keys_vec[i].0,
                keys_vec[i].1,
                votes.clone(),
                instance,
                BlockData::from(b"ABC0".to_vec()),
            );

            states_vec.push(core);
        }

        // The client state
        let mut latest = 0;
        let mut driver = DriverCore::new(instance, votes.clone());
        for r in 0..1000 {

            let i = r % keys_vec.len();
            
            driver.add_response(keys_vec[i].0, &states_vec[i].current_round_data).unwrap();
            if let Some(cert_message) = driver.create_aggregate_response() {
                states_vec[i].update_state(&cert_message).unwrap();
            }

            println!("Round of core{} = {}", i, &states_vec[i].current_round_data.round);
            latest = states_vec[i].current_round_data.round;
        }

        assert!(latest > 50);

    }
}