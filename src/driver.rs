// A driver is the active element that relays and aggregates messages between passive cores.

//! Functions to build driver logic, that actively drive the passive consensus cores.

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
    /// Whether the instance accepts new transactions.
    is_open: bool,

    // Temps for round
    block_lock: HashMap<Address, (BlockHeader, BlockData)>,
    cert_lock: HashMap<BlockHeaderDigest, PartialCertificate>,
    prev_ready_certs: HashMap<Address, BlockCertificate>,
    ready_certs: HashMap<Address, PartialCertificate>,
}

impl DriverCore {
    pub fn new(instance: InstanceID, committee: VotingPower) -> DriverCore {
        DriverCore {
            instance,
            committee,
            latest_round: 0,
            latest_states: HashMap::new(),
            is_open: true,

            // Temp state
            block_lock: HashMap::new(),
            cert_lock: HashMap::new(),
            prev_ready_certs: HashMap::new(),
            ready_certs: HashMap::new(),
        }
    }

    /// Adds a received response to the driver structure for processing.
    pub fn add_response(&mut self, source: Address, response: &DriverRequest) -> Fallible<()> {
        // Check the basic state invariants.
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

            self.block_lock.clear();
            self.cert_lock.clear();
            self.prev_ready_certs.clear();
            self.ready_certs.clear();
        }

        assert!(response.round == self.latest_round);
        let resp_copy: DriverRequest = response.clone();
        self.latest_states.insert(source, resp_copy);

        for (addr, cert) in &response.block_certificates {
            // If we already have a full cert ignore.
            if self.ready_certs.contains_key(addr) {
                continue;
            }

            // We do not have a ready full cert
            if cert.aggregate_signature.is_some() {
                self.ready_certs.insert(*addr, cert.clone());
                continue;
            }

            // Insert an entry.
            if !self.cert_lock.contains_key(&cert.block_header_digest) {
                self.cert_lock
                    .insert(cert.block_header_digest.clone(), cert.clone());
            } else {
                let entry = self.cert_lock.get_mut(&cert.block_header_digest).unwrap();
                entry.merge_from(cert)?;
            }

            let entry = self.cert_lock.get_mut(&cert.block_header_digest).unwrap();
            if entry.has_quorum(&self.committee) {
                entry.make_cert(&self.committee);
                self.ready_certs.insert(*addr, entry.clone());

                // Now clean up any equivocating blocks we have a lock on
                // If we have a cert for another block from the same sender, ignore:
                if self.block_lock.contains_key(addr) {
                    if !entry.matches_block(&self.block_lock[addr].0) {
                        self.block_lock.remove(addr);
                    }
                }
            }
        }

        // Update the temporaries.
        for (addr, prev_cert) in &response.previous_block_certificates {
            if !self.prev_ready_certs.contains_key(addr) {
                self.prev_ready_certs.insert(*addr, prev_cert.clone());
            }
        }

        for (addr, block_header) in &response.block_headers {
            if !self.block_lock.contains_key(addr) {
                // If we have a cert for another block from the same sender, ignore:
                if self.ready_certs.contains_key(addr) {
                    if !self.ready_certs[addr].matches_block(&block_header) {
                        continue;
                    }
                }

                let data = response.block_data[addr].clone();
                self.block_lock.insert(*addr, (block_header.clone(), data));
            }
        }

        Ok(())
    }

    /// Use the states received to make a driver request that will eventually
    /// move any lagging passive core to the current round.
    pub fn move_to_latest_round_request(&self) -> Option<DriverRequest> {
        let mut all_certs = BTreeMap::new();
        for (_, state) in &self.latest_states {
            all_certs.extend(state.previous_block_certificates.clone())
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

        // If we have a quorum of full certificates the request simply lists them
        // to move passive cores to the next round.
        if self.committee.has_quorum(self.ready_certs.iter()) {
            empty.block_certificates = self.ready_certs.clone();
            return Some(empty);
        }

        if self.committee.has_quorum(self.block_lock.iter()) {
            for (_a, (block, data)) in &self.block_lock {
                // Strip all the signatures, except creator's.
                let mut cert = self.cert_lock.get(&block.digest()).unwrap().clone();
                cert.strip_other_signatures();
                cert.aggregate_signature = None;

                // We ignore errors.
                let _ = empty.insert_block(data.clone(), block.clone(), cert, HashMap::new());
            }
            empty
                .previous_block_certificates
                .extend(self.prev_ready_certs.clone());

            return Some(empty);
        }

        None
    }

    /// Extract a state that contains all full certificates for this round, as well as
    /// all headers and data for the blocks with full certificates. Return some state if
    /// there is a quorum of certs and blocks, otherwise None.
    pub fn extract_full_round_state(&self) -> Option<DriverRequest> {
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
                    aggregate_certs.insert(cert.block_header_digest.clone(), cert.clone());
                }
            }
        }

        // Do we have a quorum of full certs?
        let full_certs: HashMap<Address, PartialCertificate> = aggregate_certs
            .iter()
            .filter(|(_h, c)| self.committee.has_quorum(c.signatures.iter()))
            .map(|(_h, c)| (c.block_metadata.creator, c.clone()))
            .collect();

        // Put all full certificates in the certificates list.
        if !self.committee.has_quorum(full_certs.iter()) {
            return None;
        }

        // We may need to send a list of blocks, instead
        for (_, state) in &self.latest_states {
            for (creator, block) in &state.block_headers {
                // Block has no cert
                if !full_certs.contains_key(creator) {
                    continue;
                }

                // Block is for different cert
                if !full_certs[creator].matches_block(&block) {
                    continue;
                }

                // Block is already in new structure
                if empty.block_headers.contains_key(creator) {
                    continue;
                }

                // Include block in structure.
                let _ = empty.insert_block(
                    state.block_data.get(creator).unwrap().clone(),
                    state.block_headers.get(creator).unwrap().clone(),
                    full_certs.get(creator).unwrap().clone(),
                    HashMap::new(),
                );
            }
            empty
                .previous_block_certificates
                .extend(state.previous_block_certificates.clone());
        }

        // Check if included headers / certs have a quorum.
        if !self.committee.has_quorum(empty.block_headers.iter()) {
            return None;
        }

        return Some(empty); // Return the quorum of headers to gather more signatures.
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::core_state::*;
    use crate::crypto::key_gen;
    use crate::mempool::Mempool;

    #[test]
    fn sim_four_authorities_client() {
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
        let mut core1 = SealCoreState::init(
            1,
            sk1,
            votes.clone(),
            instance,
            BlockData::from(b"ABC1".to_vec()),
        );
        let mut core2 = SealCoreState::init(
            2,
            sk2,
            votes.clone(),
            instance,
            BlockData::from(b"ABC2".to_vec()),
        );
        let mut core3 = SealCoreState::init(
            3,
            sk3,
            votes.clone(),
            instance,
            BlockData::from(b"ABC3".to_vec()),
        );

        let mut driver = DriverCore::new(instance, votes.clone());
        assert!(driver.add_response(0, &core0.current_round_data).is_ok());
        assert!(driver.create_aggregate_response().is_none());
        assert!(driver.add_response(1, &core1.current_round_data).is_ok());
        assert!(driver.create_aggregate_response().is_none());
        assert!(driver.add_response(2, &core2.current_round_data).is_ok());
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

        assert!(driver.add_response(0, &core0.current_round_data).is_ok());
        assert!(driver.add_response(1, &core1.current_round_data).is_ok());
        assert!(driver.add_response(2, &core2.current_round_data).is_ok());
        let cert_message = driver.create_aggregate_response().expect("Header message");
        assert!(
            cert_message.check_request_valid(&votes).expect("No error")
                == RequestValidState::CertQuorum(0)
        );

        let mut mp = Mempool::new();

        assert!(core3.advance_to_new_round(1, &mut mp).is_err());
        assert!(core3.update_state(&cert_message).is_ok());
        assert!(core3.current_round_data.round == 0);

        // After we explicitly advance, now it is 1
        assert!(core3.advance_to_new_round(1, &mut mp).is_ok());
        assert!(core3.current_round_data.round == 1);

        // Now add the response from 1
        assert!(driver.add_response(0, &core3.current_round_data).is_ok());
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
            let (pk, sk) = key_gen();
            keys_vec.push((pk, sk))
        }

        let votes: VotingPower = keys_vec.iter().map(|(pk, _)| (*pk, 1)).collect();

        let instance = [0; 16];

        for i in 0..keys_vec.len() {
            let core = SealCoreState::init(
                i as u16,
                keys_vec[i].1,
                votes.clone(),
                instance,
                BlockData::from(b"ABC0".to_vec()),
            );

            states_vec.push(core);
        }

        let mut mp = Mempool::new();

        // The client state
        let mut latest = 0;
        let mut driver = DriverCore::new(instance, votes.clone());
        for r in 0..1000 {
            let i = r % keys_vec.len();

            let naive_enc = &states_vec[i].current_round_data.naive_encode();
            let compress_enc = &states_vec[i].current_round_data.compressed_encode();

            println!("Full: {} Compress: {}", naive_enc.len(), compress_enc.len());

            driver
                .add_response(i as u16, &states_vec[i].current_round_data)
                .unwrap();

            // Lets see if we get the full round data:
            if let Some(full_state) = driver.extract_full_round_state() {
                println!("Full State for round {}", full_state.round);
                let rand = RoundPseudoRandom::new(full_state.instance, &votes);
                let leader = rand.pick_leader(full_state.round, &votes);
                let (strong_set, _) = full_state.strong_support(&votes);
                let leader_in = strong_set.contains(leader);
                if leader_in {
                    println!("Found leader: {:x?}", leader);
                }
            }

            if let Some(cert_message) = driver.create_aggregate_response() {
                states_vec[i].update_state(&cert_message).unwrap();
                let new_round_id = states_vec[i].current_round_data.round + 1;
                let _ = states_vec[i].advance_to_new_round(new_round_id, &mut mp);
            }

            println!(
                "Round of core{} = {}",
                i, &states_vec[i].current_round_data.round,
            );
            latest = states_vec[i].current_round_data.round;

            if latest > 25 {
                break;
            }
        }

        assert!(latest > 25);
    }

    #[test]
    fn test_progress_one_crash() {
        let mut keys_vec = Vec::new();
        let mut states_vec = Vec::new();

        for _ in 0..4 {
            let (pk, sk) = key_gen();
            keys_vec.push((pk, sk))
        }

        let votes: VotingPower = keys_vec.iter().map(|(pk, _)| (*pk, 1)).collect();

        let instance = [0; 16];

        for i in 0..keys_vec.len() {
            let core = SealCoreState::init(
                i as u16,
                keys_vec[i].1,
                votes.clone(),
                instance,
                BlockData::from(b"ABC0".to_vec()),
            );

            states_vec.push(core);
        }

        let mut mp = Mempool::new();

        // The client state
        let mut latest = 0;
        let mut driver = DriverCore::new(instance, votes.clone());
        for r in 0..1000 {
            let i = r % (keys_vec.len() - 1);

            driver
                .add_response(i as u16, &states_vec[i].current_round_data)
                .unwrap();
            if let Some(cert_message) = driver.create_aggregate_response() {
                states_vec[i].update_state(&cert_message).unwrap();
                let new_round_id = states_vec[i].current_round_data.round + 1;
                let _ = states_vec[i].advance_to_new_round(new_round_id, &mut mp);
            }

            println!(
                "Round of core{} = {}",
                i, &states_vec[i].current_round_data.round
            );
            latest = states_vec[i].current_round_data.round;
        }

        assert!(latest > 50);
    }

    use std::time::Instant;

    #[test]
    fn test_progress_at_random_many_nodes() {
        let mut keys_vec = Vec::new();
        let mut states_vec = Vec::new();

        let f = 3;
        for _ in 0..(3 * f + 1) {
            let (pk, sk) = key_gen();
            keys_vec.push((pk, sk))
        }

        let votes: VotingPower = keys_vec.iter().map(|(pk, _)| (*pk, 1)).collect();

        let instance = [0; 16];

        for i in 0..keys_vec.len() {
            let core = SealCoreState::init(
                i as u16,
                keys_vec[i].1,
                votes.clone(),
                instance,
                BlockData::from(Vec::new()),
            );

            states_vec.push(core);
        }

        // The client state
        let mut latest = 0;
        let mut driver = DriverCore::new(instance, votes.clone());

        let mut mp = Mempool::new();

        for r in 0..2000 {
            let i = r % keys_vec.len();

            //let vstart = Instant::now();

            driver
                .add_response(i as u16, &states_vec[i].current_round_data)
                .unwrap();

            // println!("(1) Response: {}", vstart.elapsed().as_millis());
            let vstart = Instant::now();

            if let Some(cert_message) = driver.create_aggregate_response() {
                // Measure size

                println!("(2) Aggregate: {}", vstart.elapsed().as_millis());
                let vstart = Instant::now();

                let naive_enc = &cert_message.naive_encode();
                let compress_enc = &cert_message.compressed_encode();

                println!("(3) Serialize: {}", vstart.elapsed().as_millis());
                let vstart = Instant::now();

                /*
                let mut req_minus_sigs = cert_message.clone();
                for (_addr, cert) in &mut req_minus_sigs.previous_block_certificates {
                    cert.0.make_cert(&votes);
                }
                for (_addr, cert) in &mut req_minus_sigs.block_certificates {
                    cert.make_cert(&votes);
                }
                let no_sig_enc = req_minus_sigs.compressed_encode();

                for (_addr, block) in &mut req_minus_sigs.block_headers {
                    block.block_certificates.clear();
                }
                let no_cert = req_minus_sigs.compressed_encode();
                */
                println!("Full: {} Compress: {}", naive_enc.len(), compress_enc.len());

                /*
                println!(
                    "No sigs compress: {} No certs compress: {}",
                    no_sig_enc.len(),
                    no_cert.len()
                );
                */

                // Update state
                states_vec[i].update_state(&cert_message).unwrap();
                let new_round_id = states_vec[i].current_round_data.round + 1;
                let _ = states_vec[i].advance_to_new_round(new_round_id, &mut mp);

                println!("(4) Process: {}", vstart.elapsed().as_millis());
            }

            println!(
                "Round of core{} = {}",
                i, &states_vec[i].current_round_data.round,
            );
            latest = states_vec[i].current_round_data.round;

            if latest > 2 {
                break;
            }
        }

        assert!(latest > 2);
    }
}
