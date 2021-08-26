//! Defines the messages passed between passive cores and drivers.

use std::collections::{BTreeMap, HashMap};

use failure::{bail, ensure, Fallible};
use serde::{Deserialize, Serialize};

use crate::base_types::*;
use crate::core_types::*;

/// Represents a client/driver request, containing an update to the consensus state
/// of a node. Also used to hold the current state within a node.
#[derive(Clone, Serialize, Deserialize)]
pub struct DriverRequest {
    /// The instance identifier of the consensus.
    pub instance: InstanceID,
    /// The Narwhal mempool round for this request.
    pub round: RoundID,
    /// All block data.
    pub block_data: HashMap<Address, BlockData>,
    /// All block headers for this round.
    pub block_headers: HashMap<Address, BlockHeader>,
    /// All block certificates for this round.
    pub block_certificates: HashMap<Address, PartialCertificate>,
}

/// The inferered type of request received.
#[derive(PartialEq, Clone, Serialize, Deserialize)]
pub enum RequestValidState {
    None,
    HeaderQuorum(RoundID),
    CertQuorum(RoundID),
}

impl DriverRequest {
    /// Create an empty request
    pub fn empty(instance: InstanceID, round: RoundID) -> DriverRequest {
        DriverRequest {
            instance,
            round,
            block_data: HashMap::new(),
            block_headers: HashMap::new(),
            block_certificates: HashMap::new(),
        }
    }

    /// Insert or update an existing certificate.
    pub fn insert_cert(&mut self, cert: &PartialCertificate) -> Fallible<()> {
        let creator = cert.block_metadata.creator;

        if self.block_certificates.contains_key(&creator) {
            self.block_certificates
                .get_mut(&creator)
                .unwrap()
                .merge_from(&cert)?
        } else {
            self.block_certificates
                .insert(creator.clone(), cert.clone());
        }

        Ok(())
    }

    /// Insert a block incl insert or update its cert.
    pub fn insert_block(
        &mut self,
        data: &BlockData,
        block: &BlockHeader,
        cert: &PartialCertificate,
    ) -> Fallible<()> {
        let creator = cert.block_metadata.creator;
        self.insert_cert(cert)?;

        self.block_data
            .insert(creator.clone(), BlockData::from(data.clone()));
        self.block_headers.insert(creator.clone(), block.clone());

        Ok(())
    }

    /// Merge a block, its data, and its cert from another driver request object.
    pub fn merge_block_from(&mut self, other: &DriverRequest, creator: &Address) -> Fallible<()> {
        self.insert_block(
            &other.block_data[creator],
            &other.block_headers[creator],
            &other.block_certificates[creator],
        )?;

        Ok(())
    }

    #[cfg(test)]
    pub fn sign_all_headers(
        &mut self,
        address: &Address,
        secret: &SigningSecretKey,
    ) -> Fallible<()> {
        for (_addr, cert) in &mut self.block_certificates {
            cert.add_own_signature(address, secret)?;
        }
        Ok(())
    }

    /// Checks all the certificates and partial certificate signatures.
    pub fn all_signatures_valid(&self) -> Fallible<()> {
        for (_addr, block) in &self.block_headers {
            for (_addr_prev, cert) in &block.block_certificates {
                ensure!(cert.0.all_signatures_valid().is_ok())
            }
        }

        for (_addr, cert) in &self.block_certificates {
            ensure!(cert.all_signatures_valid().is_ok())
        }

        Ok(())
    }

    /// Perform only basic validity checks. This is the bar for a client to consider a state
    /// valid from a node.
    pub fn check_basic_valid(&self, committee: &VotingPower) -> Fallible<()> {
        // Check each included header
        for (addr, header) in &self.block_headers {
            // Check Header

            // Header is for correct instance and round
            ensure!(header.block_metadata.instance == self.instance);
            ensure!(header.block_metadata.round == self.round);

            // Header is for stated address
            ensure!(header.block_metadata.creator == *addr);

            // Check certificates for the previous round.

            if self.round > 0 {
                // Enough voting power included to create new block
                ensure!(committee.has_quorum(header.block_certificates.iter()));

                for (cert_addr, cert) in &header.block_certificates {
                    ensure!(cert.0.block_metadata.instance == self.instance);
                    ensure!(cert.0.block_metadata.round == self.round - 1);
                    ensure!(cert.0.block_metadata.creator == *cert_addr);
                }
            } else {
                // round == 0 => there should be no old certs
                ensure!(header.block_certificates.len() == 0);
            }

            // Check body

            // The header has an associated body
            ensure!(self.block_data.contains_key(addr));
            
            // The digest and length of the body match.
            let data_digest = digest_block_data(&self.block_data[addr].data);
            ensure!(header.data_digest == data_digest); 
            ensure!(header.data_length == self.block_data[addr].data.len());

            // Check partial cert for header from creator

            // A header must also have at least a partial certificate,
            // with the creator's key.
            ensure!(self.block_certificates.contains_key(addr));
            let partial_cert = &self.block_certificates[addr];

            // The metadata of the certificate must match the header
            ensure!(header.block_metadata == partial_cert.block_metadata);

            // The hash of the certificate must match the hash of the header
            ensure!(header.digest() == partial_cert.block_header_digest);

            // The creator's signature should be included in the partial cert
            ensure!(partial_cert.signatures.contains_key(addr));
        }

        for (cert_addr, cert) in &self.block_certificates {
            ensure!(cert.block_metadata.instance == self.instance);
            ensure!(cert.block_metadata.round == self.round);
            ensure!(cert.block_metadata.creator == *cert_addr);

            // In all cases a certificate must be signed by the block creator
            ensure!(cert.signatures.contains_key(cert_addr));
        }

        Ok(())
    }

    /// Checks all the invariants for a driver request. This is the bar to accept this request from a client.
    /// Assumes that all signatures were checked and are valid
    pub fn check_request_valid(&self, committee: &VotingPower) -> Fallible<RequestValidState> {
        let mut response = RequestValidState::None;

        // First pass the basic checks
        self.check_basic_valid(&committee)?;

        if self.block_headers.len() > 0 {
            // If any blockheaders are included there must be a quorum of blockheaders
            ensure!(committee.has_quorum(self.block_headers.iter()));
            response = RequestValidState::HeaderQuorum(self.round);
        }

        // Check all certificates are valid

        // Enough certificates to form a quorum
        ensure!(committee.has_quorum(self.block_certificates.iter()));

        let mut full_certs: Vec<(&Address, _)> = Vec::with_capacity(self.block_certificates.len());
        for (cert_addr, cert) in &self.block_certificates {
            // Either it is a partial cert with one signature, or it is a full cert
            if cert.signatures.len() == 1 {
                // Must match a header, and given header check logic it is good
                ensure!(self.block_headers.contains_key(cert_addr));
            } else {
                // Is a full certificate
                ensure!(committee.has_quorum(cert.signatures.iter()));
                full_certs.push((cert_addr, ()));
            }
        }

        if full_certs.len() > 0 {
            // If one full certificate is present, then a quorum must be present
            ensure!(committee.has_quorum(full_certs.into_iter()));
            response = RequestValidState::CertQuorum(self.round);
        }

        if let RequestValidState::None = response {
            bail!("Need either Header or Cert Quorum.");
        }

        Ok(response)
    }

    /// Extracts all the full certificates
    pub fn extract_full_certs(
        &self,
        committe: &VotingPower,
    ) -> BTreeMap<Address, BlockCertificate> {
        let all_certs: BTreeMap<_, _> = self
            .block_certificates
            .clone()
            .into_iter()
            .filter(|(_, c)| committe.has_quorum(c.signatures.iter()))
            .map(|(a, c)| (a, BlockCertificate(c)))
            .collect();

        all_certs
    }

    /// Extract all certificates from the previous round, embedded in the blocks.
    pub fn extract_prev_certs(&self) -> BTreeMap<Address, BlockCertificate> {
        let all_certs: BTreeMap<_, _> = self
            .block_headers
            .clone()
            .into_iter()
            .map(|(_a, bh)| bh.block_certificates.into_iter())
            .flatten()
            .collect();
        all_certs
    }

    /// Given the evidence in this message / state extract which certificates
    /// from the previous round have strong support in this round. Strong support
    /// means that a certificate from the previous round is included in at least
    /// f+1 certified blocks in the current round.
    /// 
    /// Returns the set of addresses with blocks in the previous round that have strong 
    /// support, and the total amount of stake of certs that were available to do the
    /// calculation.
    pub fn strong_support(&self, committee: &VotingPower) -> (Vec<Address>, u64) {
        let mut total_stake_count = 0;
        let full_certs = self.extract_full_certs(committee);
        let mut stake_count: BTreeMap<_, _> = self
            .extract_prev_certs()
            .into_iter()
            .map(|(a, _)| (a, 0))
            .collect();
        for (a, cert) in &full_certs {
            if let Some(header) = self.block_headers.get(a) {
                // Must have a full cert for this block
                if cert.0.block_header_digest != header.digest() {
                    continue;
                };

                // Aggregate the stake
                for (inner_a, _prev_cert) in &header.block_certificates {
                    *stake_count.get_mut(inner_a).unwrap() +=
                        committee.get_votes(a).expect("Address Exists!");
                }

                total_stake_count += committee.get_votes(a).expect("Address exists");
            }
        }

        let prev_block_with_enough_stake: Vec<_> = stake_count
            .into_iter()
            .filter(|(_, s)| *s >= committee.one_honest_size())
            .map(|(a, _)| a)
            .collect();
        (prev_block_with_enough_stake, total_stake_count)
    }

    /// Extract a driver request that uses the certificates from previous blocks to force progress to the current round.
    pub fn extract_progress_request(&self) -> Fallible<DriverRequest> {
        ensure!(self.round > 0);
        let block_certificates = self.extract_prev_certs();
        ensure!(block_certificates.len() > 0);
        Ok(DriverRequest {
            instance: self.instance,
            round: self.round - 1,
            block_data: HashMap::new(),
            block_headers: HashMap::new(),
            block_certificates: block_certificates
                .into_iter()
                .map(|(a, c)| (a, c.0))
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::borrow::Borrow;

    #[test]
    fn make_message_zero_round() {
        let (pk0, sk0) = gen_keypair();
        let (pk1, sk1) = gen_keypair();
        let (pk2, sk2) = gen_keypair();
        let (pk3, sk3) = gen_keypair();

        let votes: VotingPower = vec![(pk0, 1), (pk1, 1), (pk2, 1), (pk3, 1)]
            .into_iter()
            .collect();
        assert!(votes.quorum_size() == 3);

        let instance = [0; 16];
        let round = 0;
        let mut empty = DriverRequest::empty(instance, round);
        assert!(empty.check_request_valid(&votes).is_err());

        let data = BlockData::from(vec![0; 16]);
        let md0 = BlockMetadata::new(instance, round, pk0, 101);
        let bh0 = BlockHeader::empty(md0, digest_block_data(data.borrow()), data.data.len());
        let cert0 = bh0.creator_sign_header(&sk0).expect("No errors");

        empty.insert_block(&data, &bh0, &cert0).expect("No errors");
        assert!(empty.check_basic_valid(&votes).is_ok()); // Basic checks ok
        assert!(empty.check_request_valid(&votes).is_err()); // Request checks not ok

        let md0 = BlockMetadata::new(instance, round, pk1, 101);
        let bh0 = BlockHeader::empty(md0, digest_block_data(data.borrow()), data.data.len());
        let cert0 = bh0.creator_sign_header(&sk1).expect("No errors");

        empty.insert_block(&data, &bh0, &cert0).expect("No errors");
        assert!(empty.check_request_valid(&votes).is_err());

        let md0 = BlockMetadata::new(instance, round, pk2, 101);
        let bh0 = BlockHeader::empty(md0, digest_block_data(data.borrow()), data.data.len());
        let cert0 = bh0.creator_sign_header(&sk2).expect("No errors");

        empty.insert_block(&data, &bh0, &cert0).expect("No errors");
        assert!(empty.check_request_valid(&votes).is_ok());

        assert!(empty.check_request_valid(&votes).unwrap() == RequestValidState::HeaderQuorum(0));

        empty.sign_all_headers(&pk0, &sk0).unwrap();
        assert!(empty.check_request_valid(&votes).is_err());

        empty.sign_all_headers(&pk1, &sk1).unwrap();
        assert!(empty.check_request_valid(&votes).is_err());

        empty.sign_all_headers(&pk2, &sk2).unwrap();
        assert!(empty.check_request_valid(&votes).unwrap() == RequestValidState::CertQuorum(0));

        empty.sign_all_headers(&pk3, &sk3).unwrap();
        assert!(empty.check_request_valid(&votes).unwrap() == RequestValidState::CertQuorum(0));

        empty.block_data.remove(&pk0);
        assert!(empty.check_request_valid(&votes).is_err());
        empty.block_headers.remove(&pk0);
        assert!(empty.check_request_valid(&votes).is_err());

        empty.block_data.remove(&pk1);
        assert!(empty.check_request_valid(&votes).is_err());
        empty.block_headers.remove(&pk1);
        assert!(empty.check_request_valid(&votes).is_err());

        empty.block_data.remove(&pk2);
        assert!(empty.check_request_valid(&votes).is_err());
        empty.block_headers.remove(&pk2);
        assert!(empty.check_request_valid(&votes).is_ok());
    }

    #[test]
    fn make_message_one_round() {
        let (pk0, sk0) = gen_keypair();
        let (pk1, sk1) = gen_keypair();
        let (pk2, sk2) = gen_keypair();
        let (pk3, sk3) = gen_keypair();

        let votes: VotingPower = vec![(pk0, 1), (pk1, 1), (pk2, 1), (pk3, 1)]
            .into_iter()
            .collect();
        assert!(votes.quorum_size() == 3);

        let instance = [0; 16];
        let round = 0;
        let mut empty = DriverRequest::empty(instance, round);
        assert!(empty.check_request_valid(&votes).is_err());
        let data = BlockData::from([0; 16].to_vec());

        for (pkx, skx) in [(&pk0, &sk0), (&pk1, &sk1), (&pk2, &sk2), (&pk3, &sk3)] {
            let md0 = BlockMetadata::new(instance, round, *pkx, 101);
            let bh0 = BlockHeader::empty(md0, digest_block_data(data.borrow()), data.data.len());
            let cert0 = bh0.creator_sign_header(skx).expect("No errors");

            empty.block_data.insert(*pkx, data.clone());
            empty.block_headers.insert(*pkx, bh0);
            empty.block_certificates.insert(*pkx, cert0);
        }

        assert!(empty.check_request_valid(&votes).unwrap() == RequestValidState::HeaderQuorum(0));

        empty.sign_all_headers(&pk0, &sk0).unwrap();
        empty.sign_all_headers(&pk1, &sk1).unwrap();
        empty.sign_all_headers(&pk2, &sk2).unwrap();
        assert!(empty.check_request_valid(&votes).unwrap() == RequestValidState::CertQuorum(0));

        let round_zero_certs = empty.extract_full_certs(&votes);

        // Try round 1 without certs -- must err

        let instance = [0; 16];
        let round = 1;
        let mut empty = DriverRequest::empty(instance, round);
        assert!(empty.check_request_valid(&votes).is_err());

        for (pkx, skx) in [(&pk0, &sk0), (&pk1, &sk1), (&pk2, &sk2), (&pk3, &sk3)] {
            let md0 = BlockMetadata::new(instance, round, *pkx, 101);
            let bh0 = BlockHeader::empty(md0, digest_block_data(data.borrow()), data.data.len());
            let cert0 = bh0.creator_sign_header(skx).expect("No errors");

            empty.block_data.insert(*pkx, data.clone());
            empty.block_headers.insert(*pkx, bh0);
            empty.block_certificates.insert(*pkx, cert0);
        }

        assert!(empty.check_request_valid(&votes).is_err());

        // Try round 1 with certs -- must ok

        let instance = [0; 16];
        let round = 1;
        let mut empty = DriverRequest::empty(instance, round);
        assert!(empty.check_request_valid(&votes).is_err());

        for (pkx, skx) in [(&pk0, &sk0), (&pk1, &sk1), (&pk2, &sk2), (&pk3, &sk3)] {
            let md0 = BlockMetadata::new(instance, round, *pkx, 101);
            let mut bh0 = BlockHeader::empty(md0, digest_block_data(data.borrow()), data.data.len());
            bh0.block_certificates = round_zero_certs.clone();
            let cert0 = bh0.creator_sign_header(skx).expect("No errors");

            empty.block_data.insert(*pkx, data.clone());
            empty.block_headers.insert(*pkx, bh0);
            empty.block_certificates.insert(*pkx, cert0);
        }

        assert!(empty.check_request_valid(&votes).is_ok());
    }

    #[test]
    fn make_message_full() {
        let votes: VotingPower = vec![([0; 32], 1), ([1; 32], 1), ([2; 32], 1), ([3; 32], 1)]
            .into_iter()
            .collect();
        assert!(votes.quorum_size() == 3);
    }
}
