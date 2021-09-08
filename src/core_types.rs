//! Defines the consensus data structures to build a shared DAG.

use std::collections::BTreeMap;
use std::convert::TryInto;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use failure::{bail, ensure, Fallible};

use crate::crypto::{aggregate_signature, sign, verify, verify_aggregate_signature, PublicKey};

use crate::base_types::*;
use bitvec::prelude::*;

/// A structure that holds block meta-data.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockMetadata {
    /// The seal protocol instance, allowing for multiple decisions to be taken in parallel.
    pub instance: InstanceID,
    /// The Narwhal protocol round for a block
    pub round: RoundID,
    /// The address of the creator of the block
    pub creator: Address,
    /// A wall time timestamp
    pub timestamp: u64,
}

impl BlockMetadata {
    /// Creates a new block meta-data structure.
    pub fn new(
        instance: InstanceID,
        round: RoundID,
        creator: Address,
        timestamp: u64,
    ) -> BlockMetadata {
        BlockMetadata {
            instance,
            round,
            creator,
            timestamp,
        }
    }

    /// Returns the sha512 digest of the block meta-data.
    pub fn digest(&self) -> [u8; DIGEST_SIZE] {
        let mut hasher = Sha512::default();
        hasher.update("META");
        hasher.update(self.instance);
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.creator.to_le_bytes());
        hasher.update(self.timestamp.to_le_bytes());

        let mut result = [0; DIGEST_SIZE];
        result.clone_from_slice(&hasher.finalize().as_slice()[0..DIGEST_SIZE]);
        result
    }
}

/// Returns the sha512 digest of block payload data.
pub fn digest_block_data(data: &[u8]) -> BlockDataDigest {
    let data_digest = Sha512::digest(data);
    data_digest.as_slice()[0..DIGEST_SIZE].try_into().unwrap()
}

/// A block header for a particular node and round.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeader {
    /// The block meta-data (instance, round, creator, time)
    pub block_metadata: BlockMetadata,
    /// The cryptographic digest of the data included in this block.
    // #[serde(with = "BigArray")]
    pub data_digest: BlockDataDigest,
    /// The length of the data in bytes (the unit of cost.)
    pub data_length: usize,
    /// A map of previous block addresses to certificates.
    pub block_certificates: BTreeMap<Address, BlockHeaderDigest>,
}

impl BlockHeader {
    /// Returns an empty block header.
    pub fn empty(
        block_metadata: BlockMetadata,
        data_digest: BlockDataDigest,
        data_length: usize,
    ) -> BlockHeader {
        BlockHeader {
            block_metadata,
            data_digest,
            data_length,
            block_certificates: BTreeMap::new(),
        }
    }

    /// Returns the digest of a header (excludes the signatures in cert.)
    pub fn digest(&self) -> BlockHeaderDigest {
        let mut hasher = Sha512::default();
        hasher.update("HEAD");
        hasher.update(self.block_metadata.digest());
        hasher.update(self.data_digest);
        hasher.update(self.data_length.to_le_bytes());

        for (_addr, block_header_digest) in &self.block_certificates {
            hasher.update(block_header_digest.0);
        }

        // Note that we do not hash in the signatures within the
        // certificate.

        // let mut result = [0; 64];
        let mut result = [0; DIGEST_SIZE];
        result.clone_from_slice(&hasher.finalize().as_slice()[0..DIGEST_SIZE]);
        BlockHeaderDigest(result)
    }

    /// The creator of the block makes the very first partial certificate
    pub fn creator_sign_header(&self, _secret: &SigningSecretKey) -> Fallible<PartialCertificate> {
        let block_header_digest = self.digest();

        let mut cert = PartialCertificate {
            block_metadata: self.block_metadata.clone(),
            block_header_digest,
            signatures: BTreeMap::new(),
            aggregate_signature: None,
        };

        let cert_digest = cert.digest();

        let mut sig = [0; 48];
        sign(&_secret, &cert_digest, &mut sig);

        cert.signatures
            .insert(self.block_metadata.creator, SignatureBytes::new(sig));

        Ok(cert)
    }
}

use bitvec::vec::BitVec;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AggregateSignature {
    signers: BitVec,
    signature: SignatureBytes,
}

use std::collections::HashMap;

impl AggregateSignature {
    pub fn has_quorum(&self, votes: &VotingPower) -> bool {
        let signers: HashMap<_, _> = self
            .signers
            .iter()
            .enumerate()
            .filter(|(id, bit)| **bit)
            .map(|(id, bit)| ((id as Address), 0usize))
            .collect();
        return votes.has_quorum(signers.iter());
    }

    pub fn verify(&self, votes: &VotingPower, message: &[u8]) -> bool {
        let signers: Vec<&PublicKey> = self
            .signers
            .iter()
            .enumerate()
            .filter(|(id, bit)| **bit)
            .map(|(id, bit)| votes.get_key(&(id as Address)))
            .collect();

        return verify_aggregate_signature(&signers[..], message, &self.signature.bytes);
    }
}

/// A partial certificate containing one or more signatures for a block header.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PartialCertificate {
    /// The block metadata
    pub block_metadata: BlockMetadata,
    /// The header digest (incl the block data digest)
    pub block_header_digest: BlockHeaderDigest,
    /// The signatures supporting this certificate
    pub signatures: BTreeMap<Address, SignatureBytes>,
    /// An aggregate signature from a quorum of nodes.
    pub aggregate_signature: Option<AggregateSignature>,
}

impl PartialCertificate {
    /// The sha512 digest of a certificate (excludes all signatures).
    pub fn digest(&self) -> [u8; 64] {
        let mut hasher = Sha512::default();
        hasher.update("CERT");
        hasher.update(self.block_metadata.digest());
        hasher.update(self.block_header_digest.0);

        // Note that we do not hash in the signatures within the
        // certificate.

        let mut result = [0; 64];
        result.clone_from_slice(hasher.finalize().as_slice());
        result
    }

    /// Add a signature to a certificate.
    pub fn add_own_signature(
        &mut self,
        committee: &VotingPower,
        signer: &Address,
        _secret: &SigningSecretKey,
    ) -> Fallible<()> {
        if !self.signatures.contains_key(signer) {
            let mut sig = [0; 48];
            sign(&_secret, &self.digest(), &mut sig);

            self.signatures
                .insert(signer.clone(), SignatureBytes::new(sig));
        }

        Ok(())
    }

    /// Checks that all certificate signatures as valid.
    pub fn all_signatures_valid(&self, committee: &VotingPower) -> Fallible<()> {
        let cert_digest = self.digest();
        // Check each signature.
        for (addr, sign) in &self.signatures {
            let public_key: &PublicKey = committee.get_key(&addr);
            ensure!(verify(&public_key, &cert_digest[..], &sign.bytes));
        }

        // If present check the certificate
        if let Some(aggr) = &self.aggregate_signature {
            ensure!(aggr.verify(&committee, &cert_digest));
        }

        Ok(())
    }

    /// Merge all signatures from other certificate into this one (returns Err if signatures are for different blocks.)
    pub fn merge_from(&mut self, other_certificate: &PartialCertificate) -> Fallible<()> {
        if self.block_metadata != other_certificate.block_metadata
            || self.block_header_digest != other_certificate.block_header_digest
        {
            bail!("Different blocks!");
        }

        for (addr, sig) in other_certificate.signatures.iter() {
            if !self.signatures.contains_key(addr) {
                self.signatures.insert(*addr, sig.clone());
            }
        }

        // Copy a cert if present.
        if self.aggregate_signature.is_none() && other_certificate.aggregate_signature.is_some() {
            self.aggregate_signature = other_certificate.aggregate_signature.clone();
        }

        Ok(())
    }

    /// Strip all signatures except the one by the block creator.
    pub fn strip_other_signatures(&mut self) {
        let own_signature = self
            .signatures
            .remove(&self.block_metadata.creator)
            .expect("Certs always have own signature.");
        self.signatures.clear();
        self.signatures
            .insert(self.block_metadata.creator, own_signature);
    }

    /// Returns true if the certificate matches the block information.
    pub fn matches_block(&self, block: &BlockHeader) -> bool {
        if self.block_metadata != block.block_metadata {
            return false;
        }

        if self.block_header_digest != block.digest() {
            return false;
        }

        return true;
    }

    pub fn make_cert(&mut self, committee: &VotingPower) {
        if self.aggregate_signature.is_some() {
            // Already have a cert, just strip all other signatures.
            if self.signatures.len() > 1 {
                self.strip_other_signatures();
            }
            return;
        }

        if committee.has_quorum(self.signatures.iter()) {
            // Enough evidence to make a cert.
            let mut bv = bitvec![0;committee.num_keys()];
            let mut signatures = Vec::with_capacity(committee.num_keys());

            for (addr, sig) in &self.signatures {
                *bv.get_mut(*addr as usize).unwrap() = true;
                signatures.push(sig.bytes.clone());
            }

            let sig = aggregate_signature(&signatures[..]).unwrap();
            self.aggregate_signature = Some(AggregateSignature {
                signers: bv,
                signature: SignatureBytes { bytes: sig },
            });

            self.strip_other_signatures();
            return;
        }
    }

    pub fn has_quorum(&self, committee: &VotingPower) -> bool {
        if let Some(cert) = &self.aggregate_signature {
            if cert.has_quorum(&committee) {
                return true;
            }
        }

        if committee.has_quorum(self.signatures.iter()) {
            return true;
        }

        return false;
    }
}

/// A partial certificate with enough support to ensure quorum intersection.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockCertificate(pub PartialCertificate);

#[cfg(test)]
mod tests {

    use super::*;
    use crate::crypto::key_gen;

    #[test]
    fn make_and_hash_metadata() {
        let md1 = BlockMetadata {
            instance: [0; 16],
            round: 99,
            creator: 9,
            timestamp: 100,
        };

        let digest1 = md1.digest();

        // Same ds same hash
        let md2 = md1.clone();
        let digest2 = md2.digest();
        assert!(digest1 == digest2);

        // mess with instance
        let mut md2 = md1.clone();
        md2.instance = [1; 16];
        let digest_bad = md2.digest();
        assert!(digest1 != digest_bad);

        // mess with round
        let mut md2 = md1.clone();
        md2.round = 1000;
        let digest_bad = md2.digest();
        assert!(digest1 != digest_bad);

        // mess with creator
        let mut md2 = md1.clone();
        md2.creator = 8;
        let digest_bad = md2.digest();
        assert!(digest1 != digest_bad);

        // mess with time
        let mut md2 = md1.clone();
        md2.timestamp = 101;
        let digest_bad = md2.digest();
        assert!(digest1 != digest_bad);
    }

    #[test]
    fn make_block_header_and_sign_verify() -> Fallible<()> {
        let (pk, sk) = key_gen();

        let votes: VotingPower = vec![(pk, 4)].into_iter().collect();

        let block_metadata = BlockMetadata {
            instance: [0; 16],
            round: 99,
            creator: 0,
            timestamp: 100,
        };

        let bh = BlockHeader {
            block_metadata,
            data_digest: [0; DIGEST_SIZE],
            data_length: 100,
            block_certificates: BTreeMap::new(),
        };

        // Add a signature from the creator
        let mut cert = bh.creator_sign_header(&sk)?;

        // Check the signature work
        cert.all_signatures_valid(&votes)?;

        // Modify something
        cert.block_header_digest.0[0] = 1;
        assert!(cert.all_signatures_valid(&votes).is_err());

        // Add more signatures
        let mut cert = bh.creator_sign_header(&sk)?;
        let (_, sk2) = key_gen();
        cert.add_own_signature(&votes, &0, &sk2)?;

        // Check the signature work
        cert.all_signatures_valid(&votes)?;

        // Modify something
        cert.block_header_digest.0[0] = 1;
        assert!(cert.all_signatures_valid(&votes).is_err());

        Ok(())
    }
}
