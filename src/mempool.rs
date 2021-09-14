//! Defines the client facing logic for the passive core.
//!
//! Client facing logic includes the list of transactions pending inclusion, or
//! awaiting confirmation. As well as accounting and credit data for each
//! client.

use crate::base_types::{Address, RoundID};
use failure::{bail, ensure, Fallible};

use std::collections::HashMap;

pub type GasUnit = u64;

/// A client account contains a balance that is local to this
/// passive core. As clients post transactions the balance is
/// lowered.
pub struct ClientAccount {
    /// Balance in gas.
    balance: GasUnit,
}

/// A structure representing a transaction that is either waiting
/// to be included in a block, or included and waiting for a
/// confirmation that the block is included / excluded.
pub struct PendingTransaction {
    _time_received: u64,
    client_origin: Address,
    transaction: Vec<u8>,
    inclusion_round: Option<RoundID>,
    gas_per_byte: GasUnit,
}

/// A mempool holds client balances, and transactions waiting to be included
/// or confirmed.
pub struct Mempool {
    client_accounts: HashMap<Address, ClientAccount>,
    pending_inclusion: Vec<PendingTransaction>,
    awaiting_confirmation: Vec<PendingTransaction>,
}

impl Mempool {

    pub fn new() -> Mempool {
        Mempool {
            client_accounts : HashMap::new(),
            pending_inclusion : Vec::new(),
            awaiting_confirmation : Vec::new(),
        }
    }

    /// Include a transactions into the list of pending transactions, and adjusts
    /// (down) the user account balance.
    pub fn include_transaction(&mut self, tx: PendingTransaction) -> Fallible<()> {
        ensure!(tx.inclusion_round.is_none());
        ensure!(tx.transaction.len() < u16::MAX.into());

        self.pay_for_tx(&tx)?;
        self.pending_inclusion.push(tx);

        Ok(())
    }

    /// Deducts the cost of including this transaction from the user account balance.
    pub fn pay_for_tx(&mut self, tx: &PendingTransaction) -> Fallible<()> {
        if !self.client_accounts.contains_key(&tx.client_origin) {
            if tx.gas_per_byte == 0 {
                return Ok(());
            } else {
                bail!("Not enough gas");
            }
        }

        let mut account = self.client_accounts.get_mut(&tx.client_origin).unwrap();
        let cost = (2 + tx.transaction.len() as u64) * tx.gas_per_byte;
        if account.balance < cost {
            bail!("Insufficient funds in account.")
        }

        // Pay for inclusion
        account.balance -= cost;

        Ok(())
    }

    /// Take a set of transactions from the pending inclusion list and add them into a block of a
    /// specified maximum size. The included transactions are prioritized through the gas per byte
    /// (more expensive first). They are then shifted to the ack list, awaiting acknowledgement.
    pub fn get_data_block(&mut self, round: RoundID, block_max_size: usize) -> Vec<u8> {
        self.pending_inclusion
            .sort_by(|a, b| a.gas_per_byte.partial_cmp(&b.gas_per_byte).unwrap());

        let mut block: Vec<u8> = Vec::with_capacity(block_max_size);
        while self.pending_inclusion.len() != 0 {
            // Get the next item length
            let this_len = self.pending_inclusion[self.pending_inclusion.len() - 1]
                .transaction
                .len();
            if block.len() + this_len + 2 > block_max_size {
                break;
            }

            let mut item = self.pending_inclusion.pop().expect("Just checked len > 0");

            // The format we use is 2 bytes (u16 length) than the bytes.
            block.extend((this_len as u16).to_le_bytes());
            block.extend(item.transaction.iter());

            item.inclusion_round = Some(round);
            self.awaiting_confirmation.push(item);
        }

        block
    }

    /// Reverting a block takes all transactions included in that block and re-inserts them
    /// into the pending inclusion list.
    pub fn revert_block(&mut self, round: RoundID) {
        let mut i = 0;
        while i < self.awaiting_confirmation.len() {
            if self.awaiting_confirmation[i].inclusion_round.unwrap() == round {
                let mut val = self.awaiting_confirmation.remove(i);
                // Re-include it in the pending group
                val.inclusion_round = None;
                self.pending_inclusion.push(val);
            } else {
                i += 1;
            }
        }
    }

    /// Confirming a block removes all transactions from that block from the ack
    /// list, since they are now posted.
    pub fn confirm_block(&mut self, round: RoundID) {
        let mut i = 0;
        while i < self.awaiting_confirmation.len() {
            if self.awaiting_confirmation[i].inclusion_round.unwrap() == round {
                let _val = self.awaiting_confirmation.remove(i);
                // Remove it
            } else {
                i += 1;
            }
        }
    }
}
