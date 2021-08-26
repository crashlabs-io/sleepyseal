//! Defines the client facing logic for the passive core. 
//! 
//! Client facing logic includes the list of transactions pending inclusion, or 
//! awaiting confirmation. As well as accounting and credit data for each 
//! client.

use crate::base_types::{Address, RoundID};

use std::collections::HashMap;

pub type GasUnit = u64;


pub struct ClientAccount {
    /// Balance in gas.
    balance : GasUnit,
}

pub struct PendingTransaction {
    time_received : u64,
    transaction : Vec<u8>,
    client_origin : Address,
    inclusion_round : Option<RoundID>,
    gas_taken : GasUnit,
}

pub struct Mempool {
    client_accounts : HashMap<Address, ClientAccount>,
    pending_inclusion : Vec<PendingTransaction>,
    awaiting_confirmation : Vec<PendingTransaction>,
}