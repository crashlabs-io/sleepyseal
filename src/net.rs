use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::base_types::{Address, BlockData, InstanceID, SigningSecretKey, VotingPower};
use crate::core_state::SealCoreState;
use crate::mempool::{Mempool, PendingTransaction};
use crate::messages::{DriverRequest, SummaryRequest};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

pub type MempoolPointer = Arc<Mutex<Mempool>>;
pub type StatePointer = Arc<Mutex<SealCoreState>>;

#[derive(Clone)]
pub struct MemDB {
    instances: Arc<Mutex<HashMap<InstanceID, (MempoolPointer, StatePointer)>>>,
}

impl MemDB {
    pub fn new() -> MemDB {
        MemDB {
            instances: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn insert_instance(
        &self,
        my_address: Address,
        my_secret: SigningSecretKey,
        committee: VotingPower,
        instance: InstanceID,
        data: BlockData,
    ) -> Result<(MempoolPointer, StatePointer), XError> {
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let state = Arc::new(Mutex::new(SealCoreState::init(
            my_address, my_secret, committee, instance, data,
        )));

        let mut map = self.instances.lock().map_err(|_e| XError::LockError {
            name: "Lock failed on init.".into(),
        })?;
        if let Some(values) = map.get(&instance) {
            return Ok(values.clone());
        } else {
            map.insert(instance, (mempool.clone(), state.clone()));
        }

        Ok((mempool, state))
    }

    /// Get a counted reference to the mempool for an instance.
    pub fn get_mempool(&self, instance: InstanceID) -> Result<Option<MempoolPointer>, ()> {
        let inner_entry = self.instances.lock().map_err(|_e| ())?;
        if let Some((mempool, _state)) = inner_entry.get(&instance) {
            return Ok(Some(mempool.clone()));
        } else {
            return Ok(None);
        }
    }

    /// Get a counted reference to the state of an instance.
    pub fn get_state(&self, instance: InstanceID) -> Result<Option<StatePointer>, ()> {
        let inner_entry = self.instances.lock().map_err(|_e| ())?;
        if let Some((_mempool, state)) = inner_entry.get(&instance) {
            return Ok(Some(state.clone()));
        } else {
            return Ok(None);
        }
    }

    pub fn insert(
        &self,
        instance: InstanceID,
        mempool: Mempool,
        state: SealCoreState,
    ) -> Result<(), ()> {
        let mut inner_entry = self.instances.lock().map_err(|_e| ())?;
        if inner_entry.get(&instance).is_none() {
            inner_entry.insert(
                instance,
                (Arc::new(Mutex::new(mempool)), Arc::new(Mutex::new(state))),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum Message {
    /// A transaction from an originator, with some data
    Transaction(Address, InstanceID, Vec<u8>),
    TransactionStored,
    /// Request a Summary of the state for an instance.
    SummaryRequest(InstanceID),
    /// Respond with the Summary of the state for an instance.
    SummaryResponse(SummaryRequest),
    /// Full State Read / Update
    StateRequest(InstanceID),
    StateResponse(DriverRequest),
    /// State update
    StateUpdate(DriverRequest),
    UpdateResponse,
    /// Generic Error
    Error(XError),
}

use bincode;
use futures::stream::StreamExt;
use futures::SinkExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub fn process_transaction(_received: Message, store: &mut MemDB) -> Result<Message, XError> {
    if let Message::Transaction(address, instance, data) = _received {
        let tx = PendingTransaction::new(instance, address, data);

        let mempool_ptr = store
            .get_mempool(instance)
            .map_err(|_e| XError::GenericError)?;
        if mempool_ptr.is_none() {
            return Err(XError::LogicError {
                name: "Cannot find this instance.".into(),
            });
        }
        let mempool = mempool_ptr.unwrap(); // .expect("Cannot panic");

        mempool
            .lock()
            .map_err(|e| XError::GenericError)?
            .include_transaction(tx)
            .map_err(|e| XError::GenericError)?;

        return Ok(Message::TransactionStored);
    }

    unreachable!();
}

pub fn process_message(_received: Message, mut store: MemDB) -> Result<Message, XError> {
    match _received {
        msg @ Message::Transaction(_, _, _) => {
            return process_transaction(msg, &mut store);
        }
        _ => {}
    }

    Ok(Message::UpdateResponse)
}

use failure::Error;

#[derive(Clone, Debug, Fail, Serialize, Deserialize, PartialEq)]
pub enum XError {
    #[fail(display = "network error: {}", name)]
    NetWorkError { name: String },
    #[fail(display = "Lock error: {}", name)]
    LockError { name: String },
    #[fail(display = "Logic error: {}", name)]
    LogicError { name: String },
    #[fail(display = "GenericError")]
    GenericError,
}

async fn main_server(address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(address).await?;
    let store = MemDB::new();

    loop {
        let (mut socket, _) = listener.accept().await?;
        let mut framed = Framed::new(socket, LengthDelimitedCodec::new());

        let moved_store = store.clone();
        tokio::spawn(async move {
            // In a loop, read data from the socket and write the data back.
            loop {
                if let Some(Ok(data)) = framed.next().await {
                    let decoded: Message =
                        bincode::deserialize(&data[..]).map_err(|_e| XError::NetWorkError {
                            name: "De-serialization error".into(),
                        })?;
                    let response = process_message(decoded, moved_store.clone())?;
                    let encoded: Vec<u8> =
                        bincode::serialize(&response).map_err(|_e| XError::NetWorkError {
                            name: "Serialization error".into(),
                        })?;

                    framed
                        .send(encoded.into())
                        .await
                        .map_err(|_e| XError::NetWorkError {
                            name: "Network Sending error".into(),
                        })?;
                } else {
                    return Result::<(), XError>::Ok(());
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::base_types::BlockData;
    use crate::crypto::key_gen;

    #[test]
    fn test_process_transaction() {
        let mut db = MemDB::new();

        let (pk0, sk0) = key_gen();
        let (pk1, _) = key_gen();
        let (pk2, _) = key_gen();
        let (pk3, _) = key_gen();

        let votes: VotingPower = vec![(pk0, 1), (pk1, 1), (pk2, 1), (pk3, 1)]
            .into_iter()
            .collect();

        let address = 0;
        let instance = [0; 16];
        let (mempool, _state) = db
            .insert_instance(address, sk0, votes, instance, BlockData::from(vec![]))
            .expect("No errors.");

        let tx = Message::Transaction(address, instance, vec![100; 50]);

        assert!(mempool.lock().unwrap().pending_inclusion.len() == 0);
        let response = process_transaction(tx, &mut db);
        assert!(response == Ok(Message::TransactionStored));
        assert!(mempool.lock().unwrap().pending_inclusion.len() == 1);
    }
}
