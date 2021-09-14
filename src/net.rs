use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::base_types::{Address, InstanceID};
use crate::core_state::SealCoreState;
use crate::mempool::Mempool;
use crate::messages::{DriverRequest, SummaryRequest};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};


#[derive(Clone, )]
pub struct MemDB {
    instances: Arc<Mutex<HashMap<InstanceID, (Arc<Mutex<Mempool>>, Arc<Mutex<SealCoreState>>)>>>,
}

impl MemDB {

    pub fn new() -> MemDB {
        MemDB {
            instances : Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get a counted reference to the mempool for an instance.
    pub fn get_mempool(&self, instance: InstanceID) -> Result<Option<Arc<Mutex<Mempool>>>, ()> {
        let inner_entry = self.instances.lock().map_err(|e| ())?;
        if let Some((mempool, _state)) = inner_entry.get(&instance) {
            return Ok(Some(mempool.clone()));
        } else {
            return Ok(None);
        }
    }

    /// Get a counted reference to the state of an instance.
    pub fn get_state(&self, instance: InstanceID) -> Result<Option<Arc<Mutex<SealCoreState>>>, ()> {
        let inner_entry = self.instances.lock().map_err(|e| ())?;
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
    /// State update
    Update(DriverRequest),
    /// Summary
    StateSummaryResponse(SummaryRequest),
    StateSummaryRequest,
}

use bincode;
use futures::stream::StreamExt;
use futures::SinkExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub fn process_message(_received: Message, store : MemDB) -> Result<Message, XError> {
    Ok(Message::StateSummaryRequest)
}

use failure::Error;

#[derive(Debug, Fail)]
pub enum XError {
    #[fail(display = "network error: {}", name)]
    NetWorkError { name: String },
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
