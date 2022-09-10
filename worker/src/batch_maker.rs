use crate::processor::SerializedDecryptableBatchMessage;
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::quorum_waiter::QuorumWaiterMessage;
use crate::worker::WorkerMessage;
use bytes::Bytes;
#[cfg(feature = "benchmark")]
use crypto::Digest;
use crypto::PublicKey;
#[cfg(feature = "benchmark")]
use ed25519_dalek::{Digest as _, Sha512};
#[cfg(feature = "benchmark")]
#[cfg(not(test))]
use log::{debug, error, info, warn}; // Use log crate when building application
use network::{CancelHandler, ReliableSender};
use std::convert::TryInto;
#[cfg(feature = "benchmark")]
use std::convert::TryInto as _;
use std::net::SocketAddr;
#[cfg(test)]
use std::{println as info, println as warn, println as error, println as debug};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::oneshot;
use tokio::time::{sleep, Duration, Instant};

#[cfg(test)]
#[path = "tests/batch_maker_tests.rs"]
pub mod batch_maker_tests;

pub type SerializedCiphertext = Vec<u8>;
pub type Batch = Vec<SerializedCiphertext>;

/// Assemble clients transactions into batches.
pub struct BatchMaker {
    /// The preferred batch size (in bytes).
    batch_size: usize,
    /// The maximum delay after which to seal the batch (in ms).
    max_batch_delay: u64,
    /// Channel to receive transactions from the network.
    rx_transaction: Receiver<SerializedCiphertext>,
    /// Channel to receive DecryptableBatches from quorum_waiter.
    rx_decryptable_batches: Receiver<(
        SerializedDecryptableBatchMessage,
        oneshot::Sender<Vec<(PublicKey, CancelHandler)>>,
    )>,
    /// Output channel to deliver sealed batches to the `QuorumWaiter`.
    tx_message: Sender<QuorumWaiterMessage>,
    /// The network addresses of the other workers that share our worker id.
    workers_addresses: Vec<(PublicKey, SocketAddr)>,
    /// Holds the current batch.
    current_batch: Batch,
    /// Holds the size of the current batch (in bytes).
    current_batch_size: usize,
    /// A network sender to broadcast the batches to the other workers.
    network: ReliableSender,
}

impl BatchMaker {
    pub fn spawn(
        batch_size: usize,
        max_batch_delay: u64,
        rx_transaction: Receiver<SerializedCiphertext>,
        rx_decryptable_batches: Receiver<(
            SerializedDecryptableBatchMessage,
            oneshot::Sender<Vec<(PublicKey, CancelHandler)>>,
        )>,
        tx_message: Sender<QuorumWaiterMessage>,
        workers_addresses: Vec<(PublicKey, SocketAddr)>,
    ) {
        tokio::spawn(async move {
            Self {
                batch_size,
                max_batch_delay,
                rx_transaction,
                rx_decryptable_batches,
                tx_message,
                workers_addresses,
                current_batch: Batch::with_capacity(batch_size * 2),
                current_batch_size: 0,
                network: ReliableSender::new(),
            }
            .run()
            .await;
        });
    }

    /// Main loop receiving incoming transactions and creating batches.
    async fn run(&mut self) {
        let timer = sleep(Duration::from_millis(self.max_batch_delay));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                // Assemble client transactions into batches of preset size.
                Some(transaction) = self.rx_transaction.recv() => {
                    debug!("batch_maker: received tx");
                    self.current_batch_size += transaction.len();
                    self.current_batch.push(transaction);
                    if self.current_batch_size >= self.batch_size {
                        self.seal().await;
                        timer.as_mut().reset(Instant::now() + Duration::from_millis(self.max_batch_delay));
                    }
                },

                // If we received decryptable batch from quorum_waiter
                Some((serialized_decryptable_batch_msg, return_channel)) = self.rx_decryptable_batches.recv() => {
                    let (names, addresses): (Vec<_>, _) =
                    self.workers_addresses.iter().cloned().unzip();
                    let bytes = Bytes::from(serialized_decryptable_batch_msg);
                    // Broadcast the decryptable shares batch through the network.
                    debug!("batch_maker: broadcasting serialized_decryptable_batch_msg to other validators");
                    let handlers = self.network.broadcast(addresses, bytes).await;
                    // and return the named handlers to quorum_waiter
                    let named_handlers = names.into_iter().zip(handlers.into_iter()).collect();
                    return_channel.send(named_handlers).unwrap();
                },

                // If the timer triggers, seal the batch even if it contains few transactions.
                () = &mut timer => {
                    if !self.current_batch.is_empty() {
                        self.seal().await;
                    }
                    timer.as_mut().reset(Instant::now() + Duration::from_millis(self.max_batch_delay));
                }
            }

            // Give the change to schedule other tasks.
            tokio::task::yield_now().await;
        }
    }

    /// Seal and broadcast the current batch.
    async fn seal(&mut self) {
        #[cfg(feature = "benchmark")]
        let size = self.current_batch_size;
        // Serialize the batch.
        self.current_batch_size = 0;
        let batch: Batch = self.current_batch.drain(..).collect();

        // Look for sample txs (they all start with 0) and gather their txs id (the next 8 bytes).
        #[cfg(feature = "benchmark")]
        let (batch, suffixes): (Vec<_>, Vec<_>) = batch
            .iter()
            .map(|tx| tx.split_at(tx.len() - 9))
            .map(|(left, right)| (left.to_vec(), right.to_vec()))
            .unzip();
        #[cfg(feature = "benchmark")]
        let tx_ids: Vec<[u8; 8]> = suffixes
            .iter()
            .filter(|suffix| suffix[0] == 0u8)
            .filter_map(|suffix| suffix[1..9].try_into().ok())
            .collect();

        let message = WorkerMessage::Batch(batch.clone());
        let serialized_batch_msg =
            bincode::serialize(&message).expect("Failed to serialize our own batch");

        #[cfg(feature = "benchmark")]
        {
            // NOTE: This is one extra hash that is only needed to print the following log entries.
            let digest = Digest(
                Sha512::digest(&serialized_batch_msg).as_slice()[..32]
                    .try_into()
                    .unwrap(),
            );

            for id in tx_ids {
                // NOTE: This log entry is used to compute performance.
                info!(
                    "Batch {:?} contains sample tx {}",
                    digest,
                    u64::from_be_bytes(id)
                );
            }

            // NOTE: This log entry is used to compute performance.
            info!("Batch {:?} contains {} B", digest, size);
        }

        // Broadcast the batch through the network.
        let (names, addresses): (Vec<_>, _) = self.workers_addresses.iter().cloned().unzip();
        let bytes = Bytes::from(serialized_batch_msg.clone());
        debug!("batch_maker: broadcasting batch to other validators");
        let handlers = self.network.broadcast(addresses, bytes).await;

        // Send the batch through the deliver channel for further processing.
        self.tx_message
            .send(QuorumWaiterMessage {
                batch,
                named_decrypt_shares_handlers: names
                    .into_iter()
                    .zip(handlers.into_iter())
                    .collect(),
            })
            .await
            .expect("Failed to deliver batch");
    }
}
