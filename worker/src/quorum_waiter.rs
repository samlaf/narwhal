// Copyright(C) Facebook, Inc. and its affiliates.
use crate::{
    batch_maker::Batch, processor::SerializedDecryptableBatchMessage, worker::WorkerMessage,
};
use config::{Committee, Stake};
use crypto::{
    threshold::{Ciphertext, DecryptionShare},
    BatchDecryptionShares, NodeDecryptionShares, NodeIndex, PublicKey, ThresholdDecryptionService,
};
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
#[cfg(not(test))]
use log::{debug, error, info, warn}; // Use log crate when building application
use network::CancelHandler;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
#[cfg(test)]
use std::{println as info, println as warn, println as error, println as debug};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot,
};

#[cfg(test)]
#[path = "tests/quorum_waiter_tests.rs"]
pub mod quorum_waiter_tests;

#[derive(Debug)]
pub struct QuorumWaiterMessage {
    /// A serialized `WorkerMessage::Batch` message.
    pub batch: Batch,
    /// The cancel handlers to receive the acknowledgements of our broadcast.
    pub named_decrypt_shares_handlers: Vec<(PublicKey, CancelHandler)>,
}

/// The QuorumWaiter waits for 2f authorities to acknowledge reception of a batch.
pub struct QuorumWaiter {
    /// The committee information.
    committee: Committee,
    /// The stake of this authority.
    stake: Stake,
    /// Service for decrypting ciphertexts
    threshold_decryption_service: ThresholdDecryptionService,
    /// Input Channel to receive commands.
    rx_message: Receiver<QuorumWaiterMessage>,
    /// Channel to deliver decryptable batches for which we have enough acknowledgements.
    tx_batch: Sender<SerializedDecryptableBatchMessage>,
    /// Channel to send DecryptableBatches to batch_maker.
    tx_decryptable_batch: Sender<(
        SerializedDecryptableBatchMessage,
        oneshot::Sender<Vec<(PublicKey, CancelHandler)>>,
    )>,
}

impl QuorumWaiter {
    /// Spawn a new QuorumWaiter.
    pub fn spawn(
        committee: Committee,
        stake: Stake,
        threshold_decryption_service: ThresholdDecryptionService,
        rx_message: Receiver<QuorumWaiterMessage>,
        tx_batch: Sender<Vec<u8>>,
        tx_decryptable_batch: Sender<(
            SerializedDecryptableBatchMessage,
            oneshot::Sender<Vec<(PublicKey, CancelHandler)>>,
        )>,
    ) {
        tokio::spawn(async move {
            Self {
                committee,
                stake,
                threshold_decryption_service,
                rx_message,
                tx_batch,
                tx_decryptable_batch: tx_decryptable_batch,
            }
            .run()
            .await;
        });
    }

    /// Helper function. It waits for a future to complete and then delivers a value.
    async fn decrypt_shares_waiter(
        wait_for_decrypt_shares: CancelHandler,
        stake: Stake,
    ) -> Option<(Stake, (NodeIndex, Vec<DecryptionShare>))> {
        match wait_for_decrypt_shares.await {
            Ok(bytes) => {
                // we try to decrypt the bytes.
                bincode::deserialize(&bytes)
                    .ok()
                    .map(|dec_shares| (stake, dec_shares))
            }
            // We only receive an error if the sender closes the channel before sending a bytes message.
            // If too many byzantine (>f) don't send us decrypt shares, this will stall our worker.
            Err(_) => None,
        }
    }
    /// Helper function. It waits for a future to complete and then delivers a value.
    async fn ack_waiter(wait_for: CancelHandler, deliver: Stake) -> Stake {
        let _ = wait_for.await;
        deliver
    }

    /// Main loop.
    async fn run(&mut self) {
        // receive batch from batch_maker
        while let Some(QuorumWaiterMessage {
            batch,
            named_decrypt_shares_handlers,
        }) = self.rx_message.recv().await
        {
            debug!("quorum_waiter: received QuorumWaiterMessage(batch)");
            // Step 1. first we decrypt our batch's ciphertexts
            let ciphertexts: Vec<Ciphertext> = batch
                .par_iter()
                .map(|tx| bincode::deserialize(tx).unwrap())
                .collect();
            let dec_shares: NodeDecryptionShares = self
                .threshold_decryption_service
                .request_decryption(ciphertexts)
                .await;
            let mut batch_decryption_shares: BatchDecryptionShares = vec![dec_shares];
            debug!("quorum_waiter: successfully decrypted our shares");

            // Then we wrap the handlers in futures
            let mut decrypt_shares_futures: FuturesUnordered<_> = named_decrypt_shares_handlers
                .into_iter()
                .map(|(name, handler)| {
                    let stake = self.committee.stake(&name);
                    Self::decrypt_shares_waiter(handler, stake)
                })
                .collect();

            // Step 2. and then wait for the first 2f nodes' decryption shares to arrive
            let mut total_stake = self.stake;
            let mut maybe_serialized_decryptable_batch: Option<SerializedDecryptableBatchMessage> =
                None;
            let (sender, receiver): (oneshot::Sender<_>, oneshot::Receiver<_>) = oneshot::channel();
            while let Some(Some((stake, dec_shares))) = decrypt_shares_futures.next().await {
                debug!("quorum_waiter: received dec_shares");
                total_stake += stake;
                batch_decryption_shares.push(dec_shares);
                if total_stake >= self.committee.quorum_threshold() {
                    debug!("quorum_waiter: gathered quorum threshold of dec shares!");
                    // Then we broadcast the decryptable_batch back to all nodes
                    let message = WorkerMessage::DecryptableBatch(batch, batch_decryption_shares);
                    let serialized_decryptable_batch =
                        bincode::serialize(&message).expect("Failed to serialize our own batch");
                    maybe_serialized_decryptable_batch = Some(serialized_decryptable_batch.clone());
                    self.tx_decryptable_batch
                        .send((serialized_decryptable_batch.clone(), sender))
                        .await
                        .unwrap();
                    break;
                }
            }
            let serialized_decryptable_batch = maybe_serialized_decryptable_batch
                .expect("Couldn't get enough decryptable shares for batch");
            let named_ack_handlers = receiver
                .await
                .expect("Failed to received ack handlers from batch_maker");

            // Step 2. then we wait for ACKs quorum
            let mut wait_for_quorum: FuturesUnordered<_> = named_ack_handlers
                .into_iter()
                .map(|(name, handler)| {
                    let stake = self.committee.stake(&name);
                    Self::ack_waiter(handler, stake)
                })
                .collect();

            
            // Wait for the first 2f nodes to send back an Ack. Then we consider the decryptable batch
            // delivered and we send its digest to the primary (that will include it into
            // the dag). This should reduce the amount of syncing.
            let mut total_stake = self.stake;
            debug!("quorum_waiter: waiting for 2f acks");
            while let Some(stake) = wait_for_quorum.next().await {
                total_stake += stake;
                if total_stake >= self.committee.quorum_threshold() {
                    debug!("quorum_waiter: gathered quorum of acks!");
                    self.tx_batch
                        .send(serialized_decryptable_batch)
                        .await
                        .expect("Failed to deliver batch");
                    break;
                }
            }
        }
    }
}
