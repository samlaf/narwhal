// Copyright(C) Facebook, Inc. and its affiliates.
use super::*;
use crate::common::{batch, committee_with_base_port, keys, ack_listener};
use crate::worker::WorkerMessage;
use bytes::Bytes;
use config::ThresholdKeyPair;
use futures::future::try_join_all;
use network::ReliableSender;
use tokio::sync::mpsc::channel;

#[tokio::test]
async fn wait_for_quorum() {
    let (tx_message, rx_message) = channel(1);
    let (tx_batch, mut rx_batch) = channel(1);
    let (myself, _) = keys().pop().unwrap();
    let committee = committee_with_base_port(7_000);

    let threshold_keypair = ThresholdKeyPair::new(1, 0, 0);
    let threshold_decryption_service =
        ThresholdDecryptionService::spawn(threshold_keypair.sk_share, threshold_keypair.node_index);
    let (tx_decryptable_batches, rx_decryptable_batches) = channel(1);

    // Spawn a `QuorumWaiter` instance.
    QuorumWaiter::spawn(
        committee.clone(),
        /* stake */ 1,
        threshold_decryption_service,
        rx_message,
        tx_batch,
        tx_decryptable_batches,
    );

    // Make a batch.
    let message = WorkerMessage::Batch(batch());
    let serialized = bincode::serialize(&message).unwrap();
    let expected = Bytes::from(serialized.clone());

    // Spawn enough listeners to acknowledge our batches.
    let mut names = Vec::new();
    let mut addresses = Vec::new();
    let mut listener_handles = Vec::new();
    for (name, address) in committee.others_workers(&myself, /* id */ &0) {
        let address = address.worker_to_worker;
        let handle = ack_listener(address, Some(expected.clone()));
        names.push(name);
        addresses.push(address);
        listener_handles.push(handle);
    }

    // Broadcast the batch through the network.
    let bytes = Bytes::from(serialized.clone());
    let handlers = ReliableSender::new().broadcast(addresses, bytes).await;

    // Forward the batch along with the handlers to the `QuorumWaiter`.
    let message = QuorumWaiterMessage {
        batch: batch(),
        named_decrypt_shares_handlers: names.into_iter().zip(handlers.into_iter()).collect(),
    };
    tx_message.send(message).await.unwrap();

    // Wait for the `QuorumWaiter` to gather enough acknowledgements and output the batch.
    let output = rx_batch.recv().await.unwrap();
    assert_eq!(output, serialized);

    // Ensure the other listeners correctly received the batch.
    assert!(try_join_all(listener_handles).await.is_ok());
}
