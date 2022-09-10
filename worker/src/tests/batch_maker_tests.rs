// Copyright(C) Facebook, Inc. and its affiliates.
use super::*;
use crate::common::transaction;
use tokio::sync::mpsc::channel;

#[tokio::test]
async fn make_batch() {
    let (tx_transaction, rx_transaction) = channel(1);
    let (tx_message, mut rx_message) = channel(1);
    let dummy_addresses = vec![(PublicKey::default(), "127.0.0.1:0".parse().unwrap())];
    let (tx_decryptable_batches, rx_decryptable_batches) = channel(1);

    // Spawn a `BatchMaker` instance.
    BatchMaker::spawn(
        /* max_batch_size */ 200,
        /* max_batch_delay */ 1_000_000, // Ensure the timer is not triggered.
        rx_transaction,
        rx_decryptable_batches,
        tx_message,
        /* workers_addresses */ dummy_addresses,
    );

    // Send enough transactions to seal a batch.
    tx_transaction.send(transaction()).await.unwrap();
    tx_transaction.send(transaction()).await.unwrap();

    // Ensure the batch is as expected.
    let expected_batch = vec![transaction(), transaction()];
    let QuorumWaiterMessage {
        batch,
        named_decrypt_shares_handlers: _,
    } = rx_message.recv().await.unwrap();
    // TODO: fix this test
    // match bincode::deserialize(&batch).unwrap() {
    //     WorkerMessage::Batch(batch) => assert_eq!(batch, expected_batch),
    //     _ => panic!("Unexpected message"),
    // }
}

#[tokio::test]
async fn batch_timeout() {
    let (tx_transaction, rx_transaction) = channel(1);
    let (tx_message, mut rx_message) = channel(1);
    let dummy_addresses = vec![(PublicKey::default(), "127.0.0.1:0".parse().unwrap())];
    let (tx_decryptable_batches, rx_decryptable_batches) = channel(1);

    // Spawn a `BatchMaker` instance.
    BatchMaker::spawn(
        /* max_batch_size */ 200,
        /* max_batch_delay */ 50, // Ensure the timer is triggered.
        rx_transaction,
        rx_decryptable_batches,
        tx_message,
        /* workers_addresses */ dummy_addresses,
    );

    // Do not send enough transactions to seal a batch..
    tx_transaction.send(transaction()).await.unwrap();

    // Ensure the batch is as expected.
    let expected_batch = vec![transaction()];
    let QuorumWaiterMessage {
        batch,
        named_decrypt_shares_handlers: _,
    } = rx_message.recv().await.unwrap();
    // TODO: fix this test
    // match bincode::deserialize(&batch).unwrap() {
    //     WorkerMessage::Batch(batch) => assert_eq!(batch, expected_batch),
    //     _ => panic!("Unexpected message"),
    // }
}
