// Copyright(C) Facebook, Inc. and its affiliates.
use super::*;
use crate::common::{
    ack_listener, batch_digest, committee_with_base_port, dec_shares_listener, keys, transaction,
    transaction_length,
};
use network::SimpleSender;
use primary::WorkerPrimaryMessage;
use std::fs;

#[tokio::test]
async fn handle_clients_transactions() {
    let (name, _) = keys().pop().unwrap();
    let id = 0;
    let threshold_keypair = ThresholdKeyPair::new(1, 0, 0);
    let committee = committee_with_base_port(11_000);
    let parameters = Parameters {
        batch_size: 2 * transaction_length(), // Two transactions.
        ..Parameters::default()
    };

    // Create a new test store.
    let path = ".db_test_handle_clients_transactions";
    let _ = fs::remove_dir_all(path);
    let store = Store::new(path).unwrap();

    // Spawn a `Worker` instance.
    Worker::spawn(
        name,
        id,
        threshold_keypair,
        committee.clone(),
        parameters,
        store,
    );

    // Spawn a network listener to receive our batch's digest.
    let primary_address = committee.primary(&name).unwrap().worker_to_primary;
    let expected = bincode::serialize(&WorkerPrimaryMessage::OurBatch(batch_digest(), id)).unwrap();
    // TODO: add a check: have to create a digest of decryptable batch... but not sure which 2f+1 workers will answer first
    let handle = ack_listener(primary_address, None);

    // Spawn enough workers' listeners to acknowledge our batches.
    for (_, addresses) in committee.others_workers(&name, &id) {
        let address = addresses.worker_to_worker;
        let _ = dec_shares_listener(address, /* expected */ None);
    }

    // Send enough transactions to create a batch.
    let mut network = SimpleSender::new();
    let address = committee.worker(&name, &id).unwrap().transactions;
    network.send(address, Bytes::from(transaction())).await;
    network.send(address, Bytes::from(transaction())).await;

    // Ensure the primary received the batch's digest (ie. it did not panic).
    assert!(handle.await.is_ok());
}
