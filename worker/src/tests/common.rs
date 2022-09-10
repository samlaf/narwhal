// Copyright(C) Facebook, Inc. and its affiliates.
use crate::batch_maker::{Batch, SerializedCiphertext};
use crate::worker::WorkerMessage;
use bytes::Bytes;
use config::{Authority, Committee, PrimaryAddresses, ThresholdKeyPair, WorkerAddresses};
use crypto::threshold::Ciphertext;
use crypto::{generate_keypair, Digest, PublicKey, SecretKey, ThresholdDecryptionService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use std::convert::TryInto as _;
use std::net::SocketAddr;
use std::{println as info, println as warn, println as error, println as debug};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

// Fixture
pub fn keys() -> Vec<(PublicKey, SecretKey)> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4).map(|_| generate_keypair(&mut rng)).collect()
}

// Fixture
pub fn committee() -> Committee {
    Committee {
        authorities: keys()
            .iter()
            .enumerate()
            .map(|(i, (id, _))| {
                let primary = PrimaryAddresses {
                    primary_to_primary: format!("127.0.0.1:{}", 100 + i).parse().unwrap(),
                    worker_to_primary: format!("127.0.0.1:{}", 200 + i).parse().unwrap(),
                };
                let workers = vec![(
                    0,
                    WorkerAddresses {
                        primary_to_worker: format!("127.0.0.1:{}", 300 + i).parse().unwrap(),
                        transactions: format!("127.0.0.1:{}", 400 + i).parse().unwrap(),
                        worker_to_worker: format!("127.0.0.1:{}", 500 + i).parse().unwrap(),
                    },
                )]
                .iter()
                .cloned()
                .collect();
                (
                    *id,
                    Authority {
                        stake: 1,
                        primary,
                        workers,
                    },
                )
            })
            .collect(),
    }
}

// Fixture.
pub fn committee_with_base_port(base_port: u16) -> Committee {
    let mut committee = committee();
    for authority in committee.authorities.values_mut() {
        let primary = &mut authority.primary;

        let port = primary.primary_to_primary.port();
        primary.primary_to_primary.set_port(base_port + port);

        let port = primary.worker_to_primary.port();
        primary.worker_to_primary.set_port(base_port + port);

        for worker in authority.workers.values_mut() {
            let port = worker.primary_to_worker.port();
            worker.primary_to_worker.set_port(base_port + port);

            let port = worker.transactions.port();
            worker.transactions.set_port(base_port + port);

            let port = worker.worker_to_worker.port();
            worker.worker_to_worker.set_port(base_port + port);
        }
    }
    committee
}

pub fn transaction_length() -> usize {
    let tx = transaction();
    tx.len()
}
// Fixture
pub fn transaction() -> SerializedCiphertext {
    let threshold_keypair = ThresholdKeyPair::new(1, 0, 0);
    let pk = threshold_keypair.pk_set.public_key();
    let msg = vec![0; 100];
    let ciphertext = pk.encrypt(&msg);
    let serialized_ciphertext = bincode::serialize(&ciphertext).unwrap();
    serialized_ciphertext
}

// Fixture
pub fn batch() -> Batch {
    vec![transaction(), transaction()]
}

// Fixture
pub fn serialized_batch() -> Vec<u8> {
    let message = WorkerMessage::Batch(batch());
    bincode::serialize(&message).unwrap()
}

// Fixture
pub fn batch_digest() -> Digest {
    Digest(
        Sha512::digest(&serialized_batch()).as_slice()[..32]
            .try_into()
            .unwrap(),
    )
}

// Fixture
pub fn ack_listener(address: SocketAddr, expected: Option<Bytes>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(&address).await.unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let transport = Framed::new(socket, LengthDelimitedCodec::new());
        let (mut writer, mut reader) = transport.split();
        match reader.next().await {
            Some(Ok(received)) => {
                writer.send(Bytes::from("Ack")).await.unwrap();
                if let Some(expected) = expected {
                    assert_eq!(received.freeze(), expected);
                }
            }
            _ => panic!("Failed to receive network message"),
        }
    })
}

// Fixture
pub fn dec_shares_listener(address: SocketAddr, expected: Option<Bytes>) -> JoinHandle<()> {
    let threshold_keypair = ThresholdKeyPair::new(1, 0, 0);
    let threshold_decryption_service =
        ThresholdDecryptionService::spawn(threshold_keypair.sk_share, threshold_keypair.node_index);
    tokio::spawn(async move {
        let listener = TcpListener::bind(&address).await.unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let transport = Framed::new(socket, LengthDelimitedCodec::new());
        let (mut writer, mut reader) = transport.split();
        loop {
            match reader.next().await {
                Some(Ok(received)) => {
                    let msg = received.freeze();
                    match bincode::deserialize(&msg) {
                        Ok(WorkerMessage::Batch(txs)) => {
                            debug!("dec_shares_listener: received workermessage(Batch)");
                            let ciphertexts: Vec<Ciphertext> = txs
                                .par_iter()
                                .map(|tx| bincode::deserialize(tx).unwrap())
                                .collect();
                            let dec_shares = threshold_decryption_service
                                .request_decryption(ciphertexts)
                                .await;
                            let serialized_dec_shares =
                                Bytes::from(bincode::serialize(&dec_shares).unwrap());
                            debug!("dec_shares_listener: sending back dec shares");
                            writer.send(serialized_dec_shares).await.unwrap();
                        }
                        Ok(WorkerMessage::DecryptableBatch(..)) => {
                            debug!("dec_shares_listener: received a WorkerMessage::DecryptableBatch, sending back Ack");
                            writer.send(Bytes::from("Ack")).await.unwrap();
                        }
                        _ => debug!("dec_shares_listener: received wrong workermessage!"),
                    }
                }
                _ => {
                    debug!("dec_shares_listener: Failed to receive network message");
                    panic!("Failed to receive network message")
                }
            }
        }
    })
}
