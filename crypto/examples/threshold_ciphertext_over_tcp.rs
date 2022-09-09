use bytes::{Bytes, BytesMut};
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use futures::StreamExt;
use rand::SeedableRng;
use threshold_crypto::{Ciphertext, PublicKey, SecretKey, SecretKeySet};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

struct ThresholdKeyPair {
    pk: PublicKey,
}
impl ThresholdKeyPair {
    fn new() -> Self {
        let mut rng = rand::prelude::StdRng::seed_from_u64(0);
        let sk_set = SecretKeySet::random(1, &mut rng);
        let pk = sk_set.public_keys().public_key();
        ThresholdKeyPair { pk }
    }
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:7878";
    let threshold_keypair = ThresholdKeyPair::new();
    let pk = threshold_keypair.pk;

    // start listening server
    let handler = tokio::spawn(async move {
        let listener = TcpListener::bind(addr).await.unwrap();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            process(socket).await;
        }
    });

    // Connect to server and send message
    let sender_socket = TcpStream::connect(addr).await.unwrap();
    let mut transport = Framed::new(sender_socket, LengthDelimitedCodec::new());
    // let (mut writer, _) = transport.split();

    let mut tx = BytesMut::with_capacity(10);
    tx.resize(3, 0u8);
    let bytes = tx.split().freeze();
    let ciphertext = pk.encrypt(bytes);
    let serialized_ciphertext = bincode::serialize(&ciphertext).unwrap();
    println!("serialized ciphertext: {:?}", &serialized_ciphertext);
    let msg = Bytes::from(serialized_ciphertext);
    let ciphertext: Ciphertext = bincode::deserialize(&msg).unwrap();
    transport.send(msg).await.unwrap();

    tokio::join!(handler).0.unwrap();
}

async fn process(socket: TcpStream) {
    let transport = Framed::new(socket, LengthDelimitedCodec::new());
    let (_, mut reader) = transport.split();
    while let Some(Ok(frame)) = reader.next().await {
        println!("{:?}", frame);
        let ciphertext: Ciphertext = bincode::deserialize(&frame.freeze()).unwrap();
    }
}
