use bytes::Bytes;
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use futures::StreamExt;
use threshold_crypto::{Ciphertext, PublicKey, SecretKey};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

#[derive(Debug, Clone)]
struct KeyPair {
    sk: SecretKey,
    pk: PublicKey,
}
impl KeyPair {
    fn random() -> Self {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        KeyPair { sk, pk }
    }
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:7878";
    let alice = KeyPair::random();

    let alice_sk = alice.sk.clone();
    // start listening server
    let handler = tokio::spawn(async move {
        let listener = TcpListener::bind(addr).await.unwrap();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            process(socket, &alice_sk).await;
        }
    });

    // Connect to server and send message
    let sender_socket = TcpStream::connect(addr).await.unwrap();
    let transport = Framed::new(sender_socket, LengthDelimitedCodec::new());
    let (mut writer, _) = transport.split();

    let msg = "hello";
    let ciphertext = alice.clone().pk.encrypt(msg);
    let serialized_ciphertext = serde_json::to_string(&ciphertext).unwrap();
    println!("serialized ciphertext: {}", serialized_ciphertext);
    writer.send(Bytes::from(serialized_ciphertext)).await.unwrap();

    tokio::join!(handler).0.unwrap();
}

async fn process(socket: TcpStream, sk: &SecretKey) {
    let transport = Framed::new(socket, LengthDelimitedCodec::new());
    let (_, mut reader) = transport.split();
    while let Some(Ok(frame)) = reader.next().await {
        println!("{:?}", frame);
        let serialized_ciphertext = String::from_utf8(frame.to_vec()).unwrap();
        let ciphertext: Ciphertext = serde_json::from_str(&serialized_ciphertext).unwrap();
        let decoded_msg_u8 = sk.decrypt(&ciphertext).unwrap();
        let decoded_msg = String::from_utf8(decoded_msg_u8).unwrap();
        println!("decoded msg: {}", decoded_msg);
    }
}
