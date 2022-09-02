// Taken from https://github.com/poanetwork/threshold_crypto/blob/master/examples/threshold_enc.rs

use std::collections::BTreeMap;

use threshold_crypto::{
    Ciphertext, DecryptionShare, PublicKey, PublicKeySet, PublicKeyShare, SecretKeySet,
    SecretKeyShare,
};

// In this example scenario, the `SecretSociety` is the "trusted key dealer". The trusted dealer is
// responsible for key generation. The society creates a master public-key, which anyone can use to
// encrypt a message to the society's members; the society is also responsible for giving each
// actor their respective share of the secret-key.
pub struct SecretSociety {
    actors: Vec<Actor>,
    pk_set: PublicKeySet,
}

impl SecretSociety {
    // Creates a new `SecretSociety`.
    //
    // # Arguments
    //
    // `n_actors` - the number of actors (members) in the secret society.
    // `threshold` - the number of actors that must collaborate to successfully
    // decrypt a message must exceed this `threshold`.
    pub fn new(n_actors: usize, threshold: usize) -> Self {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(threshold, &mut rng);
        let pk_set = sk_set.public_keys();

        let actors = (0..n_actors)
            .map(|id| {
                let sk_share = sk_set.secret_key_share(id);
                let pk_share = pk_set.public_key_share(id);
                Actor::new(id, sk_share, pk_share)
            })
            .collect();

        SecretSociety { actors, pk_set }
    }

    // The secret society publishes its public-key to a publicly accessible key server.
    pub fn publish_public_key(&self) -> PublicKey {
        self.pk_set.public_key()
    }

    pub fn get_actor(&mut self, id: usize) -> &mut Actor {
        self.actors
            .get_mut(id)
            .expect("No `Actor` exists with that ID")
    }

    // Starts a new meeting of the secret society. Each time the set of actors receive an encrypted
    // message, at least 2 of them (i.e. 1 more than the threshold) must work together to decrypt
    // the ciphertext.
    pub fn start_decryption_meeting(&self) -> DecryptionMeeting {
        DecryptionMeeting {
            pk_set: self.pk_set.clone(),
            ciphertext: None,
            dec_shares: BTreeMap::new(),
        }
    }
}

// A member of the secret society.
#[derive(Clone, Debug)]
pub struct Actor {
    id: usize,
    sk_share: SecretKeyShare,
    pk_share: PublicKeyShare,
    msg_inbox: Option<Ciphertext>,
}

impl Actor {
    fn new(id: usize, sk_share: SecretKeyShare, pk_share: PublicKeyShare) -> Self {
        Actor {
            id,
            sk_share,
            pk_share,
            msg_inbox: None,
        }
    }
}

// Sends an encrypted message to an `Actor`.
fn send_msg(actor: &mut Actor, enc_msg: Ciphertext) {
    actor.msg_inbox = Some(enc_msg);
}

// A meeting of the secret society. At this meeting, actors collaborate to decrypt a shared
// ciphertext.
pub struct DecryptionMeeting {
    pk_set: PublicKeySet,
    ciphertext: Option<Ciphertext>,
    dec_shares: BTreeMap<usize, DecryptionShare>,
}

impl DecryptionMeeting {
    // An actor contributes their decryption share to the decryption process.
    fn accept_decryption_share(&mut self, actor: &mut Actor) {
        let ciphertext = actor.msg_inbox.take().unwrap();

        // Check that the actor's ciphertext is the same ciphertext decrypted at the meeting.
        // The first actor to arrive at the decryption meeting sets the meeting's ciphertext.
        if let Some(ref meeting_ciphertext) = self.ciphertext {
            if ciphertext != *meeting_ciphertext {
                return;
            }
        } else {
            self.ciphertext = Some(ciphertext.clone());
        }

        let dec_share = actor.sk_share.decrypt_share(&ciphertext).unwrap();
        let dec_share_is_valid = actor
            .pk_share
            .verify_decryption_share(&dec_share, &ciphertext);
        assert!(dec_share_is_valid);
        self.dec_shares.insert(actor.id, dec_share);
    }

    // Tries to decrypt the shared ciphertext using the decryption shares.
    fn decrypt_message(&self) -> Result<Vec<u8>, ()> {
        let ciphertext = self.ciphertext.clone().unwrap();
        self.pk_set
            .decrypt(&self.dec_shares, &ciphertext)
            .map_err(|_| ())
    }
}
