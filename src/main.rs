use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes128Gcm, Key, Nonce};

use std::env;

fn main() {
    let mut mykey = "00000000000000000000000000000000";
    let mut msg = "This is a secret message!";
    let mut mynonce = "unique nonce";
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        msg = args[1].as_str();
    }
    if args.len() > 2 {
        mykey = args[2].as_str();
    }
    if args.len() > 3 {
        mynonce = args[3].as_str();
    }

    println!("== AES GCM ==");
    println!("Message: {:?}", msg);
    println!("Key: {:?}", mykey);
    println!("Nonce: {:?}", mynonce);

    let key_as_slice = hex::decode(mykey).expect("hex conversion failure!");

    let key = Key::from_slice(&key_as_slice);
    let cipher = Aes128Gcm::new(key);

    let nonce = Nonce::from_slice(mynonce.as_bytes());

    let ciphertext = cipher
        .encrypt(nonce, msg.as_ref())
        .expect("encryption failure!");
    println!("\nEncrypted: {}", hex::encode(ciphertext.clone()));

    let decipher = Aes128Gcm::new(key);
    let plaintext = decipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!");

    println!("\nDecrypted {}", std::str::from_utf8(&plaintext).unwrap());
}
