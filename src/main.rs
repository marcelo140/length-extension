mod engine;

use hex;
use sha2::{Sha256, Digest};

use engine::LengthExtensionEngine;

const ORIGINAL_REQUEST: &str = "add 1";
const REQUEST_EXTENSION: &str = " and add 2";
const ORIGINAL_MAC: &str = "20e05d0afa47a9d3dad361bdcd405f705e5baee9c0aae1eb66ca98bd6690f546";

const SECRET: &str = "secret";
const MAX_SECRET_SIZE: usize = 1024;

struct MockService {}

impl MockService {
    pub fn validate_message<B: AsRef<[u8]>>(input: B, mac: &[u8]) -> bool {
        let mut secured_input = SECRET.as_bytes().to_vec();
        secured_input.extend_from_slice(input.as_ref());

        let mut hasher = Sha256::new();
        hasher.input(secured_input);
        hasher.result().as_slice() == mac
    }
}

fn main() {
    let digest = engine::into_sha256_state(&hex::decode(ORIGINAL_MAC).unwrap());
    let engine = LengthExtensionEngine::new(ORIGINAL_REQUEST, REQUEST_EXTENSION);


    for (secret_size, candidate_input) in engine.candidate_inputs().enumerate() {
        let tampered_mac = engine.tampered_mac(&digest, secret_size);

        if MockService::validate_message(&candidate_input, &tampered_mac.as_slice()) {

            println!("Found valid input! Secret size is {}.", secret_size);
            println!("Extended MAC: {}", hex::encode(tampered_mac.as_slice()));
            println!("Extended input:\n{:?}", candidate_input);

            std::process::exit(0);
        }
    }

    println!("Could not find a valid message considering secret sizes up to {}", MAX_SECRET_SIZE);
    std::process::exit(1);
}

