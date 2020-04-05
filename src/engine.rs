use sha2::{Sha256, Digest};

use std::convert::TryInto;

const BLOCK_SIZE: usize = 64;
const MINIMUM_PADDING: usize = 9;

pub struct LengthExtensionEngine {
    message: String,
    extension: String,
}

impl LengthExtensionEngine {
    pub fn new<T: ToString>(message: T, extension: T) -> Self {
        LengthExtensionEngine { 
            message: message.to_string(),
            extension: extension.to_string(),
        }
    }

    fn candidate_message(&self, secret_size: usize) -> Vec<u8> {
        let input_size = (secret_size + self.message.len()) as u64;
        let extra_padding = BLOCK_SIZE - (self.message.len() + secret_size + MINIMUM_PADDING % BLOCK_SIZE);
        let capacity = self.message.len() + extra_padding + MINIMUM_PADDING + self.extension.len();

        let mut v = Vec::with_capacity(capacity);

        v.extend(self.message.as_bytes());
        v.push(0x80);
        v.resize_with(capacity - 8 - self.extension.len(), Default::default);
        v.extend(&(input_size*8).to_be_bytes()); // input_size in bits
        v.extend(self.extension.as_bytes());

        v
    }

    pub fn candidate_inputs(&self, max_secret_size: usize) -> CandidateInputs {
        CandidateInputs {
            engine: self,
            secret_size: 0,
            max_secret_size: max_secret_size,
        }
    }

    pub fn tampered_mac(&self, internal_state: &[u32; 8], secret_size: usize) -> Vec<u8> {
        let mut bytes_processed = self.message.len() + secret_size;
        // sha256 processes blocks of 64 bytes at a time
        bytes_processed +=  64 - (bytes_processed % 64);

        let mut hasher = Sha256::with_internal_state(&internal_state, bytes_processed as u64);
        hasher.input(&self.extension);

        hasher.result().as_slice().to_owned()
    }
}

pub struct CandidateInputs<'a> {
    engine: &'a LengthExtensionEngine,
    secret_size: usize,
    max_secret_size: usize,
}

impl<'a> Iterator for CandidateInputs<'a> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.secret_size == self.max_secret_size {
            return None;
        }

        let r = self.engine.candidate_message(self.secret_size);
        self.secret_size += 1;

        Some(r)
    }
}

pub fn into_sha256_state(digest: &[u8]) -> [u32; 8] {
    let mut state: [u32; 8] = [0; 8];

    for (i, chunk) in digest.chunks_exact(4).enumerate() {
        state[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    state
}

#[test]
fn tampered_mac_computation_is_correct() {
    let original = "original_message";
    let extended = "extended_message";

    let mut hasher = Sha256::new();
    hasher.input(original);
    let hasher_state = into_sha256_state(&hasher.result_reset());

    let engine = LengthExtensionEngine::new(original, extended);
    let extended_message = engine.candidate_message(0);
    hasher.input(&extended_message);
    let extended_mac = hasher.result();

    let tampered_mac = engine.tampered_mac(&hasher_state, 0);
    assert_eq!(extended_mac.as_slice(), tampered_mac.as_slice());
}

#[test]
fn sha256_state_conversion_is_correct() {
    let digest = hex::decode("dc83f83e509a65d36e1dc2a5228df34539c60db474c966f99d7a16f28696b703").unwrap();
    let result = [
        3699636286,
        1352295891,
        1847444133,
        579728197,
        969280948,
        1959356153,
        2642024178,
        2258024195
    ];

    assert!(into_sha256_state(&digest) == result)
}

#[test]
fn candidate_message_is_well_formed() {
    let original = "ls -al";
    let extension = " && echo 'hello'";
    let secret_size = 13;

    let engine = LengthExtensionEngine::new(original, extension);
    let message = engine.candidate_message(secret_size);

    assert_eq!(&message[0..6], "ls -al".as_bytes());
    assert_eq!(message[6], 0x80);
    assert!(message[7..].iter().take(36).all(|v| *v == 0x00));
    assert_eq!(message[43..51], 152_u64.to_be_bytes());
    assert_eq!(&message[51..], extension.as_bytes());
}
