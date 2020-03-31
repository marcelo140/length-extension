use hex::{self, FromHexError};
use sha2::{Sha256, Digest};

fn main() {
    let internal_state = [8;8];
    let mut hasher = Sha256::with_internal_state(&internal_state);
    hasher.input("Hello world");

    let digest = hasher.result();
    println!("Result: {:x}", digest);

}

fn digest_to_state(digest: &str) -> Result<[u32;8], FromHexError> {
    let mut state: [u32; 8] = [0; 8];

    for (i, chunk) in hex::decode(digest)?.chunks_exact(4).enumerate() {
        state[i] = u32::from(chunk[0]) << 24
            | u32::from(chunk[1]) << 16
            | u32::from(chunk[2]) << 8
            | u32::from(chunk[3]);
    }

    Ok(state)
}

#[test]
fn test_digest_to_state() {
    let hash = String::from("dc83f83e509a65d36e1dc2a5228df34539c60db474c966f99d7a16f28696b703");
    let result = [3699636286, 1352295891, 1847444133, 579728197, 969280948, 1959356153,
 2642024178, 2258024195];

    assert!(digest_to_state(&hash) == Ok(result))
}
