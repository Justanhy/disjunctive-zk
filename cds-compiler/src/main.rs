extern crate curve25519_dalek;
extern crate rand_chacha;
extern crate rand_core;
extern crate schnorr;

use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use schnorr::Schnorr;

fn main() {
    let witness = Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
    let answer = Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
    let protocol = Schnorr::new(witness);
    println!("random scalar: {:?}", protocol.get_p_random());
    let commitment = protocol.commitment();
    println!("commitment: {:?}", commitment);
    let challenge = protocol.challenge();
    println!("challenge: {:?}", challenge);
    let proof = protocol.prove(challenge, answer);
    println!("proof: {:?}", proof);
    let result = protocol.verify(challenge, proof, commitment);
    println!("result: {:?}", result);
}
