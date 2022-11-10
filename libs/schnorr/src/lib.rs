extern crate curve25519_dalek;
extern crate rand;
extern crate rand_chacha;
extern crate rand_core;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// pub struct Verifier {}

// pub struct Prover {
//     witness: Scalar,
// }

// impl Prover {}

pub struct Schnorr {
    witness: Scalar,
    generator: RistrettoPoint,
    p_random: Scalar,
}

impl Schnorr {
    pub fn new(witness: Scalar) -> Self {
        Schnorr {
            witness: witness,
            generator: RISTRETTO_BASEPOINT_POINT,
            p_random: Scalar::random(&mut ChaCha20Rng::from_entropy()),
        }
    }

    pub fn commitment(&self) -> RistrettoPoint {
        self.generator * self.p_random
    }

    pub fn challenge(&self) -> Scalar {
        Scalar::random(&mut ChaCha20Rng::from_entropy())
    }

    pub fn prove(&self, challenge: Scalar, answer: Scalar) -> Scalar {
        challenge * answer + self.p_random
    }

    pub fn verify(&self, challenge: Scalar, proof: Scalar, commitment: RistrettoPoint) -> bool {
        let lhs = self.generator * proof;
        let rhs = commitment + self.generator * challenge * self.witness;
        lhs == rhs
    }

    pub fn get_p_random(&self) -> Scalar {
        self.p_random
    }
}
