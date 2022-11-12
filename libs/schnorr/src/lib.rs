extern crate curve25519_dalek;
extern crate rand;
extern crate rand_chacha;
extern crate rand_core;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

pub trait SigmaProtocol {
    fn simulator(&self) -> Transcript;
}

pub struct Transcript {
    pub commitment: RistrettoPoint,
    pub challenge: Scalar,
    pub proof: Scalar,
}
// pub struct Verifier {}

// pub struct Prover {
//     witness: Scalar,
// }

// impl Prover {}

pub struct Schnorr {
    witness: Scalar,
    pub_key: RistrettoPoint,
    generator: RistrettoPoint,
    p_random: Scalar,
}

impl SigmaProtocol for Schnorr {
    fn simulator(&self) -> Transcript {
        let proof = Scalar::random(&mut ChaCha20Rng::from_entropy());
        let challenge = Scalar::random(&mut ChaCha20Rng::from_entropy());
        Transcript {
            commitment: self.generator * proof - challenge * self.pub_key,
            challenge,
            proof,
        }
    }
}

impl Schnorr {
    pub fn new(witness: Scalar) -> Self {
        Schnorr {
            pub_key: RISTRETTO_BASEPOINT_POINT * witness,
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

    pub fn prove(&self, challenge: &Scalar, provers_witness: &Scalar) -> Scalar {
        challenge * provers_witness + self.p_random
    }

    pub fn verify(&self, challenge: &Scalar, proof: &Scalar, commitment: &RistrettoPoint) -> bool {
        let lhs = self.generator * proof;
        let rhs = commitment + challenge * self.pub_key;
        lhs == rhs
    }

    pub fn get_p_random(&self) -> Scalar {
        self.p_random
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schnorr_works() {
        let actual_witness = Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let provers_witness = Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let protocol = Schnorr::new(actual_witness);
        let commitment = protocol.commitment();
        let challenge = protocol.challenge();
        let proof = protocol.prove(&challenge, &provers_witness);
        let result = protocol.verify(&challenge, &proof, &commitment);
        assert!(result);
    }

    #[test]
    fn schnorr_fails() {
        let actual_witness = Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let provers_witness = Scalar::random(&mut ChaCha20Rng::from_seed([1u8; 32]));
        let protocol = Schnorr::new(actual_witness);
        let commitment = protocol.commitment();
        let challenge = protocol.challenge();
        let proof = protocol.prove(&challenge, &provers_witness);
        let result = protocol.verify(&challenge, &proof, &commitment);
        assert!(!result);
    }

    #[test]
    fn schnorr_simulator() {
        let witness = Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let protocol = Schnorr::new(witness);
        let transcript = protocol.simulator();
        let result = protocol.verify(
            &transcript.challenge,
            &transcript.proof,
            &transcript.commitment,
        );
        assert!(result);
    }
}
