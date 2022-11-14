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
    fn with_simulator<T>(
        &self,
        sim: fn(T) -> (Scalar, Scalar),
        args: T,
    ) -> Transcript;
    fn init(witness: Scalar) -> Self;
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
    initialised: bool,
    pub pub_key: RistrettoPoint,
    p_random: Scalar,
}

impl SigmaProtocol for Schnorr {
    fn simulator(&self) -> Transcript {
        let proof = Scalar::random(&mut ChaCha20Rng::from_entropy());
        let challenge = Scalar::random(&mut ChaCha20Rng::from_entropy());
        Transcript {
            commitment: RISTRETTO_BASEPOINT_POINT * proof
                - challenge * self.pub_key,
            challenge,
            proof,
        }
    }

    fn with_simulator<T>(
        &self,
        sim: fn(T) -> (Scalar, Scalar),
        args: T,
    ) -> Transcript {
        let (challenge, proof) = sim(args);
        Transcript {
            commitment: RISTRETTO_BASEPOINT_POINT * proof
                - challenge * self.pub_key,
            challenge,
            proof,
        }
    }

    fn init(witness: Scalar) -> Self {
        Schnorr {
            initialised: true,
            pub_key: RISTRETTO_BASEPOINT_POINT * witness,
            p_random: Scalar::random(&mut ChaCha20Rng::from_entropy()),
        }
    }
}

impl Schnorr {
    pub fn new() -> Self {
        Schnorr {
            initialised: false,
            pub_key: RistrettoPoint::default(),
            p_random: Scalar::default(),
        }
    }

    pub fn commitment(&self) -> RistrettoPoint {
        assert!(self.initialised);
        RISTRETTO_BASEPOINT_POINT * self.p_random
    }

    pub fn challenge(&self) -> Scalar {
        assert!(self.initialised);
        Scalar::random(&mut ChaCha20Rng::from_entropy())
    }

    pub fn prove(
        &self,
        challenge: &Scalar,
        provers_witness: &Scalar,
    ) -> Scalar {
        assert!(self.initialised);
        challenge * provers_witness + self.p_random
    }

    pub fn verify(
        &self,
        commitment: &RistrettoPoint,
        challenge: &Scalar,
        proof: &Scalar,
    ) -> bool {
        assert!(self.initialised);
        let lhs = RISTRETTO_BASEPOINT_POINT * proof;
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
        let actual_witness =
            Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let provers_witness =
            Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let protocol = Schnorr::init(actual_witness);
        let commitment = protocol.commitment();
        let challenge = protocol.challenge();
        let proof = protocol.prove(&challenge, &provers_witness);
        let result = protocol.verify(&commitment, &challenge, &proof);
        assert!(result);
    }

    #[test]
    fn schnorr_fails() {
        let actual_witness =
            Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let provers_witness =
            Scalar::random(&mut ChaCha20Rng::from_seed([1u8; 32]));
        let protocol = Schnorr::init(actual_witness);
        let commitment = protocol.commitment();
        let challenge = protocol.challenge();
        let proof = protocol.prove(&challenge, &provers_witness);
        let result = protocol.verify(&commitment, &challenge, &proof);
        assert!(!result);
    }

    #[test]
    fn schnorr_simulator() {
        let witness = Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let protocol = Schnorr::init(witness);
        let transcript = protocol.simulator();
        let result = protocol.verify(
            &transcript.commitment,
            &transcript.challenge,
            &transcript.proof,
        );
        assert!(result);
    }

    #[test]
    fn uninitialized_schnorr() {
        let protocol = Schnorr::new();
        let result = std::panic::catch_unwind(|| protocol.commitment());
        assert!(result.is_err());
    }
}
