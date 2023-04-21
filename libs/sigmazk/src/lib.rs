//! This crate defines traits related to Sigma Protocols and
//! includes an implementation of Schnorr's identification
//! scheme implementing said traits.
extern crate rand;
extern crate rand_chacha;
extern crate rand_core;
pub mod error;
pub mod schnorr;
pub mod sigma;
pub mod zk;

use curve25519_dalek::constants::{
    RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
pub use schnorr::*;
pub use sigma::*;
pub use zk::*;

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

        let prover = SchnorrProver::new(&provers_witness);
        let verifier = SchnorrVerifier::new();

        let (state, commitment) =
            Schnorr::first(&protocol, &provers_witness, &mut prover.get_rng());

        let challenge = Schnorr::second(&mut verifier.get_rng());

        let proof = Schnorr::third(
            &protocol,
            state,
            &provers_witness,
            &challenge,
            &mut prover.get_rng(),
        );

        let result =
            Schnorr::verify(&protocol, &commitment, &challenge, &proof);
        assert!(result);
    }

    #[test]
    fn schnorr_fails() {
        let actual_witness =
            Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let provers_witness =
            Scalar::random(&mut ChaCha20Rng::from_seed([1u8; 32]));

        let protocol = Schnorr::init(actual_witness);
        let prover = SchnorrProver::new(&provers_witness);
        let verifier = SchnorrVerifier::new();

        let (state, commitment) =
            Schnorr::first(&protocol, &provers_witness, &mut prover.get_rng());

        let challenge = Schnorr::second(&mut verifier.get_rng());

        let proof = Schnorr::third(
            &protocol,
            state,
            &provers_witness,
            &challenge,
            &mut prover.get_rng(),
        );

        let result =
            Schnorr::verify(&protocol, &commitment, &challenge, &proof);
        assert!(!result);
    }

    #[test]
    fn schnorr_simulator() {
        let witness = Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let protocol = Schnorr::init(witness);
        let transcript = protocol.simulator();
        let result = Schnorr::verify(
            &protocol,
            &transcript
                .commitment
                .expect("Commitment not found"),
            &transcript
                .challenge
                .expect("Challenge not found"),
            &transcript
                .proof
                .expect("Proof not found"),
        );
        assert!(result);
    }
}
