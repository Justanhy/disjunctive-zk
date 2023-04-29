//! This crate defines traits related to Sigma Protocols and
//! includes an implementation of Schnorr's identification
//! scheme implementing said traits.
extern crate rand;
extern crate rand_chacha;
extern crate rand_core;
pub mod error;
pub mod message;
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
        let actual_witness = Scalar::random(
            &mut ChaCha20Rng::from_seed([0u8; 32]),
        );
        let provers_witness = Scalar::random(
            &mut ChaCha20Rng::from_seed([0u8; 32]),
        );

        let provers_rng =
            &mut ChaCha20Rng::from_seed([2u8; 32]);

        let verifiers_rng =
            &mut ChaCha20Rng::from_seed([3u8; 32]);

        let protocol = Schnorr::init(actual_witness);

        let (state, commitment) = Schnorr::first(
            &protocol,
            &provers_witness,
            provers_rng,
        );

        let challenge = Schnorr::second(verifiers_rng);

        let proof = Schnorr::third(
            &protocol,
            state,
            &provers_witness,
            &challenge,
            provers_rng,
        );

        let result = Schnorr::verify(
            &protocol,
            &commitment,
            &challenge,
            &proof,
        );
        assert!(result);
    }

    #[test]
    fn schnorr_fails() {
        let actual_witness = Scalar::random(
            &mut ChaCha20Rng::from_seed([0u8; 32]),
        );
        let provers_witness = Scalar::random(
            &mut ChaCha20Rng::from_seed([1u8; 32]),
        );

        let provers_rng =
            &mut ChaCha20Rng::from_seed([2u8; 32]);
        let verifiers_rng =
            &mut ChaCha20Rng::from_seed([3u8; 32]);

        let protocol = Schnorr::init(actual_witness);

        let (state, commitment) = Schnorr::first(
            &protocol,
            &provers_witness,
            provers_rng,
        );

        let challenge = Schnorr::second(verifiers_rng);

        let proof = Schnorr::third(
            &protocol,
            state,
            &provers_witness,
            &challenge,
            provers_rng,
        );

        let result = Schnorr::verify(
            &protocol,
            &commitment,
            &challenge,
            &proof,
        );
        assert!(!result);
    }

    #[test]
    fn schnorr_simulator() {
        let witness = Scalar::random(
            &mut ChaCha20Rng::from_seed([0u8; 32]),
        );
        let protocol = Schnorr::init(witness);
        let (a, c, z) =
            <Schnorr as HVzk>::simulate(&protocol);
        let result = Schnorr::verify(&protocol, &a, &c, &z);
        assert!(result);
    }
}
