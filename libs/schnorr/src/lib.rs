//! Defines traits related to Sigma Protocols and includes an implementation of
//! Schnorr's identification scheme implementing defined traits.
extern crate curve25519_dalek_ml as curve25519_dalek;
extern crate rand;
extern crate rand_chacha;
extern crate rand_core;
pub mod error;
pub mod sigma;

use curve25519_dalek::constants::{
    RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use error::Error;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use sigma::{SigmaProtocol, SigmaProver, SigmaTranscript, SigmaVerifier};

/// Transcript for the Schnorr protocol
#[derive(Debug, Clone, Copy, Default)]
pub struct SchnorrTranscript {
    pub commitment: Option<RistrettoPoint>,
    pub challenge: Option<Scalar>,
    pub proof: Option<Scalar>,
}

/// Implementation of SigmaTranscript for SchnorrTranscript
impl SigmaTranscript for SchnorrTranscript {
    type A = RistrettoPoint;
    type C = Scalar;
    type Z = Scalar;
    fn get_commitment(&self) -> Result<Self::A, Error> {
        self.commitment
            .ok_or(Error::UninitializedCommitment)
    }

    fn get_challenge(&self) -> Result<Self::C, Error> {
        self.challenge
            .ok_or(Error::UninitializedChallenge)
    }

    fn get_proof(&self) -> Result<Self::Z, Error> {
        self.proof
            .ok_or(Error::UninitializedProof)
    }
}

impl SchnorrTranscript {
    pub fn new() -> Self {
        SchnorrTranscript {
            commitment: None,
            challenge: None,
            proof: None,
        }
    }

    pub fn is_new(&self) -> bool {
        self.commitment == None && self.challenge == None && self.proof == None
    }

    pub fn is_commited(&self) -> bool {
        self.commitment != None
    }

    pub fn is_challenged(&self) -> bool {
        self.commitment != None && self.challenge != None
    }

    pub fn is_proven(&self) -> bool {
        self.commitment != None && self.challenge != None && self.proof != None
    }
}

#[derive(Debug, Clone)]
pub struct SchnorrProver {
    _provers_witness: Scalar,
    prover_rng: ChaCha20Rng,
    _transcript: SchnorrTranscript,
}

impl SchnorrProver {
    pub fn new(witness: &Scalar) -> Self {
        SchnorrProver {
            _provers_witness: witness.to_owned(),
            prover_rng: ChaCha20Rng::from_entropy(),
            _transcript: SchnorrTranscript::new(),
        }
    }
}

impl SigmaProver<ChaCha20Rng> for SchnorrProver {
    type Protocol = Schnorr;

    fn get_rng(&self) -> ChaCha20Rng {
        self.prover_rng
            .clone()
    }
}

#[derive(Debug, Clone)]
pub struct SchnorrVerifier {
    verifier_rng: ChaCha20Rng,
    _transcript: SchnorrTranscript,
}

impl SchnorrVerifier {
    pub fn new() -> Self {
        SchnorrVerifier {
            verifier_rng: ChaCha20Rng::from_entropy(),
            _transcript: SchnorrTranscript::new(),
        }
    }
}

impl SigmaVerifier<ChaCha20Rng> for SchnorrVerifier {
    type Protocol = Schnorr;

    fn get_rng(&self) -> ChaCha20Rng {
        self.verifier_rng
            .clone()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Schnorr {
    pub pub_key: RistrettoPoint,
}

impl SigmaProtocol for Schnorr {
    type Statement = Schnorr;
    type Witness = Scalar;

    type State = Scalar;
    type A = RistrettoPoint;
    type C = Scalar;
    type Z = Scalar;

    type ProverContext = ();

    fn first<R: CryptoRngCore>(
        _statement: &Schnorr,
        _witness: &Scalar,
        prover_rng: &mut R,
        _: &(),
    ) -> (Self::State, Self::A) {
        let state = Scalar::random(prover_rng);
        let message = &state * &RISTRETTO_BASEPOINT_TABLE;
        (state, message)
    }

    fn second<R: CryptoRngCore>(verifier_rng: &mut R) -> Self::C {
        Scalar::random(verifier_rng)
    }

    fn third<R: CryptoRngCore>(
        _statement: &Schnorr,
        _state: &Scalar,
        witness: &Scalar,
        challenge: &Scalar,
        prover_rng: &mut R,
        _: &(),
    ) -> Self::Z {
        // TODO: Allow use with state (remove re-computation)
        challenge * witness + Scalar::random(prover_rng)
    }

    fn simulate(
        statement: &Schnorr,
        challenge: &Scalar,
        z: &Scalar,
    ) -> Self::A {
        &RISTRETTO_BASEPOINT_TABLE * z - challenge * statement.pub_key
    }

    fn verify(
        statement: &Schnorr,
        a: &RistrettoPoint,
        c: &Scalar,
        z: &Scalar,
    ) -> bool {
        &RISTRETTO_BASEPOINT_TABLE * z - c * statement.pub_key == *a
    }
}

impl Schnorr {
    pub fn init(witness: Scalar) -> Self {
        Schnorr {
            pub_key: RISTRETTO_BASEPOINT_POINT * witness,
        }
    }

    pub fn simulator(self) -> SchnorrTranscript {
        let z = Scalar::random(&mut ChaCha20Rng::from_entropy());
        let c = Scalar::random(&mut ChaCha20Rng::from_entropy());
        let a = Schnorr::simulate(&self, &c, &z);
        SchnorrTranscript {
            commitment: Some(a),
            challenge: Some(c),
            proof: Some(z),
        }
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

        let prover = SchnorrProver::new(&provers_witness);
        let verifier = SchnorrVerifier::new();

        let (state, commitment) = Schnorr::first(
            &protocol,
            &provers_witness,
            &mut prover.get_rng(),
            &(),
        );

        let challenge = Schnorr::second(&mut verifier.get_rng());

        let proof = Schnorr::third(
            &protocol,
            &state,
            &provers_witness,
            &challenge,
            &mut prover.get_rng(),
            &(),
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

        let (state, commitment) = Schnorr::first(
            &protocol,
            &provers_witness,
            &mut prover.get_rng(),
            &(),
        );

        let challenge = Schnorr::second(&mut verifier.get_rng());

        let proof = Schnorr::third(
            &protocol,
            &state,
            &provers_witness,
            &challenge,
            &mut prover.get_rng(),
            &(),
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
