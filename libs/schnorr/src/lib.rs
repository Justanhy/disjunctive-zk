extern crate curve25519_dalek_ml as curve25519_dalek;
extern crate rand;
extern crate rand_chacha;
extern crate rand_core;

/// Re-export the error module
pub mod error;

use curve25519_dalek::constants::{
    RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
pub use error::Error;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};

/// Trait for the transcripts in Sigma protocols
/// A is the first message (the commitment of the Prover)
/// C is the challenge (sent by the Verifier)
/// Z is the proof (sent by the Prover which the Verifier uses to validate the prover)
/// These are generic types that the Sigma protocol concrete implementation will define
pub trait SigmaTranscript {
    type A; // Commitment (First round message)
    type C; // Challenge (Second round message)
    type Z; // Proof (Third round message)

    fn get_commitment(&self) -> Result<Self::A, Error>;

    fn get_challenge(&self) -> Result<Self::C, Error>;

    fn get_proof(&self) -> Result<Self::Z, Error>;
}

/// Trait for provers in Sigma protocols
pub trait SigmaProver<W, A, C, Z, R>
where
    R: CryptoRngCore,
{
    // type Transcript: SigmaTranscript;
    type Protocol: SigmaProtocol;

    fn get_rng(&self) -> R;
}

/// Trait for provers in Sigma protocols
pub trait SigmaVerifier<W, A, C, Z, R>
where
    R: CryptoRngCore,
{
    // type Transcript: SigmaTranscript;
    type Protocol: SigmaProtocol;

    fn get_rng(&self) -> R;
}

/// Trait for Sigma protocols
/// Transcript is the type of the transcript that the Sigma protocol will use
pub trait SigmaProtocol {
    type Statement; // Public key of the protocol
    type Witness; // Private key of the protocol
    type State; // State that generates commitment

    type A; // First round message
    type C; // Challenge
    type Z; // Third round message

    fn simulate(
        statement: &Self::Statement,
        challenge: &Self::C,
        z: &Self::Z,
    ) -> Self::A;

    fn a<R: CryptoRngCore>(
        statement: &Self::Statement,
        witness: &Self::Witness,
        prover_rng: &mut R,
    ) -> (Self::State, Self::A);

    fn challenge<R: CryptoRngCore>(verifier_rng: &mut R) -> Self::C;

    fn z<R: CryptoRngCore>(
        statement: &Self::Statement,
        state: &Self::State,
        witness: &Self::Witness,
        challenge: &Self::C,
        prover_rng: &mut R,
    ) -> Self::Z;

    fn verify(
        statement: &Self::Statement,
        a: &Self::A,
        c: &Self::C,
        z: &Self::Z,
    ) -> bool;
}

/// Transcript for the Schnorr protocol
#[derive(Debug, Clone, Copy)]
pub struct SchnorrTranscript {
    pub commitment: Option<RistrettoPoint>,
    pub challenge: Option<Scalar>,
    pub proof: Option<Scalar>,
}

/// Type aliases for Schnorr protocol
/// SW is the witness
type SW = Scalar;
/// SA is the commitment
type SA = Result<RistrettoPoint, Error>;
/// SC is the challenge
type SC = Result<Scalar, Error>;
/// SZ is the proof
type SZ = Result<Scalar, Error>;

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
    fn new() -> Self {
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
        self.commitment != None && self.challenge == None && self.proof == None
    }

    pub fn is_challenged(&self) -> bool {
        self.commitment != None && self.challenge != None && self.proof == None
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

impl SigmaProver<SW, SA, SC, SZ, ChaCha20Rng> for SchnorrProver {
    // type Transcript = SchnorrTranscript;
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

impl SigmaVerifier<SW, SA, SC, SZ, ChaCha20Rng> for SchnorrVerifier {
    // type Transcript = SchnorrTranscript;
    type Protocol = Schnorr;

    fn get_rng(&self) -> ChaCha20Rng {
        self.verifier_rng
            .clone()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Schnorr {
    pub pub_key: RistrettoPoint,
    transcript: SchnorrTranscript,
}

impl SigmaProtocol for Schnorr {
    type Statement = RistrettoPoint;
    type Witness = Scalar;
    type State = Scalar;

    type A = RistrettoPoint;
    type C = Scalar;
    type Z = Scalar;

    fn a<R: CryptoRngCore>(
        _statement: &RistrettoPoint,
        _witness: &Scalar,
        prover_rng: &mut R,
    ) -> (Self::State, Self::A) {
        let state = Scalar::random(prover_rng);
        let message = &state * &RISTRETTO_BASEPOINT_TABLE;
        (state, message)
    }

    fn challenge<R: CryptoRngCore>(verifier_rng: &mut R) -> Self::C {
        Scalar::random(verifier_rng)
    }

    fn z<R: CryptoRngCore>(
        _statement: &RistrettoPoint,
        state: &Scalar,
        witness: &Scalar,
        challenge: &Scalar,
        _prover_rng: &mut R,
    ) -> Self::Z {
        challenge * witness + state
    }

    fn simulate(
        statement: &RistrettoPoint,
        challenge: &Scalar,
        z: &Scalar,
    ) -> Self::A {
        &RISTRETTO_BASEPOINT_TABLE * z - challenge * statement
    }

    fn verify(
        statement: &RistrettoPoint,
        a: &RistrettoPoint,
        c: &Scalar,
        z: &Scalar,
    ) -> bool {
        &RISTRETTO_BASEPOINT_TABLE * z - c * statement == *a
    }
}

impl Schnorr {
    pub fn init(witness: SW) -> Self {
        let pub_key = RISTRETTO_BASEPOINT_POINT * witness;
        Schnorr {
            pub_key,
            transcript: SchnorrTranscript::new(),
        }
    }

    pub fn get_transcript(self) -> SchnorrTranscript {
        self.transcript
    }

    pub fn simulator(self) -> SchnorrTranscript {
        let z = Scalar::random(&mut ChaCha20Rng::from_entropy());
        let c = Scalar::random(&mut ChaCha20Rng::from_entropy());
        let a = Schnorr::simulate(&self.pub_key, &c, &z);
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

        let (state, commitment) = Schnorr::a(
            &protocol.pub_key,
            &provers_witness,
            &mut prover.get_rng(),
        );

        let challenge = Schnorr::challenge(&mut verifier.get_rng());

        let proof = Schnorr::z(
            &protocol.pub_key,
            &state,
            &provers_witness,
            &challenge,
            &mut prover.get_rng(),
        );

        let result =
            Schnorr::verify(&protocol.pub_key, &commitment, &challenge, &proof);
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

        let (state, commitment) = Schnorr::a(
            &protocol.pub_key,
            &provers_witness,
            &mut prover.get_rng(),
        );

        let challenge = Schnorr::challenge(&mut verifier.get_rng());

        let proof = Schnorr::z(
            &protocol.pub_key,
            &state,
            &provers_witness,
            &challenge,
            &mut prover.get_rng(),
        );

        let result =
            Schnorr::verify(&protocol.pub_key, &commitment, &challenge, &proof);
        assert!(!result);
    }

    #[test]
    fn schnorr_simulator() {
        let witness = Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let protocol = Schnorr::init(witness);
        let transcript = protocol.simulator();
        let result = Schnorr::verify(
            &protocol.pub_key,
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
