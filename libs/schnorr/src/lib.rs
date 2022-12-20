extern crate curve25519_dalek;
extern crate rand;
extern crate rand_chacha;
extern crate rand_core;

/// Re-export the error module
pub mod error;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
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
pub trait SigmaTranscript<A, C, Z> {
    fn get_commitment(&self) -> A;

    fn get_challenge(&self) -> C;

    fn get_proof(&self) -> Z;
}

/// Trait for provers in Sigma protocols
pub trait SigmaProver<W, A, C, Z, R>
where
    R: CryptoRngCore,
{
    type Transcript: SigmaTranscript<A, C, Z>;
    type Protocol: SigmaProtocol<W, A, C, Z>;

    fn get_rng(&self) -> R;
}

/// Trait for provers in Sigma protocols
pub trait SigmaVerifier<W, A, C, Z, R>
where
    R: CryptoRngCore,
{
    type Transcript: SigmaTranscript<A, C, Z>;
    type Protocol: SigmaProtocol<W, A, C, Z>;

    fn get_rng(&self) -> R;
}

/// Trait for Sigma protocols
/// Transcript is the type of the transcript that the Sigma protocol will use
pub trait SigmaProtocol<W, A, C, Z> {
    type Transcript: SigmaTranscript<A, C, Z>;

    fn simulator(&self) -> Self::Transcript;

    fn first_message<R: CryptoRngCore>(&mut self, prover_rng: &mut R) -> A;

    fn challenge<R: CryptoRngCore>(&mut self, verifier_rng: &mut R) -> C;

    fn second_message<R: CryptoRngCore>(
        &mut self,
        witness: &W,
        challenge: C,
        prover_rng: &mut R,
    ) -> Z;

    fn verify(&self, transcript: Self::Transcript) -> bool;

    fn init(witness: W) -> Self;
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
impl SigmaTranscript<SA, SC, SZ> for SchnorrTranscript {
    fn get_commitment(&self) -> SA {
        match self.commitment {
            Some(a) => Ok(a),
            None => Err(Error::UninitializedCommitment),
        }
    }

    fn get_challenge(&self) -> SC {
        match self.challenge {
            Some(c) => Ok(c),
            None => Err(Error::UninitializedChallenge),
        }
    }

    fn get_proof(&self) -> SZ {
        match self.proof {
            Some(z) => Ok(z),
            None => Err(Error::UninitializedProof),
        }
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

    fn is_new(&self) -> bool {
        self.commitment == None && self.challenge == None && self.proof == None
    }

    fn is_commited(&self) -> bool {
        self.commitment != None && self.challenge == None && self.proof == None
    }

    fn is_challenged(&self) -> bool {
        self.commitment != None && self.challenge != None && self.proof == None
    }

    fn is_proven(&self) -> bool {
        self.commitment != None && self.challenge != None && self.proof != None
    }
}

#[derive(Debug, Clone)]
pub struct SchnorrProver {
    provers_witness: Scalar,
    prover_rng: ChaCha20Rng,
    transcript: SchnorrTranscript,
}

impl SchnorrProver {
    pub fn new(witness: &Scalar) -> Self {
        SchnorrProver {
            provers_witness: witness.to_owned(),
            prover_rng: ChaCha20Rng::from_entropy(),
            transcript: SchnorrTranscript::new(),
        }
    }
}

impl SigmaProver<SW, SA, SC, SZ, ChaCha20Rng> for SchnorrProver {
    type Transcript = SchnorrTranscript;
    type Protocol = Schnorr;

    fn get_rng(&self) -> ChaCha20Rng {
        self.prover_rng
            .clone()
    }
}

#[derive(Debug, Clone)]
pub struct SchnorrVerifier {
    pub_key: RistrettoPoint,
    verifier_rng: ChaCha20Rng,
    transcript: SchnorrTranscript,
}

impl SchnorrVerifier {
    pub fn new(pub_key: RistrettoPoint) -> Self {
        SchnorrVerifier {
            pub_key,
            verifier_rng: ChaCha20Rng::from_entropy(),
            transcript: SchnorrTranscript::new(),
        }
    }
}

impl SigmaVerifier<SW, SA, SC, SZ, ChaCha20Rng> for SchnorrVerifier {
    type Transcript = SchnorrTranscript;
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

impl SigmaProtocol<SW, SA, SC, SZ> for Schnorr {
    type Transcript = SchnorrTranscript;

    fn simulator(&self) -> SchnorrTranscript {
        let proof = Scalar::random(&mut ChaCha20Rng::from_entropy());
        let challenge = Scalar::random(&mut ChaCha20Rng::from_entropy());
        SchnorrTranscript {
            commitment: Some(
                RISTRETTO_BASEPOINT_POINT * proof - challenge * self.pub_key,
            ),
            challenge: Some(challenge),
            proof: Some(proof),
        }
    }

    /// Method used by the prover to generate the first message of the Sigma protocol
    /// The prover provides their rng to generate the random commitment
    fn first_message<R: CryptoRngCore>(&mut self, prover_rng: &mut R) -> SA {
        self.transcript
            .commitment =
            Some(RISTRETTO_BASEPOINT_POINT * Scalar::random(prover_rng));

        // Check that the state of the transcript is appropriate
        let commitment = match self
            .transcript
            .is_commited()
        {
            true => self
                .transcript
                .get_commitment(),
            false => Err(Error::InvalidTranscriptState),
        };

        commitment
    }

    /// Method used by the verifier to generate the challenge of the Sigma protocol
    /// The verifier provides their rng to generate the random challenge
    fn challenge<R: CryptoRngCore>(&mut self, verifier_rng: &mut R) -> SC {
        self.transcript
            .challenge = Some(Scalar::random(verifier_rng));

        // Check that state of the transcript is correct
        let challenge = match self
            .transcript
            .is_challenged()
        {
            true => self
                .transcript
                .get_challenge(),
            false => Err(Error::InvalidTranscriptState),
        };

        challenge
    }

    /// Method used by the prover to generate the second message of the Sigma protocol
    ///
    /// `provers_witness`: the witness they believe to be the solution to the statement
    /// `provers_challenge`: the challenge they believe to have received from the Verifier
    /// `prover_rng`: the prover provides their rng
    ///
    fn second_message<R: CryptoRngCore>(
        &mut self,
        provers_witness: &SW,
        provers_challenge: SC,
        prover_rng: &mut R,
    ) -> SZ {
        let challenge = match self
            .transcript
            .get_challenge()?
            == provers_challenge?
        {
            true => self
                .transcript
                .get_challenge(),
            false => Err(Error::ChallengeMismatch),
        };

        self.transcript
            .proof =
            Some(challenge? * provers_witness + Scalar::random(prover_rng));

        let proof = match self
            .transcript
            .is_proven()
        {
            true => self
                .transcript
                .get_proof(),
            false => Err(Error::InvalidTranscriptState),
        };

        proof
    }

    fn verify(&self, transcript: SchnorrTranscript) -> bool {
        // TODO: Refactor to mitigate timing attacks
        let challenge = match transcript.get_challenge() {
            Ok(c) => c,
            Err(_) => return false,
        };

        let proof = match transcript.get_proof() {
            Ok(z) => z,
            Err(_) => return false,
        };

        let commitment = match transcript.get_commitment() {
            Ok(a) => a,
            Err(_) => return false,
        };

        let lhs = RISTRETTO_BASEPOINT_POINT * proof;
        let rhs = commitment + challenge * self.pub_key;
        lhs == rhs
    }

    fn init(witness: SW) -> Self {
        let pub_key = RISTRETTO_BASEPOINT_POINT * witness;
        Schnorr {
            pub_key,
            transcript: SchnorrTranscript::new(),
        }
    }
}

impl Schnorr {
    pub fn get_transcript(self) -> SchnorrTranscript {
        self.transcript
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

        let mut protocol = Schnorr::init(actual_witness);

        let prover_rng = ChaCha20Rng::from_entropy();
        let verifier_rng = ChaCha20Rng::from_entropy();

        let commitment = protocol
            .first_message(&mut prover_rng.clone())
            .unwrap();

        let challenge =
            SigmaProtocol::challenge(&mut protocol, &mut verifier_rng.clone())
                .unwrap();

        let proof = protocol
            .second_message(
                &provers_witness,
                Ok(challenge),
                &mut prover_rng.clone(),
            )
            .unwrap();

        let result = SigmaProtocol::verify(
            &protocol,
            SchnorrTranscript {
                commitment: Some(commitment),
                challenge: Some(challenge),
                proof: Some(proof),
            },
        );
        assert!(result);
    }

    #[test]
    fn schnorr_fails() {
        let actual_witness =
            Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let provers_witness =
            Scalar::random(&mut ChaCha20Rng::from_seed([1u8; 32]));

        let mut protocol = Schnorr::init(actual_witness);
        let prover = SchnorrProver::new(&provers_witness);
        let verifier = SchnorrVerifier::new(protocol.pub_key);

        let _commitment = protocol.first_message(&mut prover.get_rng());
        let challenge = protocol.challenge(&mut verifier.get_rng());
        let _proof = protocol.second_message(
            &provers_witness,
            challenge,
            &mut prover.get_rng(),
        );
        let transcript = protocol.get_transcript();
        let result = protocol.verify(transcript);
        assert!(!result);
    }

    #[test]
    fn schnorr_simulator() {
        let witness = Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
        let protocol = Schnorr::init(witness);
        let transcript = protocol.simulator();
        let result = protocol.verify(transcript);
        assert!(result);
    }
}
