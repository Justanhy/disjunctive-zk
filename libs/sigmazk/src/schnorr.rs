use curve25519_dalek::digest::typenum::Zero;

use crate::*;

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

    fn get_commitment(&self) -> Option<Self::A> {
        self.commitment
    }

    fn get_challenge(&self) -> Option<Self::C> {
        self.challenge
    }

    fn get_proof(&self) -> Option<Self::Z> {
        self.proof
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

    // fn simulate(
    //     statement: &Schnorr,
    //     challenge: &Scalar,
    //     z: &Scalar,
    // ) -> Self::A {
    //     &RISTRETTO_BASEPOINT_TABLE * z - challenge * statement.pub_key
    // }

    fn verify(
        statement: &Schnorr,
        a: &RistrettoPoint,
        c: &Scalar,
        z: &Scalar,
    ) -> bool {
        &RISTRETTO_BASEPOINT_TABLE * z - c * statement.pub_key == *a
    }
}
pub struct SimArgs {
    pub_key: RistrettoPoint,
    proof: Scalar,
    challenge: Scalar,
}

/// Implementation of ZeroKnowledge for Schnorr
impl ZeroKnowledge for Schnorr {
    type Input = SimArgs;
    type Output = SchnorrTranscript;

    fn simulate(args: Self::Input) -> Self::Output {
        let SimArgs {
            pub_key,
            proof,
            challenge,
        } = args;
        let commitment =
            Some(&RISTRETTO_BASEPOINT_TABLE * &proof - challenge * pub_key);
        SchnorrTranscript {
            commitment,
            challenge: Some(challenge),
            proof: Some(proof),
        }
    }
}

/// Implementation of EHVzk trait for Schnorr
impl EHVzk for Schnorr {
    fn simulate(
        statement: &Self::Statement,
        challenge: &Self::C,
        z: &Self::Z,
    ) -> Self::A {
        &RISTRETTO_BASEPOINT_TABLE * z - challenge * statement.pub_key
    }
}

/// Implementation of Schnorr protocol
impl Schnorr {
    /// Initialize the Schnorr protocol with a witness
    pub fn init(witness: Scalar) -> Self {
        Schnorr {
            pub_key: RISTRETTO_BASEPOINT_POINT * witness,
        }
    }

    /// Default simulator for Schnorr protocol
    pub fn simulator(self) -> SchnorrTranscript {
        let z = Scalar::random(&mut ChaCha20Rng::from_entropy());
        let c = Scalar::random(&mut ChaCha20Rng::from_entropy());
        <Schnorr as ZeroKnowledge>::simulate(SimArgs {
            pub_key: self.pub_key,
            proof: z,
            challenge: c,
        })
    }
}
