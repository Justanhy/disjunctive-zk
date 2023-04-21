use curve25519_dalek::ristretto::CompressedRistretto;

use crate::*;

/// Transcript for the Schnorr protocol
#[derive(Debug, Clone, Copy, Default)]
pub struct SchnorrTranscript {
    pub commitment: Option<CompressedRistretto>,
    pub challenge: Option<Scalar>,
    pub proof: Option<Scalar>,
}

/// Implementation of SigmaTranscript for SchnorrTranscript
impl SigmaTranscript for SchnorrTranscript {
    type MessageA = CompressedRistretto;
    type Challenge = Scalar;
    type MessageZ = Scalar;

    fn get_commitment(&self) -> Option<Self::MessageA> {
        self.commitment
    }

    fn get_challenge(&self) -> Option<Self::Challenge> {
        self.challenge
    }

    fn get_proof(&self) -> Option<Self::MessageZ> {
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

impl Challenge for Scalar {
    fn new(bytes: &[u8; 64]) -> Self {
        Scalar::from_bytes_mod_order_wide(bytes)
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
    type MessageA = CompressedRistretto;
    type Challenge = Scalar;
    type MessageZ = Scalar;

    fn first<R: CryptoRngCore>(
        _statement: &Schnorr,
        _witness: &Scalar,
        prover_rng: &mut R,
    ) -> (Self::State, Self::MessageA) {
        let state = Scalar::random(prover_rng);
        let message = &state * RISTRETTO_BASEPOINT_TABLE;
        (state, message.compress())
    }

    fn second<R: CryptoRngCore>(verifier_rng: &mut R) -> Self::Challenge {
        Scalar::random(verifier_rng)
    }

    fn third<R: CryptoRngCore>(
        _statement: &Schnorr,
        _state: Scalar,
        witness: &Scalar,
        challenge: &Scalar,
        prover_rng: &mut R,
    ) -> Self::MessageZ {
        // TODO: Allow use with state (remove re-computation)
        challenge * witness + Scalar::random(prover_rng)
    }

    fn verify(
        statement: &Schnorr,
        a: &CompressedRistretto,
        c: &Scalar,
        z: &Scalar,
    ) -> bool {
        RISTRETTO_BASEPOINT_TABLE * z - c * statement.pub_key
            == a.decompress()
                .unwrap()
    }
}
pub struct SimArgs {
    pub_key: RistrettoPoint,
    proof: Scalar,
    challenge: Scalar,
}

impl HVzk for Schnorr {
    fn simulate(
        statement: &Self::Statement,
    ) -> (Self::MessageA, Self::Challenge, Self::MessageZ) {
        let mut rng = ChaCha20Rng::from_entropy();
        let z = Scalar::random(&mut rng);
        let c = Scalar::random(&mut rng);
        let a =
            (RISTRETTO_BASEPOINT_TABLE * &z - c * statement.pub_key).compress();
        (a, c, z)
    }
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
        let commitment = Some(
            (RISTRETTO_BASEPOINT_TABLE * &proof - challenge * pub_key)
                .compress(),
        );
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
        challenge: &Self::Challenge,
        z: &Self::MessageZ,
    ) -> Self::MessageA {
        (RISTRETTO_BASEPOINT_TABLE * z - challenge * statement.pub_key)
            .compress()
    }
}

// impl Message for CompressedRistretto {
//     fn write<W: Write>(&self, writer: &mut W) {
//         writer
//             .write_all(self.as_bytes())
//             .unwrap();
//     }
// }

// impl Message for Scalar {
//     fn write<W: Write>(&self, writer: &mut W) {
//         writer
//             .write_all(self.as_bytes())
//             .unwrap();
//     }
// }

// impl Challenge for Scalar {
//     fn new(bytes: &[u8; 64]) -> Self {
//         Scalar::from_bytes_mod_order_wide(bytes)
//     }
// }

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
