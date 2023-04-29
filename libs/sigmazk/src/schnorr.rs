use curve25519_dalek::ristretto::CompressedRistretto;

use crate::*;

impl Challenge for Scalar {
    fn new(bytes: &[u8; 64]) -> Self {
        Scalar::from_bytes_mod_order_wide(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Schnorr {
    pub pub_key: RistrettoPoint,
}

/// Sigma protocol implementation for Schnorr
impl SigmaProtocol for Schnorr {
    type Statement = Schnorr;
    type Witness = Scalar;

    type State = Scalar;
    type MessageA = CompressedRistretto;
    type Challenge = Scalar;
    type MessageZ = Scalar;

    /// First round of Schnorr's protocol
    fn first<R: CryptoRngCore>(
        _statement: &Schnorr,
        _witness: &Scalar,
        prover_rng: &mut R,
    ) -> (Self::State, Self::MessageA) {
        // Get trapdoor
        let state = Scalar::random(prover_rng);
        // Get group element (point on the curve)
        let message = &state * RISTRETTO_BASEPOINT_TABLE;

        (state, message.compress())
    }

    /// Second round of Schnorr's protocol. Random challenge.
    fn second<R: CryptoRngCore>(
        verifier_rng: &mut R,
    ) -> Self::Challenge {
        Scalar::random(verifier_rng)
    }

    /// Third round of Schnorr's protocol
    fn third<R: CryptoRngCore>(
        _statement: &Schnorr,
        state: Scalar,
        witness: &Scalar,
        challenge: &Scalar,
        _prover_rng: &mut R,
    ) -> Self::MessageZ {
        // z = r + cx
        challenge * witness + state
    }

    /// Verification of transcript algorithm
    fn verify(
        statement: &Schnorr,
        a: &CompressedRistretto,
        c: &Scalar,
        z: &Scalar,
    ) -> bool {
        // G * z  =?= a + c * H => G * z - c * H =?= a
        RISTRETTO_BASEPOINT_TABLE * z
            - c * statement.pub_key
            == a.decompress()
                .unwrap()
    }
}

impl HVzk for Schnorr {
    fn simulate(
        statement: &Self::Statement,
    ) -> (Self::MessageA, Self::Challenge, Self::MessageZ)
    {
        let mut rng = ChaCha20Rng::from_entropy();
        let z = Scalar::random(&mut rng);
        let c = Scalar::random(&mut rng);
        let a = (RISTRETTO_BASEPOINT_TABLE * &z
            - c * statement.pub_key)
            .compress();
        (a, c, z)
    }
}

/// Implementation of EHVzk trait for Schnorr
impl EHVzk for Schnorr {
    fn simulate(
        statement: &Self::Statement,
        challenge: &Self::Challenge,
        z: &Self::MessageZ,
    ) -> Self::MessageA {
        (RISTRETTO_BASEPOINT_TABLE * z
            - challenge * statement.pub_key)
            .compress()
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
}
