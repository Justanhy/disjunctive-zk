//! This module defines shared traits for Sigma protocols

use crate::*;

/// Trait for Sigma protocols
///
/// This trait defines the methods that a general sigma protocol should have
pub trait SigmaProtocol {
    /// Public key of the protocol
    type Statement;
    /// Private key of the protocol
    type Witness;

    /// The state that generates the commitment
    type State;
    /// First round message
    type A;
    /// Challenge (Second round message)
    type C;
    /// Third round message
    type Z;

    /// Information that is provided by the prover for the protocol.
    type ProverContext;

    fn simulate(
        statement: &Self::Statement,
        challenge: &Self::C,
        z: &Self::Z,
    ) -> Self::A;

    /// The first message in a Sigma protocol (sent by the Prover).
    fn first<R: CryptoRngCore>(
        statement: &Self::Statement,
        witness: &Self::Witness,
        prover_rng: &mut R,
        prover_context: &Self::ProverContext,
    ) -> (Self::State, Self::A);

    /// The second message in a Sigma protocol (sent by the Verifier).
    ///
    /// Usually, this is a challenge sent by the Verifier to the Prover.
    fn second<R: CryptoRngCore>(verifier_rng: &mut R) -> Self::C;

    /// The third message in a Sigma protocol (sent by the Prover).
    fn third<R: CryptoRngCore>(
        statement: &Self::Statement,
        state: &Self::State,
        witness: &Self::Witness,
        challenge: &Self::C,
        prover_rng: &mut R,
        prover_context: &Self::ProverContext,
    ) -> Self::Z;

    /// The verification method used by the Verifier
    ///
    /// **Parameters**
    /// - `statement` contextual information about the statement to prove
    /// - `a` the first message, sent by the prover
    /// - `c` the second message, sent by the verifier
    /// - `z` the third message, sent by the prover
    ///
    /// Given these parameters, the verifier can verify if the conversation/transcript
    /// between the verifier and prover is consistent with the statement.
    ///
    /// **Returns**
    /// - `true` if the transcript is consistent with the statement
    /// - `false` otherwise
    fn verify(
        statement: &Self::Statement,
        a: &Self::A,
        c: &Self::C,
        z: &Self::Z,
    ) -> bool;
}

/// Trait for the transcripts in Sigma protocols
///
/// **Trait Types**
/// - `A` Type of the first message (the commitment of the Prover)
/// - `C` Type of the second message (sent by the Verifier)
/// - `Z` Type of the third message (sent by the Prover which the Verifier uses to validate the prover)
///
/// These are generic types that the Sigma protocol concrete implementation will define
pub trait SigmaTranscript {
    /// Commitment (First round message)
    type A;
    /// Challenge (Second round message)
    type C;
    /// Proof (Third round message)
    type Z;

    fn get_commitment(&self) -> Option<Self::A>;

    fn get_challenge(&self) -> Option<Self::C>;

    fn get_proof(&self) -> Option<Self::Z>;

    fn is_new(&self) -> bool {
        self.get_commitment()
            .is_none()
            && self
                .get_challenge()
                .is_none()
            && self
                .get_proof()
                .is_none()
    }

    fn is_commited(&self) -> bool {
        self.get_commitment()
            .is_some()
    }

    fn is_challenged(&self) -> bool {
        self.is_commited()
            && self
                .get_challenge()
                .is_some()
    }

    fn is_proven(&self) -> bool {
        self.is_challenged()
            && self
                .get_proof()
                .is_some()
    }
}

/// Trait for provers in Sigma protocols
pub trait SigmaProver<R>
where
    R: CryptoRngCore,
{
    type Protocol: SigmaProtocol;

    fn get_rng(&self) -> R;
}

/// Trait for verifiers in Sigma protocols
pub trait SigmaVerifier<R>
where
    R: CryptoRngCore,
{
    type Protocol: SigmaProtocol;

    fn get_rng(&self) -> R;
}
