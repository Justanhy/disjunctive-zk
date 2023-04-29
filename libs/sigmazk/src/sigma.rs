//! This module defines traits related to Sigma protocols

use rand_core::CryptoRngCore;

pub trait Challenge {
    fn new(bytes: &[u8; 64]) -> Self;
}

/// Trait for Sigma protocols
///
/// This trait defines the methods that a general sigma
/// protocol should have
pub trait SigmaProtocol {
    /// Public information of the protocol
    type Statement;
    /// Private information of the protocol. Should only be
    /// known by the Prover
    type Witness;

    /// First round message
    type MessageA: Clone;
    /// Challenge (Second round message)
    type Challenge: Clone + Challenge;
    /// Third round message
    type MessageZ: Clone;

    /// On every protocol execution (i.e. interaction
    /// between the prover and the verifier) there is a
    /// particular *state* for that execution. This *state*
    /// contains contextual information for the protocol
    /// that may be used (usually by the prover in the third
    /// round).
    type State: Clone;

    /// The first message in a Sigma protocol (sent by the
    /// Prover).
    fn first<R: CryptoRngCore + Clone>(
        statement: &Self::Statement,
        witness: &Self::Witness,
        prover_rng: &mut R,
    ) -> (Self::State, Self::MessageA)
    where
        Self: Sized;

    /// The second message in a Sigma protocol (sent by the
    /// Verifier).
    ///
    /// Usually, this is a challenge sent by the Verifier to
    /// the Prover.
    fn second<R: CryptoRngCore + Clone>(
        verifier_rng: &mut R,
    ) -> Self::Challenge
    where
        Self: Sized;

    /// The third message in a Sigma protocol (sent by the
    /// Prover).
    fn third<R: CryptoRngCore + Clone>(
        statement: &Self::Statement,
        state: Self::State,
        witness: &Self::Witness,
        challenge: &Self::Challenge,
        prover_rng: &mut R,
    ) -> Self::MessageZ
    where
        Self: Sized;

    /// The verification method used by the Verifier
    ///
    /// **Parameters**
    /// - `statement` contextual information about the
    ///   statement to prove
    /// - `a` the first message, sent by the prover
    /// - `c` the second message, sent by the verifier
    /// - `z` the third message, sent by the prover
    ///
    /// Given these parameters, the verifier can verify if
    /// the conversation/transcript between the verifier
    /// and prover is consistent with the statement.
    ///
    /// **Returns**
    /// - `true` if the transcript is consistent with the
    ///   statement
    /// - `false` otherwise
    fn verify(
        statement: &Self::Statement,
        a: &Self::MessageA,
        c: &Self::Challenge,
        z: &Self::MessageZ,
    ) -> bool
    where
        Self: Sized;
}
