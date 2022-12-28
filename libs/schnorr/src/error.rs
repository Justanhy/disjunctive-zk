/// Errors for Schnorr's protocol
#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// Transcript commitment is not initialized
    UninitializedCommitment,
    /// Transcript challenge is not initialized
    UninitializedChallenge,
    /// Failed to initialize challenge
    FailedInitOfChallenge,
    /// Transcript proof is not initialized
    UninitializedProof,
    /// Schnorr protocol is not initialized
    /// (i.e. public key is not initialized)
    UninitializedSchnorr,
    /// When a method that should not be called on the current transcript state is called
    /// e.g. SigmaProtocol::second_message() is called when transcript is new.
    InvalidTranscriptState,
    /// When the challenge provided by the prover doesn't match the challenge remembered by the protocol.
    /// Indicates that the prover might have called the method on the wrong instance of the protocol
    /// or the prover is not saving the challenge appropriately.
    ChallengeMismatch,
}
