//! Traits for Zero Knowledge
use crate::{SigmaProtocol, SigmaTranscript};

/// deprecated
pub trait ZeroKnowledge {
    type Input;
    type Output: SigmaTranscript;

    fn simulate(args: Self::Input) -> Self::Output;
}

pub trait HVzk: SigmaProtocol {
    fn simulate(
        statement: &Self::Statement,
    ) -> (Self::MessageA, Self::Challenge, Self::MessageZ);
}

/// Extended Honest-Verifier Zero Knowledge
pub trait EHVzk: SigmaProtocol {
    fn simulate(
        statement: &Self::Statement,
        challenge: &Self::Challenge,
        z: &Self::MessageZ,
    ) -> Self::MessageA;
}
