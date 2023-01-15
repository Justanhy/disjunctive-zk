//! Traits for Zero Knowledge
use crate::{SigmaProtocol, SigmaTranscript};

pub trait ZeroKnowledge {
    type Input;
    type Output: SigmaTranscript;

    fn simulate(args: Self::Input) -> Self::Output;
}

/// Extended Honest-Verifier Zero Knowledge
pub trait EHVzk: SigmaProtocol {
    fn simulate(
        statement: &Self::Statement,
        challenge: &Self::C,
        z: &Self::Z,
    ) -> Self::A;
}
