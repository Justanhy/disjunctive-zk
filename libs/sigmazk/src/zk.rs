//! Traits for Zero Knowledge

use crate::SigmaProtocol;

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
