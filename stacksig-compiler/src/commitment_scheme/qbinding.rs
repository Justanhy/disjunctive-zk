//! Implementation of 1-of-2^q partially-binding vector commitment
//! from discrete log using halfbinding comitment schemes

use rand_core::CryptoRngCore;

use super::halfbinding::{HalfBinding, PublicParams};

pub struct QBinding;

impl QBinding {
    pub fn setup<R: CryptoRngCore>(
        rng: &mut R,
    ) -> (PublicParams, PublicParams) {
        let left = HalfBinding::setup(rng);
        let right = HalfBinding::setup(rng);
        (left, right)
    }
}
