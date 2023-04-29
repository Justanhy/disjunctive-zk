use std::fmt::Debug;

use curve25519_dalek::Scalar;
use group::ff::PrimeField;
use wrapped_ristretto::scalar::WrappedScalar;

/// A trait for types that can be split be Shamir's Secret
/// Sharing scheme
///
/// It is a trait that is implemented to map types to a
/// field element
pub trait Shareable: Default + Debug {
    type F: PrimeField;

    // Map the type to a prime field element
    fn share(&self) -> Self::F;

    // Derive the instance of the type from a field element
    fn derive(elem: Self::F) -> Self;

    // Convert field element into usize
    fn to_usize(elem: Self::F) -> usize;
}

impl Shareable for Scalar {
    type F = WrappedScalar;

    fn share(&self) -> Self::F {
        WrappedScalar(*self)
    }

    fn derive(elem: Self::F) -> Self {
        elem.0
    }

    fn to_usize(elem: Self::F) -> usize {
        usize::from_le_bytes(
            elem.to_bytes()[..8]
                .try_into()
                .unwrap(),
        )
    }
}
