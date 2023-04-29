use crate::shamir_error::ShamirError;
use core::ops::{AddAssign, Mul};
use group::ff::PrimeField;
use rand_core::CryptoRngCore;

/// The polynomial used for generating the shares
#[derive(Clone, Debug)]
pub struct LagrangePolynomial<F: PrimeField> {
    x_coordinates: Vec<F>,
    y_coordinates: Vec<F>,
}

impl<F: PrimeField> LagrangePolynomial<F> {
    /// Initialise a random polynomial given only the
    /// y-intercept
    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn new<R: CryptoRngCore>(
        y_intercept: F,
        size: usize,
        rng: &mut R,
    ) -> Self {
        let x_coordinates: Vec<F> = (0..=size)
            .map(|i| F::from(i as u64))
            .collect();
        let mut y_coordinates: Vec<F> =
            Vec::with_capacity(size);
        y_coordinates.push(y_intercept);
        for _ in 1..=size {
            y_coordinates.push(F::random(&mut *rng));
        }
        Self {
            x_coordinates,
            y_coordinates,
        }
    }

    /// Initialise a polynomial with the given
    /// initialisation
    pub fn init(
        x_coordinates: Vec<F>,
        y_coordinates: Vec<F>,
    ) -> Result<Self, ShamirError> {
        if x_coordinates.len() != y_coordinates.len() {
            return Err(
                ShamirError::InvalidCoordinateSizes,
            );
        }
        Ok(Self {
            x_coordinates,
            y_coordinates,
        })
    }

    pub fn interpolate(&self, x: F) -> F {
        Self::lagrange_interpolation(
            &self.x_coordinates,
            &self.y_coordinates,
            x,
        )
    }

    /// Interpolate a polynomial using the given points
    pub fn lagrange_interpolation<S>(
        xs: &[F],
        ys: &[S],
        x: F,
    ) -> S
    where
        S: Default + Copy + AddAssign + Mul<F, Output = S>,
    {
        let limit = xs.len();
        let mut result = S::default();
        for i in 0..limit {
            let mut num = F::ONE;
            let mut denom = F::ONE;
            for j in 0..limit {
                if i == j {
                    continue;
                }
                num *= x - xs[j];
                denom *= xs[i] - xs[j];
            }
            result += ys[i]
                * num
                * denom
                    .invert()
                    .unwrap();
        }
        result
    }
}

#[cfg(test)]
mod polynomial_tests {
    use crate::lagrange::LagrangePolynomial;
    use curve25519_dalek::scalar::Scalar;
    use wrapped_ristretto::scalar::WrappedScalar;

    #[test]
    fn interpolate_works() {
        let xs = vec![
            WrappedScalar::from(1u64),
            WrappedScalar::from(2u64),
            WrappedScalar::from(5u64),
        ];

        let ys = vec![
            WrappedScalar::from(1u64),
            WrappedScalar::from(24u64),
            WrappedScalar(Scalar::from_bytes_mod_order([
                66, 211, 245, 92, 26, 99, 18, 88, 214, 156,
                247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
            ])),
        ];

        let poly =
            LagrangePolynomial::init(xs, ys).unwrap();

        let res =
            poly.interpolate(WrappedScalar::from(3u64));

        debug_assert_eq!(res, WrappedScalar::from(3u64));
    }
}
