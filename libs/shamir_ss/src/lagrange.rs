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
    pub fn new<R: CryptoRngCore>(
        y_intercept: F,
        size: usize,
        rng: &mut R,
    ) -> Self {
        let x_coordinates: Vec<F> = (0..=size)
            .map(|i| F::from(i as u64))
            .collect();
        let mut y_coordinates: Vec<F> = Vec::with_capacity(size);
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
            return Err(ShamirError::InvalidCoordinateSizes);
        }
        Ok(Self {
            x_coordinates,
            y_coordinates,
        })
    }

    /// Initialise a polynomial with the given
    /// initialisation, filling in missing y coordinates
    pub fn filling_init<R>(
        x_coordinates: Vec<F>,
        y_coordinates: Vec<Option<F>>,
        rng: &mut R,
    ) -> Result<Self, ShamirError>
    where
        R: CryptoRngCore,
    {
        let mut ys = vec![F::default(); y_coordinates.len()];
        for (i, c) in ys
            .iter_mut()
            .enumerate()
        {
            match y_coordinates[i] {
                Some(v) => *c = v,
                None => *c = F::random(&mut *rng),
            }
        }
        Self::init(x_coordinates, ys)
    }

    pub fn interpolate(&self, x: F) -> F {
        Self::lagrange_interpolation(
            &self.x_coordinates,
            &self.y_coordinates,
            x,
        )
    }

    /// Interpolate a polynomial using the given points
    pub fn lagrange_interpolation<S>(xs: &[F], ys: &[S], x: F) -> S
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
