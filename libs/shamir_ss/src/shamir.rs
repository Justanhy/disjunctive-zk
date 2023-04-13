use core::ops::{AddAssign, Mul};

use group::ff::PrimeField;
use rand_core::CryptoRngCore;

use crate::lagrange::LagrangePolynomial;
use crate::shamir_error::ShamirError;

#[derive(Copy, Clone, Debug, Default)]
pub struct Share<F: PrimeField> {
    pub x: F,
    pub y: F,
}

impl<F: PrimeField> Share<F> {
    pub fn new(x: F, y: F) -> Self {
        Self { x, y }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ShamirSecretSharing {
    pub threshold: usize,
    pub shares: usize,
}

impl ShamirSecretSharing {
    pub fn split_secret<F, R>(
        &self,
        secret: F,
        rng: &mut R,
    ) -> Result<(LagrangePolynomial<F>, Vec<Share<F>>), ShamirError>
    where
        F: PrimeField,
        R: CryptoRngCore,
    {
        // Initialise x-coordinates to be 0, 1, 2, ..., size to
        // represent secret + participants in secret sharing
        let x_coordinates: Vec<F> = (0..self.threshold)
            .map(|i| F::from(i as u64))
            .collect();
        // Corresponding y-coordinates are their values with
        // intercept as secret
        let mut y_coordinates: Vec<F> = Vec::with_capacity(self.threshold);
        // Corresponding shares to each participant
        let mut shares: Vec<Share<F>> = Vec::with_capacity(self.threshold - 1);
        // Initialise y-intercept (secret)
        y_coordinates.push(secret);
        // To create random polynomial
        for i in 1..self.threshold {
            y_coordinates.push(F::random(&mut *rng));
            // Initialise shares for each x-coordinate from 1 to size
            shares.push(Share {
                x: x_coordinates[i],
                y: y_coordinates[i],
            })
        }
        Ok((
            LagrangePolynomial::init(x_coordinates, y_coordinates)?,
            shares,
        ))
    }

    pub fn complete_shares<F>(
        &self,
        secret: &F,
        shares: &Vec<Share<F>>,
        xs_to_fill: &Vec<F>,
    ) -> Result<Vec<Share<F>>, ShamirError>
    where
        F: PrimeField,
    {
        // Self::check_params(self.n, self.t,
        // Some(secret.to_owned()))?;

        if shares.len() != self.threshold - 1 {
            return Err(ShamirError::InvalidUnqualifiedSet);
        }

        let mut x_coordinates: Vec<F> = Vec::with_capacity(self.threshold);
        let mut y_coordinates = Vec::with_capacity(self.threshold);

        x_coordinates.push(F::ZERO);
        y_coordinates.push(*secret);

        for (i, share) in shares
            .iter()
            .enumerate()
        {
            let x = share.x;
            if x.is_zero()
                .into()
            {
                return Err(ShamirError::InvalidShare);
            }
            let y = share.y;

            x_coordinates.push(x);
            y_coordinates.push(y);
        }

        let poly = LagrangePolynomial::init(x_coordinates, y_coordinates)?;

        let challenges = xs_to_fill
            .iter()
            .map(|x| {
                let y = poly.interpolate(*x);
                Share { x: *x, y }
            })
            .collect();

        Ok(challenges)
    }

    /// Reconstructs secret from shares
    pub fn reconstruct_secret<F>(
        &self,
        shares: &Vec<Share<F>>,
    ) -> Result<F, ShamirError>
    where
        F: PrimeField,
        // S: Default + Copy + AddAssign + Mul<F, Output = S>,
    {
        if shares.len() < self.threshold {
            return Err(ShamirError::NotEnoughShares);
        }
        let (xs, ys): (Vec<F>, Vec<F>) = shares
            .iter()
            .map(|share| (share.x, share.y))
            .take(self.threshold)
            .unzip();
        Ok(LagrangePolynomial::lagrange_interpolation(
            &xs,
            &ys,
            F::ZERO,
        ))
    }

    /// Reconstructs secret with cached polynomial
    pub fn reconstruct_secret_fast<F>(
        &self,
        poly: LagrangePolynomial<F>,
    ) -> Result<F, ShamirError>
    where
        F: PrimeField,
    {
        Ok(poly.interpolate(F::ZERO))
    }
}
