use core::ops::{AddAssign, Mul};

use group::ff::PrimeField;
use rand::seq::IteratorRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
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

    pub fn complete_shares_mut<F>(
        &self,
        secret: &F,
        unqualified_shares: &mut Vec<Share<F>>,
        remaining_xs: &mut Vec<F>,
    ) -> Result<(), ShamirError>
    where
        F: PrimeField,
    {
        if unqualified_shares.len() != self.threshold - 1 {
            return Err(ShamirError::InvalidUnqualifiedSet);
        }

        let mut x_coordinates: Vec<F> = Vec::with_capacity(self.threshold);
        let mut y_coordinates: Vec<F> = Vec::with_capacity(self.threshold);

        x_coordinates.push(F::ZERO);
        y_coordinates.push(*secret);

        // Extract x and y coordinates from each share in
        // unqualified set
        for share in unqualified_shares.iter() {
            let x = share.x;
            // Check if x-coordinate is 0
            if x.is_zero()
                .into()
            {
                return Err(ShamirError::InvalidShare);
            }
            let y = share.y;
            // Add x and y coordinates to their respective vectors
            x_coordinates.push(x);
            y_coordinates.push(y);
        }

        // Create polynomial with x and y coordinates
        let poly = LagrangePolynomial::init(x_coordinates, y_coordinates)?;

        // Iterate through each x-coordinate in remaining set and
        // interpolate at each point
        // Interpolation is a O(n^2) operation where n = size of
        // threshold = total - active + 1 This outer loop
        // goes through remaining_xs which is of size = active
        // So, total complexity is O(n^2 * active)
        unqualified_shares
            .resize(self.threshold + remaining_xs.len() - 1, Share::default());

        for (i, x) in remaining_xs
            .iter()
            .enumerate()
        {
            let y = poly.interpolate(*x);
            unqualified_shares[i] = Share { x: *x, y };
        }

        Ok(())
    }

    pub fn complete_shares<F>(
        &self,
        secret: &F,
        unqualified_shares: &Vec<Share<F>>,
        remaining_xs: &Vec<F>,
    ) -> Result<Vec<Share<F>>, ShamirError>
    where
        F: PrimeField,
    {
        if unqualified_shares.len() != self.threshold - 1 {
            return Err(ShamirError::InvalidUnqualifiedSet);
        }

        let mut x_coordinates: Vec<F> = Vec::with_capacity(self.threshold);
        let mut y_coordinates: Vec<F> = Vec::with_capacity(self.threshold);

        x_coordinates.push(F::ZERO);
        y_coordinates.push(*secret);

        // Extract x and y coordinates from each share in
        // unqualified set
        for share in unqualified_shares.iter() {
            let x = share.x;
            // Check if x-coordinate is 0
            if x.is_zero()
                .into()
            {
                return Err(ShamirError::InvalidShare);
            }
            let y = share.y;
            // Add x and y coordinates to their respective vectors
            x_coordinates.push(x);
            y_coordinates.push(y);
        }

        // Create polynomial with x and y coordinates
        let poly = LagrangePolynomial::init(x_coordinates, y_coordinates)?;

        // Iterate through each x-coordinate in remaining set and
        // interpolate at each point
        // Interpolation is a O(n^2) operation where n = size of
        // threshold = total - active + 1 This outer loop
        // goes through remaining_xs which is of size = active
        // So, total complexity is O(n^2 * active)
        let remaining_shares = remaining_xs
            .iter()
            .map(|x| {
                let y = poly.interpolate(*x);
                Share { x: *x, y }
            })
            .collect();

        Ok(remaining_shares)
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
        // let (xs, ys): (Vec<F>, Vec<F>) = shares
        //     .iter()
        //     .choose_multiple(&mut ChaCha20Rng::from_entropy(),
        // self.threshold)     .into_iter()
        //     .map(|share| (share.x, share.y))
        //     .unzip();
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
