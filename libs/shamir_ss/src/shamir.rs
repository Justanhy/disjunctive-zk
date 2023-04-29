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
    ) -> Result<
        (LagrangePolynomial<F>, Vec<Share<F>>),
        ShamirError,
    >
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
        let mut y_coordinates: Vec<F> =
            Vec::with_capacity(self.threshold);
        // Corresponding shares to each participant
        let mut shares: Vec<Share<F>> =
            Vec::with_capacity(self.shares);
        // Initialise y-intercept (secret)
        y_coordinates.push(secret);
        // To create random polynomial
        for i in 1..self.threshold {
            y_coordinates.push(F::random(&mut *rng));
            // Initialise shares for each x-coordinate from 1 to threshold
            shares.push(Share {
                x: x_coordinates[i],
                y: y_coordinates[i],
            })
        }
        let poly = LagrangePolynomial::init(
            x_coordinates,
            y_coordinates,
        )?;

        for i in self.threshold..=self.shares {
            // Initialise shares for each x-coordinate from threshold to shares
            shares.push(Share {
                x: F::from(i as u64),
                y: poly.interpolate(F::from(i as u64)),
            })
        }

        Ok((poly, shares))
    }

    pub fn complete_shares_mut<F>(
        &self,
        secret: &F,
        unqualified_shares: &mut Vec<Share<F>>,
        remaining_xs: &Vec<usize>,
    ) -> Result<(), ShamirError>
    where
        F: PrimeField,
    {
        if unqualified_shares.len() != self.threshold - 1 {
            return Err(ShamirError::InvalidUnqualifiedSet);
        }

        let mut x_coordinates: Vec<F> =
            Vec::with_capacity(self.threshold);
        let mut y_coordinates: Vec<F> =
            Vec::with_capacity(self.threshold);

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
        let poly = LagrangePolynomial::init(
            x_coordinates,
            y_coordinates,
        )?;

        // Iterate through each x-coordinate in remaining set and
        // interpolate at each point
        // Interpolation is a O(n^2) operation where n = size of
        // threshold = total - active + 1 This outer loop
        // goes through remaining_xs which is of size = active
        // So, total complexity is O(n^2 * active)
        unqualified_shares.resize(
            self.threshold + remaining_xs.len() - 1,
            Share::default(),
        );

        for i in remaining_xs.iter() {
            let x = F::from(*i as u64);
            let y = poly.interpolate(x);
            unqualified_shares[*i] = Share { x, y };
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

        let mut x_coordinates: Vec<F> =
            Vec::with_capacity(self.threshold);
        let mut y_coordinates: Vec<F> =
            Vec::with_capacity(self.threshold);

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
        let poly = LagrangePolynomial::init(
            x_coordinates,
            y_coordinates,
        )?;

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
        poly: &LagrangePolynomial<F>,
    ) -> Result<F, ShamirError>
    where
        F: PrimeField,
    {
        Ok(poly.interpolate(F::ZERO))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use curve25519_dalek::Scalar;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use wrapped_ristretto::scalar::WrappedScalar;

    #[test]
    fn split_secret_works() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sc = Scalar::random(&mut rng);
        const N: usize = 3;
        const D: usize = 1;
        let shamir = ShamirSecretSharing {
            threshold: N - D + 1,
            shares: N,
        };
        let (poly, shares) = shamir
            .split_secret(WrappedScalar(sc), &mut rng)
            .unwrap();
        assert_eq!(shares.len(), N);
        let combined_secret_fast = shamir
            .reconstruct_secret_fast(&poly)
            .unwrap();
        assert_eq!(combined_secret_fast, WrappedScalar(sc));
        let combined_secret = shamir
            .reconstruct_secret(&shares)
            .unwrap();
        assert_eq!(combined_secret, WrappedScalar(sc))
    }

    #[test]
    fn complete_shares_work_small() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sc = Scalar::random(&mut rng);
        const N: usize = 2;
        const T: usize = 2;
        const D: usize = 1;
        let starting_shares: Vec<Share<WrappedScalar>> =
            vec![Share {
                x: WrappedScalar::from(2u64),
                y: WrappedScalar::from_bytes_mod_order([
                    184, 174, 62, 6, 69, 168, 106, 243, 28,
                    9, 167, 9, 238, 122, 164, 2, 64, 199,
                    113, 183, 211, 174, 83, 131, 156, 7,
                    244, 23, 147, 159, 56, 0,
                ]),
            }];
        let shamir = ShamirSecretSharing {
            threshold: T,
            shares: N,
        };
        let res = shamir.complete_shares::<WrappedScalar>(
            &sc.into(),
            &starting_shares,
            &vec![WrappedScalar::from(1u64)],
        );
        assert!(res.is_ok());

        let missing_shares = res.unwrap();
        let mut all_shares = vec![Share::default(); N];

        for i in 0..N {
            if i < D {
                // purposefully use missing shares first to test all of them
                all_shares[i] =
                    missing_shares[i].to_owned();
            } else {
                all_shares[i] =
                    starting_shares[i - D].to_owned();
            }
        }
        let res = shamir
            .reconstruct_secret::<WrappedScalar>(
                &all_shares,
            );
        debug_assert!(res.is_ok());
        let combined_secret = res.unwrap();
        debug_assert_eq!(combined_secret.0, sc);
    }

    #[test]
    fn complete_shares_mutable_work_small() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sc = Scalar::random(&mut rng);
        const N: usize = 2;
        const T: usize = 2;
        const D: usize = 1;
        let mut starting_shares: Vec<Share<WrappedScalar>> =
            vec![Share {
                x: WrappedScalar::from(2u64),
                y: WrappedScalar::from_bytes_mod_order([
                    184, 174, 62, 6, 69, 168, 106, 243, 28,
                    9, 167, 9, 238, 122, 164, 2, 64, 199,
                    113, 183, 211, 174, 83, 131, 156, 7,
                    244, 23, 147, 159, 56, 0,
                ]),
            }];
        let shamir = ShamirSecretSharing {
            threshold: T,
            shares: N,
        };
        let res = shamir
            .complete_shares_mut::<WrappedScalar>(
                &sc.into(),
                &mut starting_shares,
                &vec![1],
            );
        assert!(res.is_ok());

        let all_shares = starting_shares;

        let res = shamir
            .reconstruct_secret::<WrappedScalar>(
                &all_shares,
            );
        debug_assert!(res.is_ok());
        let combined_secret = res.unwrap();
        debug_assert_eq!(combined_secret.0, sc);
    }

    #[test]
    fn complete_shares_work_big() {
        let mut rng = ChaCha20Rng::from_entropy();
        let sc = Scalar::random(&mut rng);
        const N: usize = 10; // Total number of clauses
        const T: usize = 7; // Threshold of Shamir
        const D: usize = 4; // Number of active clauses
        let starting_shares: Vec<Share<WrappedScalar>> = vec![
            Share {
                x: WrappedScalar::from(1),
                y: WrappedScalar::from([1u8; 32]),
            },
            Share {
                x: WrappedScalar::from(2),
                y: WrappedScalar::from([2u8; 32]),
            },
            Share {
                x: WrappedScalar::from(7),
                y: WrappedScalar::from([7u8; 32]),
            },
            Share {
                x: WrappedScalar::from(4),
                y: WrappedScalar::from([4u8; 32]),
            },
            Share {
                x: WrappedScalar::from(9),
                y: WrappedScalar::from([9u8; 32]),
            },
            Share {
                x: WrappedScalar::from(6),
                y: WrappedScalar::from([6u8; 32]),
            },
        ];
        let shamir = ShamirSecretSharing {
            threshold: T,
            shares: N,
        };

        let res = shamir.complete_shares::<WrappedScalar>(
            &sc.into(),
            &starting_shares,
            &vec![
                WrappedScalar::from(3u64),
                WrappedScalar::from(8u64),
                WrappedScalar::from(5u64),
                WrappedScalar::from(10u64),
            ],
        );
        debug_assert!(res.is_ok());

        let missing_shares = res.unwrap();
        let mut all_shares = vec![Share::default(); N];

        for i in 0..N {
            if i < D {
                // purposefully use missing shares first to test all of them
                all_shares[i] =
                    missing_shares[i].to_owned();
            } else {
                all_shares[i] =
                    starting_shares[i - D].to_owned();
            }
        }

        let res = shamir
            .reconstruct_secret::<WrappedScalar>(
                &all_shares,
            );
        debug_assert!(res.is_ok());
        let combined_secret = res.unwrap();

        debug_assert_eq!(combined_secret.0, sc);
    }
}
