/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
// use super::{Polynomial, Share};
// use crate::lib::*;
// use crate::util::bytes_to_group;
// use crate::{bytes_to_field, Error};
// use core::ops::{AddAssign, Mul};
// use ff::PrimeField;
// use group::{Group, GroupEncoding, ScalarMul};
// use rand_core::{CryptoRng, RngCore};

use core::{
    mem::MaybeUninit,
    ops::{AddAssign, Mul},
};
use curve25519_dalek_ml::scalar::Scalar;
use ed25519_dalek::SecretKey;
use ff::PrimeField;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use vsss_rs::{curve25519::WrappedScalar, Error, Shamir, Share};
use x25519_dalek::StaticSecret;

trait WithSecret<const T: usize, const N: usize> {
    fn combine_with_secret<F, S, const SS: usize>(
        shares: &[Share<SS>],
        f: fn(&[u8]) -> Option<S>,
    ) -> Result<S, Error>
    where
        F: PrimeField,
        S: Default + Copy + AddAssign + Mul<F, Output = S>;

    fn interpolate<F, S>(x_coordinates: &[F], y_coordinates: &[S]) -> S
    where
        F: PrimeField,
        S: Default + Copy + AddAssign + Mul<F, Output = S>,
    {
        let limit = x_coordinates.len();
        // Initialize to zero
        let mut result = S::default();

        for i in 0..limit {
            let mut basis = F::ONE;
            for j in 0..limit {
                if i == j {
                    continue;
                }

                let mut denom: F = x_coordinates[j] - x_coordinates[i];
                denom = denom
                    .invert()
                    .unwrap();
                // x_m / (x_m - x_j) * ...
                basis *= x_coordinates[j] * denom;
            }

            result += y_coordinates[i] * basis;
        }
        result
    }

    fn check_params<F>(secret: Option<F>) -> Result<(), Error>
    where
        F: PrimeField,
    {
        if N < T {
            return Err(Error::SharingLimitLessThanThreshold);
        }
        if T < 2 {
            return Err(Error::SharingMinThreshold);
        }
        if N > 255 {
            return Err(Error::SharingMaxRequest);
        }
        if secret.is_some()
            && secret
                .unwrap()
                .is_zero()
                .unwrap_u8()
                == 1u8
        {
            return Err(Error::InvalidShare);
        }
        Ok(())
    }
}

impl<const T: usize, const N: usize> WithSecret<T, N> for Shamir<T, N> {
    fn combine_with_secret<F, S, const SS: usize>(
        shares: &[Share<SS>],
        f: fn(&[u8]) -> Option<S>,
    ) -> Result<S, Error>
    where
        F: PrimeField,
        S: Default + Copy + AddAssign + Mul<F, Output = S>,
    {
        Self::check_params::<F>(None)?;

        if shares.len() < T {
            return Err(Error::SharingMinThreshold);
        }
        let mut dups = [false; N];
        let mut x_coordinates = [F::default(); T];
        let mut y_coordinates = [S::default(); T];

        for (i, s) in shares
            .iter()
            .enumerate()
            .take(T)
        {
            let identifier = s.identifier();

            if dups[identifier as usize - 1] {
                return Err(Error::SharingDuplicateIdentifier);
            }
            if s.is_zero() {
                return Err(Error::InvalidShare);
            }
            dups[identifier as usize - 1] = true;

            let y = f(s.value());
            match y {
                Some(y) => {
                    x_coordinates[i] = F::from(identifier as u64);
                    y_coordinates[i] = y;
                }
                None => return Err(Error::InvalidShare),
            }
        }
        let secret = Self::interpolate(&x_coordinates, &y_coordinates);
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_works() {
        let mut rng = ChaCha20Rng::from_entropy();
        let sc = Scalar::random(&mut rng);
        let sk1 = StaticSecret::from(sc.to_bytes());
        let ske1 = SecretKey::from_bytes(&sc.to_bytes()).unwrap();
        let res = Shamir::<2, 3>::split_secret::<WrappedScalar, ChaCha20Rng, 33>(
            sc.into(),
            &mut rng,
        );
        assert!(res.is_ok());
        let shares = res.unwrap();

        let res = Shamir::<2, 3>::combine_shares::<WrappedScalar, 33>(&shares);
        assert!(res.is_ok());
        let scalar = res.unwrap();
        assert_eq!(scalar.0, sc);
        let sk2 = StaticSecret::from(
            scalar
                .0
                .to_bytes(),
        );
        let ske2 = SecretKey::from_bytes(
            &scalar
                .0
                .to_bytes(),
        )
        .unwrap();
        assert_eq!(sk2.to_bytes(), sk1.to_bytes());
        assert_eq!(ske1.to_bytes(), ske2.to_bytes());
    }
}

// impl vsss_rs::Shamir {
//     fn combine_with_secret<F, S>(
//         &self,
//         secret: Share,
//         shares: &[Share],
//         f: fn(&[u8]) -> Option<S>,
//     ) -> Result<S, Error>
//     where
//         F: PrimeField,
//         S: Default + Copy + AddAssign + Mul<F, Output = S>,
//     {
//         self.check_params::<F>(None)?;

//         if shares.len() < self.t {
//             return Err(Error::SharingMinThreshold);
//         }

//         let mut dups = BTreeSet::new();
//         let mut x_coordinates = Vec::with_capacity(self.t);
//         let mut y_coordinates = Vec::with_capacity(self.t);

//         for s in shares
//             .iter()
//             .take(self.t)
//         {
//             let identifier = s.identifier();
//             if identifier == 0 {
//                 return Err(Error::SharingInvalidIdentifier);
//             }
//             if dups.contains(&(identifier as usize - 1)) {
//                 return Err(Error::SharingDuplicateIdentifier);
//             }
//             if s.is_zero() {
//                 return Err(Error::InvalidShare);
//             }
//             dups.insert(identifier as usize - 1);

//             let y = f(s.value());
//             if y.is_none() {
//                 return Err(Error::InvalidShare);
//             }
//             x_coordinates.push(F::from(identifier as u64));
//             y_coordinates.push(y.unwrap());
//         }
//         let secret = Self::interpolate(&x_coordinates, &y_coordinates);
//         Ok(secret)
//     }

//     /// Create shares from a secret.
//     /// F is the prime field
//     /// S is the number of bytes used to represent F
//     pub fn split_secret<F, R>(
//         &self,
//         secret: F,
//         rng: &mut R,
//     ) -> Result<Vec<Share>, Error>
//     where
//         F: PrimeField,
//         R: RngCore + CryptoRng,
//     {
//         self.check_params(Some(secret))?;

//         let (shares, _) = self.get_shares_and_polynomial(secret, rng);
//         Ok(shares)
//     }

//     /// Reconstruct a secret from shares created from `split_secret`.
//     /// The X-coordinates operate in `F`
//     /// The Y-coordinates operate in `F`
//     pub fn combine_shares<F>(&self, shares: &[Share]) -> Result<F, Error>
//     where
//         F: PrimeField,
//     {
//         self.combine::<F, F>(shares, bytes_to_field)
//     }

//     /// Reconstruct a secret from shares created from `split_secret`.
//     /// The X-coordinates operate in `F`
//     /// The Y-coordinates operate in `G`
//     ///
//     /// Exists to support operations like threshold BLS where the shares
//     /// operate in `F` but the partial signatures operate in `G`.
//     pub fn combine_shares_group<F, G>(
//         &self,
//         shares: &[Share],
//     ) -> Result<G, Error>
//     where
//         F: PrimeField,
//         G: Group + GroupEncoding + ScalarMul<F> + Default,
//     {
//         self.combine::<F, G>(shares, bytes_to_group)
//     }

//     fn combine<F, S>(
//         &self,
//         shares: &[Share],
//         f: fn(&[u8]) -> Option<S>,
//     ) -> Result<S, Error>
//     where
//         F: PrimeField,
//         S: Default + Copy + AddAssign + Mul<F, Output = S>,
//     {
//         self.check_params::<F>(None)?;

//         if shares.len() < self.t {
//             return Err(Error::SharingMinThreshold);
//         }

//         let mut dups = BTreeSet::new();
//         let mut x_coordinates = Vec::with_capacity(self.t);
//         let mut y_coordinates = Vec::with_capacity(self.t);

//         for s in shares
//             .iter()
//             .take(self.t)
//         {
//             let identifier = s.identifier();
//             if identifier == 0 {
//                 return Err(Error::SharingInvalidIdentifier);
//             }
//             if dups.contains(&(identifier as usize - 1)) {
//                 return Err(Error::SharingDuplicateIdentifier);
//             }
//             if s.is_zero() {
//                 return Err(Error::InvalidShare);
//             }
//             dups.insert(identifier as usize - 1);

//             let y = f(s.value());
//             if y.is_none() {
//                 return Err(Error::InvalidShare);
//             }
//             x_coordinates.push(F::from(identifier as u64));
//             y_coordinates.push(y.unwrap());
//         }
//         let secret = Self::interpolate(&x_coordinates, &y_coordinates);
//         Ok(secret)
//     }

//     pub(crate) fn get_shares_and_polynomial<F, R>(
//         &self,
//         secret: F,
//         rng: &mut R,
//     ) -> (Vec<Share>, Polynomial<F>)
//     where
//         F: PrimeField,
//         R: RngCore + CryptoRng,
//     {
//         let polynomial = Polynomial::<F>::new(secret, rng, self.t);
//         // Generate the shares of (x, y) coordinates
//         // x coordinates are incremental from [1, N+1). 0 is reserved for the secret
//         let mut shares = Vec::with_capacity(self.n);
//         let mut x = F::one();
//         for i in 0..self.n {
//             let y = polynomial.evaluate(x, self.t);
//             let mut t = Vec::with_capacity(
//                 1 + y
//                     .to_repr()
//                     .as_ref()
//                     .len(),
//             );
//             t.push((i + 1) as u8);
//             t.extend_from_slice(
//                 y.to_repr()
//                     .as_ref(),
//             );

//             shares.push(Share(t));

//             x += F::one();
//         }
//         (shares, polynomial)
//     }

//     /// Calculate lagrange interpolation
//     fn interpolate<F, S>(x_coordinates: &[F], y_coordinates: &[S]) -> S
//     where
//         F: PrimeField,
//         S: Default + Copy + AddAssign + Mul<F, Output = S>,
//     {
//         let limit = x_coordinates.len();
//         // Initialize to zero
//         let mut result = S::default();

//         for i in 0..limit {
//             let mut basis = F::one();
//             for j in 0..limit {
//                 if i == j {
//                     continue;
//                 }

//                 let mut denom: F = x_coordinates[j] - x_coordinates[i];
//                 denom = denom
//                     .invert()
//                     .unwrap();
//                 // x_m / (x_m - x_j) * ...
//                 basis *= x_coordinates[j] * denom;
//             }

//             result += y_coordinates[i] * basis;
//         }
//         result
//     }

//     pub(crate) fn check_params<F>(&self, secret: Option<F>) -> Result<(), Error>
//     where
//         F: PrimeField,
//     {
//         if self.n < self.t {
//             return Err(Error::SharingLimitLessThanThreshold);
//         }
//         if self.t < 2 {
//             return Err(Error::SharingMinThreshold);
//         }
//         if self.n > 255 {
//             return Err(Error::SharingMaxRequest);
//         }
//         if secret.is_some()
//             && secret
//                 .unwrap()
//                 .is_zero()
//                 .unwrap_u8()
//                 == 1u8
//         {
//             return Err(Error::InvalidShare);
//         }
//         Ok(())
//     }
// }
