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
mod lagrange;
mod shamir_error;

use core::{
    mem::MaybeUninit,
    ops::{AddAssign, Mul},
};
use curve25519_dalek_ml::scalar::Scalar;
use ed25519_dalek::SecretKey;
use elliptic_curve::{ff::PrimeField, group::cofactor::CofactorCurveAffine};
use lagrange::LagrangePolynomial;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use shamir_error::ShamirError;
use vsss_rs::Error::{
    InvalidSecret, InvalidShare, InvalidShareConversion,
    SharingDuplicateIdentifier, SharingInvalidIdentifier,
    SharingLimitLessThanThreshold, SharingMaxRequest, SharingMinThreshold,
};
use vsss_rs::{curve25519::WrappedScalar, Shamir, Share};

pub trait WithShares<const T: usize, const N: usize> {
    fn split_secret_filling_shares<F, R, const S: usize, const D: usize>(
        secret: F,
        shares: &[Share<S>],
        active_clause_index: [F; D],
    ) -> Result<[Share<S>; D], ShamirError>
    where
        F: PrimeField,
        R: CryptoRngCore;

    fn check_params<F>(secret: Option<F>) -> Result<(), ShamirError>
    where
        F: PrimeField,
    {
        if N < T {
            return Err(ShamirError::Error(SharingLimitLessThanThreshold));
        }
        if T < 2 {
            return Err(ShamirError::Error(SharingMinThreshold));
        }
        if N > 255 {
            return Err(ShamirError::Error(SharingMaxRequest));
        }
        if secret.is_some()
            && secret
                .unwrap()
                .is_zero()
                .unwrap_u8()
                == 1u8
        {
            return Err(ShamirError::Error(InvalidShare));
        }
        Ok(())
    }
}

fn u32_to_field<F: PrimeField>(x: &u32) -> Result<F, ShamirError> {
    let mut repr = F::Repr::default();
    repr.as_mut()
        .copy_from_slice(
            x.to_be_bytes()
                .as_ref(),
        );
    let res = F::from_repr(repr);
    if res
        .is_some()
        .unwrap_u8()
        == 1u8
    {
        Ok(res.unwrap())
    } else {
        Err(ShamirError::Error(InvalidShare))
    }
}

impl<const T: usize, const N: usize> WithShares<T, N> for Shamir<T, N> {
    fn split_secret_filling_shares<F, R, const S: usize, const D: usize>(
        secret: F,
        shares: &[Share<S>],
        active_clause_index: [F; D],
    ) -> Result<[Share<S>; D], ShamirError>
    where
        F: PrimeField,
        R: CryptoRngCore,
    {
        Self::check_params(Some(secret))?;
        let k = shares.len();
        if k != T - 1 {
            return Err(ShamirError::InvalidUnqualifiedSet);
        }

        let mut x_coordinates = [F::default(); T];
        let mut y_coordinates = [F::default(); T];

        x_coordinates[0] = F::zero();
        y_coordinates[0] = secret;

        for i in 0..k {
            let x = shares[i].identifier();
            if x == 0 {
                return Err(ShamirError::Error(InvalidShare));
            }
            let val = shares[i].as_field_element();
            if val.is_err() {
                return Err(ShamirError::Error(InvalidShareConversion));
            }
            x_coordinates[i + 1] = F::from(x as u64);
            y_coordinates[i + 1] = val.unwrap();
        }

        let poly = LagrangePolynomial::init(x_coordinates, y_coordinates);

        let mut challenges: [Share<S>; D] = [Share::default(); D];

        for i in 0..D {
            let x = active_clause_index[i];
            let y = poly.interpolate(x);
            let mut t = [0u8; S];
            t[0] = x
                .to_repr()
                .as_ref()[0];
            t[1..].copy_from_slice(
                y.to_repr()
                    .as_ref(),
            );
            challenges[i] = Share(t);
        }

        Ok(challenges)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use x25519_dalek::StaticSecret;

    #[test]
    fn it_works() {
        let mut rng = ChaCha20Rng::from_entropy();
        let sc = Scalar::random(&mut rng);
        let sk1 = StaticSecret::from(sc.to_bytes());
        let ske1 = SecretKey::from_bytes(&sc.to_bytes()).unwrap();
        const N: usize = 10; // Total number of clauses
        const T: usize = 7; // Threshold of Shamir
        const D: usize = 4; // Number of active clauses
        const SHARESIZE: usize = 33; // Size of each share
        let starting_shares: [Share<SHARESIZE>; T - 1] = [
            Share([1u8; 33]),
            Share([2u8; 33]),
            Share([3u8; 33]),
            Share([4u8; 33]),
            Share([5u8; 33]),
            Share([6u8; 33]),
        ];
        let res = Shamir::<T, N>::split_secret_filling_shares::<
            WrappedScalar,
            ChaCha20Rng,
            SHARESIZE,
            D,
        >(
            sc.into(),
            &starting_shares,
            [
                WrappedScalar::from(7u64),
                WrappedScalar::from(8u64),
                WrappedScalar::from(9u64),
                WrappedScalar::from(10u64),
            ],
        );
        debug_assert!(res.is_ok());

        let missing_shares = res.unwrap();
        let mut all_shares = [Share::default(); N];

        for i in 0..N {
            if i < D {
                // purposefully use missing shares first to test all of them
                all_shares[i] = missing_shares[i];
            } else {
                all_shares[i] = starting_shares[i - D];
            }
        }

        let res =
            Shamir::<T, N>::combine_shares::<WrappedScalar, 33>(&all_shares);
        debug_assert!(res.is_ok());
        let scalar = res.unwrap();
        debug_assert_eq!(scalar.0, sc);
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
        debug_assert_eq!(sk2.to_bytes(), sk1.to_bytes());
        debug_assert_eq!(ske1.to_bytes(), ske2.to_bytes());
    }

    #[cfg(test)]
    mod polynomial_tests {
        use super::*;
        use crate::lagrange::LagrangePolynomial;

        #[test]
        fn interpolate_works() {
            let xs = [
                WrappedScalar::from(1u64),
                WrappedScalar::from(2u64),
                WrappedScalar::from(5u64),
            ];

            let ys = [
                WrappedScalar::from(1u64),
                WrappedScalar::from(24u64),
                WrappedScalar(Scalar::from_bytes_mod_order([
                    66, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222,
                    249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    16,
                ])),
            ];

            let poly = LagrangePolynomial::init(xs, ys);

            let res = poly.interpolate(WrappedScalar::from(3u64));

            debug_assert_eq!(res, WrappedScalar::from(3u64));
        }
    }
}
