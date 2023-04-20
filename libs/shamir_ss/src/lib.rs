mod lagrange;
pub mod shamir;
pub mod shamir_error;
pub extern crate vsss_rs;

#[cfg(test)]
mod tests {

    use super::*;
    use curve25519_dalek::Scalar;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use shamir::{ShamirSecretSharing, Share};
    use wrapped_ristretto::scalar::WrappedScalar;

    #[test]
    fn it_works_small() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sc = Scalar::random(&mut rng);
        const N: usize = 2;
        const T: usize = 2;
        const D: usize = 1;
        let starting_shares: Vec<Share<WrappedScalar>> = vec![Share {
            x: WrappedScalar::from(2u64),
            y: WrappedScalar::from_bytes_mod_order([
                184, 174, 62, 6, 69, 168, 106, 243, 28, 9, 167, 9, 238, 122,
                164, 2, 64, 199, 113, 183, 211, 174, 83, 131, 156, 7, 244, 23,
                147, 159, 56, 0,
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
                all_shares[i] = missing_shares[i].to_owned();
            } else {
                all_shares[i] = starting_shares[i - D].to_owned();
            }
        }
        let res = shamir.reconstruct_secret::<WrappedScalar>(&all_shares);
        debug_assert!(res.is_ok());
        let combined_secret = res.unwrap();
        debug_assert_eq!(combined_secret.0, sc);
    }

    #[test]
    fn it_works() {
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
                all_shares[i] = missing_shares[i].to_owned();
            } else {
                all_shares[i] = starting_shares[i - D].to_owned();
            }
        }

        let res = shamir.reconstruct_secret::<WrappedScalar>(&all_shares);
        debug_assert!(res.is_ok());
        let combined_secret = res.unwrap();

        debug_assert_eq!(combined_secret.0, sc);
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
                    66, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222,
                    249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    16,
                ])),
            ];

            let poly = LagrangePolynomial::init(xs, ys).unwrap();

            let res = poly.interpolate(WrappedScalar::from(3u64));

            debug_assert_eq!(res, WrappedScalar::from(3u64));
        }
    }
}
