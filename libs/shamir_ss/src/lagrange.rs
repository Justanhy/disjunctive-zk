use core::ops::{AddAssign, Mul};
use elliptic_curve::ff::PrimeField;
use rand_core::CryptoRngCore;

pub enum LagrangeError {
    InvalidCoordinateSizes,
}

/// The polynomial used for generating the shares
pub struct LagrangePolynomial<F: PrimeField> {
    x_coordinates: Vec<F>,
    y_coordinates: Vec<F>,
}

impl<F: PrimeField> LagrangePolynomial<F> {
    pub fn check_coordinates(
        xs: &Vec<F>,
        ys: &Vec<F>,
    ) -> Result<(), LagrangeError> {
        if xs.len() != ys.len() {
            return Err(LagrangeError::InvalidCoordinateSizes);
        }
        Ok(())
    }
    /// Initialise a polynomial with the given initialisation
    pub fn init(x_coordinates: Vec<F>, y_coordinates: Vec<F>) -> Self {
        if Self::check_coordinates(&x_coordinates, &y_coordinates).is_err() {
            panic!("x and y coordinates must be the same length");
        }
        Self {
            x_coordinates,
            y_coordinates,
        }
    }

    /// Initialise a polynomial with the given initialisation,
    /// filling in missing y coordinates
    pub fn filling_init(
        x_coordinates: Vec<F>,
        y_coordinates: Vec<Option<F>>,
        mut rng: &mut impl CryptoRngCore,
    ) -> Self {
        let mut ys = vec![F::default(); y_coordinates.len()];
        for (i, c) in ys
            .iter_mut()
            .enumerate()
        {
            match y_coordinates[i] {
                Some(v) => *c = v,
                None => *c = F::random(&mut rng),
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
        F: PrimeField,
        S: Default + Copy + AddAssign + Mul<F, Output = S>,
    {
        let limit = xs.len();
        let mut result = S::default();
        for i in 0..limit {
            let mut num = F::one();
            let mut denom = F::one();
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

// pub struct LagrangePolynomial<F: PrimeField, const N: usize> {
//     x_coordinates: [F; N],
//     y_coordinates: [F; N],
// }

// impl<F: PrimeField, const N: usize> LagrangePolynomial<F, N> {
//     /// Initialise a polynomial with the given initialisation
//     pub fn init(x_coordinates: [F; N], y_coordinates: [F; N]) -> Self {
//         Self {
//             x_coordinates,
//             y_coordinates,
//         }
//     }

//     /// Initialise a polynomial with the given initialisation,
//     /// filling in missing y coordinates
//     pub fn filling_init(
//         x_coordinates: [F; N],
//         y_coordinates: [Option<F>; N],
//         mut rng: &mut impl CryptoRngCore,
//     ) -> Self {
//         let mut ys = [F::default(); N];
//         for (i, c) in ys
//             .iter_mut()
//             .enumerate()
//         {
//             match y_coordinates[i] {
//                 Some(v) => *c = v,
//                 None => *c = F::random(&mut rng),
//             }
//         }
//         Self::init(x_coordinates, ys)
//     }

//     pub fn interpolate(&self, x: F) -> F {
//         Self::lagrange_interpolation(
//             &self.x_coordinates,
//             &self.y_coordinates,
//             x,
//         )
//     }

//     /// Interpolate a polynomial using the given points
//     pub fn lagrange_interpolation<S>(xs: &[F], ys: &[S], x: F) -> S
//     where
//         F: PrimeField,
//         S: Default + Copy + AddAssign + Mul<F, Output = S>,
//     {
//         let limit = xs.len();
//         let mut result = S::default();
//         for i in 0..limit {
//             let mut num = F::one();
//             let mut denom = F::one();
//             for j in 0..limit {
//                 if i == j {
//                     continue;
//                 }
//                 num *= x - xs[j];
//                 denom *= xs[i] - xs[j];
//             }
//             result += ys[i]
//                 * num
//                 * denom
//                     .invert()
//                     .unwrap();
//         }
//         result
//     }
// }
