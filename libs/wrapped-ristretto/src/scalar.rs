use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use curve25519_dalek::Scalar;
use group::ff::{Field, PrimeField};
use group::prime::PrimeGroup;
use group::{Group, GroupEncoding};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use rand_core::CryptoRngCore;
use sigmazk::Challenge;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct WrappedScalar(pub Scalar);

impl WrappedScalar {
    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Self {
        Self(Scalar::from_bytes_mod_order(bytes))
    }

    pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        Self(Scalar::from_bytes_mod_order_wide(bytes))
    }

    pub fn from_canonical_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        Scalar::from_canonical_bytes(bytes).map(|s| Self(s))
    }

    pub const fn from_bits(bytes: [u8; 32]) -> Self {
        Self(Scalar::from_bits(bytes))
    }

    pub const fn from_bites_clamped(bytes: [u8; 32]) -> Self {
        Self(Scalar::from_bits_clamped(bytes))
    }

    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self(Scalar::random(rng))
    }

    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
            .to_bytes()
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0
            .as_bytes()
    }

    pub fn invert(&self) -> WrappedScalar {
        Self(
            self.0
                .invert(),
        )
    }

    pub fn reduce(&self) -> WrappedScalar {
        Self(
            self.0
                .reduce(),
        )
    }

    pub fn is_canonical(&self) -> Choice {
        self.0
            .is_canonical()
    }
}

impl PrimeGroup for WrappedScalar {}

impl GroupEncoding for WrappedScalar {
    type Repr = [u8; 32];

    fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        CtOption::new(
            Self(Scalar::from_bytes_mod_order(*bytes)),
            Choice::from(1u8),
        )
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        Self::from_canonical_bytes(*bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        self.0
            .to_bytes()
    }
}

impl Group for WrappedScalar {
    type Scalar = WrappedScalar;

    fn random(mut rng: impl RngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut crng = ChaChaRng::from_seed(seed);
        Self(Scalar::random(&mut crng))
    }

    fn identity() -> Self {
        Self(Scalar::ZERO)
    }

    fn generator() -> Self {
        Self(Scalar::ONE)
    }

    fn is_identity(&self) -> Choice {
        Choice::from(u8::from(self == &Self::identity()))
    }

    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }
}

impl Field for WrappedScalar {
    const ONE: Self = Self(Scalar::ONE);
    const ZERO: Self = Self(Scalar::ZERO);

    fn random(mut rng: impl RngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut crng = ChaChaRng::from_seed(seed);
        Self(Scalar::random(&mut crng))
    }

    fn square(&self) -> Self {
        Self(self.0 * self.0)
    }

    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }

    fn invert(&self) -> CtOption<Self> {
        CtOption::new(
            Self(
                self.0
                    .invert(),
            ),
            Choice::from(1u8),
        )
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        // if num
        //     .is_zero()
        //     .into()
        // {
        //     (Choice::from(1u8), Self::ZERO)
        // } else if div
        //     .is_zero()
        //     .into()
        // {
        //     (Choice::from(0u8), Self::ZERO)
        // } else {
        //     let x: Scalar = num.0
        //         * div .0 .invert() .unwrap();
        //     let x = u32::from_be_bytes(x.to_bytes());
        //     let root = sqrt
        // }
        unimplemented!()
    }

    fn is_zero(&self) -> Choice {
        Choice::from(u8::from(self.0 == Scalar::ZERO))
    }
}

impl PrimeField for WrappedScalar {
    type Repr = [u8; 32];

    const MODULUS: &'static str =
        "2^252 + 27742317777372353535851937790883648493";
    const NUM_BITS: u32 = 32;
    const CAPACITY: u32 = Self::NUM_BITS - 1;
    const MULTIPLICATIVE_GENERATOR: Self = Self(Scalar::from_bits([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ]));
    const TWO_INV: Self = Self(Scalar::from_bits([
        235, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222,
        20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
    ]));
    const S: u32 = 252;
    // ROOT_OF_UNITY = Self::MULTIPLICATIVE_GENERATOR * t
    // where t = (modulus - 1) >> Self::S = 1
    const ROOT_OF_UNITY: Self = Self::MULTIPLICATIVE_GENERATOR;
    const ROOT_OF_UNITY_INV: Self = Self::TWO_INV;
    const DELTA: Self = Self(Scalar::from_bits([
        19, 44, 10, 163, 229, 156, 237, 167, 41, 99, 8, 93, 33, 6, 33, 235,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 15,
    ]));

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        CtOption::new(
            Self(Scalar::from_bytes_mod_order(repr)),
            Choice::from(1u8),
        )
    }

    fn to_repr(&self) -> Self::Repr {
        self.0
            .to_bytes()
    }

    fn is_odd(&self) -> Choice {
        Choice::from(self.0[0] & 1)
    }
}

impl Sum for WrappedScalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |acc, x| acc + x)
    }
}

impl<'a> Sum<&'a Self> for WrappedScalar {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |acc, x| acc + x)
    }
}

impl Product for WrappedScalar {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |acc, x| acc * x)
    }
}

impl<'a> Product<&'a Self> for WrappedScalar {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |acc, x| acc * x)
    }
}

impl From<u64> for WrappedScalar {
    fn from(d: u64) -> WrappedScalar {
        Self(Scalar::from(d))
    }
}

impl ConditionallySelectable for WrappedScalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(Scalar::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for WrappedScalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0
            .ct_eq(&other.0)
    }
}

impl<'a, 'b> Add<&'b WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn add(self, rhs: &'b WrappedScalar) -> Self::Output {
        *self + *rhs
    }
}

impl<'b> Add<&'b WrappedScalar> for WrappedScalar {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &'b WrappedScalar) -> Self::Output {
        self + *rhs
    }
}

impl<'a> Add<WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn add(self, rhs: WrappedScalar) -> Self::Output {
        *self + rhs
    }
}

impl Add for WrappedScalar {
    type Output = Self;

    #[inline]
    fn add(self, rhs: WrappedScalar) -> Self::Output {
        WrappedScalar(self.0 + rhs.0)
    }
}

impl AddAssign for WrappedScalar {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<'b> AddAssign<&'b WrappedScalar> for WrappedScalar {
    #[inline]
    fn add_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = *self + rhs;
    }
}

impl<'a, 'b> Sub<&'b WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn sub(self, rhs: &'b WrappedScalar) -> Self::Output {
        *self - *rhs
    }
}

impl<'b> Sub<&'b WrappedScalar> for WrappedScalar {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &'b WrappedScalar) -> Self::Output {
        self - *rhs
    }
}

impl<'a> Sub<WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn sub(self, rhs: WrappedScalar) -> Self::Output {
        *self - rhs
    }
}

impl Sub for WrappedScalar {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: WrappedScalar) -> Self::Output {
        WrappedScalar(self.0 - rhs.0)
    }
}

impl SubAssign for WrappedScalar {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<'b> SubAssign<&'b WrappedScalar> for WrappedScalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = *self - rhs;
    }
}

impl<'a, 'b> Mul<&'b WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        *self * *rhs
    }
}

impl<'b> Mul<&'b WrappedScalar> for WrappedScalar {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &'b WrappedScalar) -> Self::Output {
        self * *rhs
    }
}

impl<'a> Mul<WrappedScalar> for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        *self * rhs
    }
}

impl Mul for WrappedScalar {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: WrappedScalar) -> Self::Output {
        WrappedScalar(self.0 * rhs.0)
    }
}

impl MulAssign for WrappedScalar {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<'b> MulAssign<&'b WrappedScalar> for WrappedScalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b WrappedScalar) {
        *self = *self * rhs;
    }
}

impl<'a> Neg for &'a WrappedScalar {
    type Output = WrappedScalar;

    #[inline]
    fn neg(self) -> Self::Output {
        WrappedScalar(
            self.0
                .neg(),
        )
    }
}

impl Neg for WrappedScalar {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        -&self
    }
}

impl From<WrappedScalar> for Scalar {
    fn from(s: WrappedScalar) -> Scalar {
        s.0
    }
}

impl From<Scalar> for WrappedScalar {
    fn from(s: Scalar) -> WrappedScalar {
        Self(s)
    }
}

impl From<[u8; 32]> for WrappedScalar {
    fn from(bytes: [u8; 32]) -> WrappedScalar {
        Self(Scalar::from_bytes_mod_order(bytes))
    }
}

impl Challenge for WrappedScalar {
    fn new(bytes: &[u8; 64]) -> Self {
        Self(Scalar::from_bytes_mod_order_wide(bytes))
    }
}
