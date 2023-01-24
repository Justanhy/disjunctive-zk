//! Implementation of 1-of-2 partial-binding vector commitment scheme
//! from discrete log

use curve25519_dalek::constants::{
    RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE,
};
use curve25519_dalek::ristretto::{
    CompressedRistretto, RistrettoBasepointTable, RistrettoPoint,
};
use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};

use crate::stack::Message;
use crate::util::hash;

/// 1 out of 2 commitment scheme
pub struct HalfBinding;

#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub enum Side {
    One,
    Two,
}

#[derive(Clone)]
pub struct PublicParams(RistrettoBasepointTable, RistrettoBasepointTable);

#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub struct CommitKey(CompressedRistretto);

#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub struct Commitment(pub [u8; 32], pub [u8; 32]);

#[derive(Clone, Debug, PartialEq, Hash)]
pub struct EquivKey {
    binding_side: Side,
    equiv_scalar: Scalar,
    commit_key: CommitKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Hash)]
pub struct Randomness(Scalar, Scalar);

impl EquivKey {
    pub fn new(
        binding_side: Side,
        equiv_scalar: Scalar,
        commit_key: CommitKey,
    ) -> Self {
        Self {
            binding_side,
            equiv_scalar,
            commit_key,
        }
    }
}

/// Implementation of 1-of-2 partially-binding vector commitment scheme
impl HalfBinding {
    /// Generate public parameters for the commitment scheme
    pub fn setup<R: CryptoRngCore>(rng: &mut R) -> PublicParams {
        let h = &Scalar::random(rng) * &RISTRETTO_BASEPOINT_TABLE;
        let g0 = &RISTRETTO_BASEPOINT_TABLE
            * &Scalar::random(&mut ChaCha20Rng::from_entropy());
        PublicParams(
            RistrettoBasepointTable::create(&g0),
            RistrettoBasepointTable::create(&h),
        )
    }

    /// Generate a commitment key and equivocation key pair,
    ///
    /// ## Parameters
    /// `pp`: Public parameters
    ///
    /// `side`: Binding side
    ///
    ///
    ///
    pub fn gen(pp: &PublicParams, binding_side: Side) -> (CommitKey, EquivKey) {
        let PublicParams(g0, h) = pp;
        let equiv_scalar = Scalar::random(&mut ChaCha20Rng::from_entropy());
        match binding_side {
            Side::One => {
                let g2 = h * &equiv_scalar;
                let g1 = &g2 + g0 * &Scalar::ONE.invert();
                let commit_key = CommitKey(g1.compress());
                (
                    commit_key,
                    EquivKey {
                        binding_side,
                        equiv_scalar,
                        commit_key,
                    },
                )
            }
            Side::Two => {
                let g1 = h * &equiv_scalar;
                // let g2 = &g1 + g0.basepoint();
                let commit_key = CommitKey(g1.compress());
                (
                    commit_key,
                    EquivKey {
                        binding_side,
                        equiv_scalar,
                        commit_key,
                    },
                )
            }
        }
    }

    /// Setup of public parameters and generation of commit key and equiv key
    ///
    /// Prefer this method over `setup` then `gen` if you are generating keys immediately
    /// from setup.
    pub fn setupgen<R: CryptoRngCore>(
        rng: &mut R,
        binding_side: Side,
    ) -> (PublicParams, CommitKey, EquivKey) {
        let h = RistrettoBasepointTable::create(
            &(&Scalar::random(rng) * &RISTRETTO_BASEPOINT_TABLE),
        );
        let g0 = RistrettoBasepointTable::create(
            &(&Scalar::random(&mut ChaCha20Rng::from_entropy())
                * &RISTRETTO_BASEPOINT_TABLE),
        );
        let pp = PublicParams(g0, h);
        let (ck, ek) = Self::gen(&pp, binding_side);
        (pp, ck, ek)
    }

    /// Commit to a message in it's binding side
    ///
    /// ## Parameters
    /// `pp`: Public parameters
    /// `ck`: Commitment key
    /// `msg`: Message to commit to
    /// `binding_side`: Binding side
    ///
    /// ## Steps
    /// 1. Derive the second side, regardless of binding side. We can do this because of how
    /// we derived g2 in `gen` method.
    /// 2. For each side, compute the commitment. Commit honestly to both sides as we don't know
    /// which side is the binding side.
    /// 3. Return the commitment for both sides together
    ///
    pub fn bind<M: Message>(
        pp: &PublicParams,
        ck: CommitKey,
        msg: (&M, &M),
        randomness: Randomness,
    ) -> Commitment {
        let PublicParams(g0, h) = pp;
        let CommitKey(g1) = ck;
        let g1 = g1
            .decompress()
            .unwrap();
        let g2 = &g1 + g0.basepoint();

        let (m1, m2) = msg;
        let Randomness(r1, r2) = randomness;
        // We hash the message so that we can commit to longer strings
        let comm1 = h * &r1 + &g1 * &hash(m1);
        let comm2 = h * &r2 + &g2 * &hash(m2);
        Commitment(
            *comm1
                .compress()
                .as_bytes(),
            *comm2
                .compress()
                .as_bytes(),
        )
    }

    // / Commit to a message in it's binding side
    // pub fn commit<M: Message>(
    //     pp: &PublicParams,
    //     ek: &EquivKey,
    //     msg: (&M, &M),
    // ) -> (Commitment, Randomness) {
    //     let EquivKey { commit_key, .. } = ek;
    //     let r = Randomness(
    //         Scalar::random(&mut ChaCha20Rng::from_entropy()),
    //         Scalar::random(&mut ChaCha20Rng::from_entropy()),
    //     );
    //     (Self::bind(pp, *commit_key, msg, r), r)
    // }

    /// Commit with access to the equivocation key. The difference between this
    /// and `bind` is that this method requires the user to have the equivocation key.
    /// This is useful as we have contextual information of which side is the binding side
    /// and can avoid unnecessary computation when committing as we can give the equivocable side
    /// the value of zero.
    ///
    /// ## Parameters
    /// `pp`: Public parameters
    /// `ek`: Equivocation key
    /// `msg`: Message to commit to
    /// `randomness`: Randomness to commit with
    ///
    /// ## Returns
    /// The 2-tuple of bytes representing the commitment of each side
    pub fn equivcom<M: Message>(
        pp: &PublicParams,
        ek: EquivKey,
        msg: (&M, &M),
        randomness: Randomness,
    ) -> Commitment {
        let EquivKey {
            binding_side,
            commit_key,
            ..
        } = ek;

        let CommitKey(g1) = commit_key;
        let g1 = g1
            .decompress()
            .unwrap();
        let PublicParams(g0, h) = pp;
        let g2 = &g1 + g0.basepoint();

        let (v1, v2) = match binding_side {
            Side::One => (hash(msg.0), Scalar::ZERO),
            Side::Two => (Scalar::ZERO, hash(msg.1)),
        };

        let Randomness(r1, r2) = randomness;

        let comm1 = h * &r1 + &g1 * &v1;
        let comm2 = h * &r2 + &g2 * &v2;

        Commitment(
            *comm1
                .compress()
                .as_bytes(),
            *comm2
                .compress()
                .as_bytes(),
        )
    }

    /// Equivocates the message on the equivocable side
    ///
    /// ## Parameters
    /// `ek:`: Equivocation key
    ///
    /// `old`: Old message
    ///
    /// `new`: New message
    ///
    /// `r`: Randomness for the old message
    ///
    /// ## Returns
    /// The new auxiliary information for equivocation (i.e. updated randomness
    /// for the equivocable side)
    pub fn equiv<M: Message>(
        ek: &EquivKey,
        old: (&M, &M),
        new: (&M, &M),
        r: Randomness,
    ) -> Randomness {
        let EquivKey {
            binding_side,
            equiv_scalar,
            ..
        } = ek;
        let Randomness(r1, r2) = r;

        // randomness for binding side does not change, equiv side changes
        match binding_side {
            Side::One => {
                // equiv side is Two
                let old2 = hash(old.1);
                let new2 = hash(new.1);
                let delta = &new2 - &old2;
                Randomness(r1, r2 - equiv_scalar * delta)
            }
            Side::Two => {
                // equiv side is left
                let old1 = hash(old.0);
                let new1 = hash(new.0);
                let delta = &new1 - &old1;
                Randomness(r1 - equiv_scalar * delta, r2)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_half_binding() {
        let mut rng = ChaCha20Rng::from_entropy();
        let pp = HalfBinding::setup(&mut rng);
        let (ck, ek) = HalfBinding::gen(&pp, Side::One);
        let (ck2, ek2) = HalfBinding::gen(&pp, Side::Two);
        assert_ne!(ck, ck2);
        assert_ne!(ek, ek2);
    }
}
