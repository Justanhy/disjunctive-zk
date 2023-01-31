//! Implementation of 1-of-2 partial-binding vector commitment scheme
//! from discrete log

use std::io::Write;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
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

impl Side {
    /// Maps side to index (0 or 1)
    pub fn to_index(&self) -> usize {
        match self {
            Side::One => 0,
            Side::Two => 1,
        }
    }
}

#[derive(Clone)]
pub struct PublicParams(RistrettoBasepointTable, RistrettoBasepointTable);

#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub struct CommitKey(CompressedRistretto);

#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub struct Commitment(pub [u8; 32], pub [u8; 32]);

impl Message for Commitment {
    fn write<W: Write>(&self, writer: &mut W) {
        let mut a = [0u8; 64];
        a[..32].copy_from_slice(&self.0[..]);
        a[32..].copy_from_slice(&self.1[..]);
        writer
            .write_all(&a[..])
            .unwrap();
    }
}

#[derive(Clone, Debug, PartialEq, Hash)]
pub struct EquivKey {
    binding_side: Side,
    equiv_scalar: Scalar,
    pub commit_key: CommitKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Hash)]
pub struct Randomness(pub Scalar, pub Scalar);

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
    fn g2_from_g1(
        g1: &RistrettoPoint,
        g0: &RistrettoBasepointTable,
    ) -> RistrettoPoint {
        g1 + g0.basepoint()
    }

    fn g1_from_g2(
        g2: &RistrettoPoint,
        g0: &RistrettoBasepointTable,
    ) -> RistrettoPoint {
        g2 - g0.basepoint()
    }

    fn commitment<M: Message + ?Sized>(
        gi: &RistrettoPoint,
        h: &RistrettoBasepointTable,
        message: Option<&M>,
        rand: &Scalar,
    ) -> CompressedRistretto {
        (h * rand
            + gi * &message
                .map(|val| hash(val))
                .unwrap_or(Scalar::ZERO))
            .compress()
    }
    /// Generate public parameters for the commitment scheme
    pub fn setup<R: CryptoRngCore>(rng: &mut R) -> PublicParams {
        let h = &Scalar::random(rng) * RISTRETTO_BASEPOINT_TABLE;
        let g0 = RISTRETTO_BASEPOINT_TABLE
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
                let g1 = Self::g1_from_g2(&g2, g0);
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
            &(&Scalar::random(rng) * RISTRETTO_BASEPOINT_TABLE),
        );
        let g0 = RistrettoBasepointTable::create(
            &(&Scalar::random(&mut ChaCha20Rng::from_entropy())
                * RISTRETTO_BASEPOINT_TABLE),
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
    pub fn bind<M: Message + ?Sized>(
        pp: &PublicParams,
        ck: CommitKey,
        msg: (Option<&M>, Option<&M>),
        randomness: Randomness,
    ) -> Commitment {
        let PublicParams(g0, h) = pp;
        let CommitKey(g1) = ck;
        let g1 = g1
            .decompress()
            .unwrap();
        let g2 = Self::g2_from_g1(&g1, g0);

        let (m1, m2) = msg;
        let Randomness(r1, r2) = randomness;
        // We hash the message so that we can commit to longer strings
        let comm1 = Self::commitment(&g1, h, m1, &r1);
        let comm2 = Self::commitment(&g2, h, m2, &r2);
        Commitment(*comm1.as_bytes(), *comm2.as_bytes())
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
    pub fn equivcom<M: Message + ?Sized>(
        pp: &PublicParams,
        ek: &EquivKey,
        msg: (Option<&M>, Option<&M>),
        randomness: Option<Randomness>,
    ) -> (Commitment, Randomness) {
        let EquivKey { commit_key, .. } = ek;

        let rand = match randomness {
            Some(rand) => rand,
            None => Randomness(
                Scalar::random(&mut ChaCha20Rng::from_entropy()),
                Scalar::random(&mut ChaCha20Rng::from_entropy()),
            ),
        };

        // let PublicParams(g0, h) = pp;
        // let CommitKey(g1) = commit_key;
        // let g1 = g1
        //     .decompress()
        //     .unwrap();
        // let g2 = Self::g2_from_g1(&g1, g0);
        // let comm1 = Self::commitment(&g1, h, msg.0, &r1);
        // let comm2 = Self::commitment(&g2, h, msg.1, &r2);

        (Self::bind(&pp, *commit_key, msg, rand), rand)
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
    pub fn equiv<M: Message + ?Sized>(
        ek: &EquivKey,
        old: (Option<&M>, Option<&M>),
        new: (Option<&M>, Option<&M>),
        old_aux: Randomness,
    ) -> Randomness {
        let EquivKey {
            binding_side,
            equiv_scalar,
            ..
        } = ek;
        let Randomness(r1, r2) = old_aux;

        // randomness for binding side does not change, equiv side changes
        match binding_side {
            Side::One => {
                // equiv side is Two
                let old2 = old
                    .1
                    .map(|m| hash(m))
                    .unwrap_or(Scalar::ZERO);
                let new_equiv = new
                    .1
                    .map(|m| hash(m))
                    .unwrap_or(Scalar::ZERO);
                let delta = &new_equiv - &old2;
                Randomness(r1, r2 - equiv_scalar * delta)
            }
            Side::Two => {
                // equiv side is left
                let old1 = old
                    .0
                    .map(|m| hash(m))
                    .unwrap_or(Scalar::ZERO);
                let new_equiv = new
                    .0
                    .map(|m| hash(m))
                    .unwrap_or(Scalar::ZERO);
                let delta = &new_equiv - &old1;
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
    fn test_g1g2() {
        let (pp, ck, ..) = HalfBinding::setupgen(
            &mut ChaCha20Rng::from_seed([0u8; 32]),
            Side::One,
        );
        let g1 =
            ck.0.decompress()
                .unwrap();
        let g2 = HalfBinding::g2_from_g1(&g1, &pp.0);
        assert_eq!(
            g2,
            g1 + pp
                .0
                .basepoint()
        );
        assert_eq!(g1, HalfBinding::g1_from_g2(&g2, &pp.0));
        let (pp, ck, ..) = HalfBinding::setupgen(
            &mut ChaCha20Rng::from_seed([0u8; 32]),
            Side::Two,
        );
        let g1 =
            ck.0.decompress()
                .unwrap();
        let g2 = HalfBinding::g2_from_g1(&g1, &pp.0);
        assert_eq!(
            g2,
            g1 + pp
                .0
                .basepoint()
        );
        assert_eq!(g1, HalfBinding::g1_from_g2(&g2, &pp.0));
    }

    #[test]
    fn test_half_binding() {
        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let aux = Randomness(
            Scalar::random(&mut ChaCha20Rng::from_seed([1u8; 32])),
            Scalar::random(&mut ChaCha20Rng::from_seed([2u8; 32])),
        );
        let msg = "hello world";
        let msg2 = "goodbye world";
        let m = (Some(msg.as_bytes()), None);
        let m_equiv = (Some(msg.as_bytes()), Some(msg2.as_bytes()));
        let pp = HalfBinding::setup(rng);
        let (ck, ek) = HalfBinding::gen(&pp, Side::One);

        let (comm_equivcom, aux_old) =
            HalfBinding::equivcom(&pp, &ek, m, Some(aux));
        // let comm_old_bind = HalfBinding::bind(&pp, ck, m, aux_old);
        // assert_eq!(comm_old, comm_old_bind);

        let aux_new = HalfBinding::equiv(&ek, m, m_equiv, aux_old);
        // let (comm_equivcom, _) = HalfBinding::equivcom(&pp, &ek, m_equiv, Some(aux_new));
        let comm_bind = HalfBinding::bind(&pp, ck, m_equiv, aux_new);
        assert_eq!(comm_equivcom, comm_bind);
    }
}
