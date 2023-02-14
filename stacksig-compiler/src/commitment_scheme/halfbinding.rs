//! Implementation of 1-of-2 partial-binding vector
//! commitment scheme from discrete log

use core::fmt;
use std::io::Write;
use std::rc::Rc;

use curve25519_dalek::ristretto::{
    CompressedRistretto, RistrettoBasepointTable, RistrettoPoint,
};
use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};

use crate::stackable::Message;
use crate::util::hash;

use super::comm::PartialBindingCommScheme;

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
pub struct PublicParams(
    Rc<RistrettoBasepointTable>,
    Rc<RistrettoBasepointTable>,
);

impl PartialEq for PublicParams {
    fn eq(&self, other: &Self) -> bool {
        self.0
            .basepoint()
            == other
                .0
                .basepoint()
            && self
                .1
                .basepoint()
                == other
                    .1
                    .basepoint()
    }
}

impl fmt::Debug for PublicParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicParams")
            .field(
                "g0 precomputed table with basepoint",
                &self
                    .0
                    .basepoint(),
            )
            .field(
                "h precomputed table with basepoint",
                &self
                    .1
                    .basepoint(),
            )
            .finish()
    }
}

// impl Default for PublicParams {
//     fn default() -> Self {
//         PublicParams(
//
// RistrettoBasepointTable::create(&RistrettoPoint::random(
//                 &mut ChaCha20Rng::from_entropy(),
//             )),
//
// RistrettoBasepointTable::create(&RistrettoPoint::random(
//                 &mut ChaCha20Rng::from_entropy(),
//             )),
//         )
//     }
// }

#[derive(Copy, Clone, Debug, PartialEq, Hash, Default)]
pub struct CommitKey(pub CompressedRistretto);

impl Message for CommitKey {
    fn write<W: Write>(&self, writer: &mut W) {
        writer
            .write_all(
                self.0
                    .as_bytes(),
            )
            .unwrap();
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub struct Commitment(pub [u8; 32], pub [u8; 32]);

impl Default for Commitment {
    fn default() -> Self {
        Commitment([0; 32], [0; 32])
    }
}

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
    trapdoor: Scalar,
    pub commit_key: CommitKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Hash)]
pub struct Randomness(pub Scalar, pub Scalar);

impl Randomness {
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self(Scalar::random(rng), Scalar::random(rng))
    }
}

impl EquivKey {
    pub fn new(
        binding_side: Side,
        trapdoor: Scalar,
        commit_key: CommitKey,
    ) -> Self {
        Self {
            binding_side,
            trapdoor,
            commit_key,
        }
    }
}

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
        message: Rc<M>,
        rand: &Scalar,
    ) -> CompressedRistretto {
        (h * rand + gi * hash(message.as_ref())).compress()
    }
    /// Setup of public parameters and generation of commit
    /// key and equiv key
    ///
    /// Prefer this method over `setup` then `gen` if you
    /// are generating keys immediately from setup.
    fn setupgen<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        binding_side: Side,
    ) -> (PublicParams, CommitKey, EquivKey) {
        let h = RistrettoBasepointTable::create(&RistrettoPoint::random(
            &mut ChaCha20Rng::from_entropy(),
        ));
        let g0 = RistrettoBasepointTable::create(&RistrettoPoint::random(
            &mut ChaCha20Rng::from_entropy(),
        ));
        let pp = PublicParams(Rc::new(g0), Rc::new(h));
        let (ck, ek) = self.gen(&pp, binding_side, rng);
        (pp, ck, ek)
    }
}

/// Implementation of 1-of-2 partially-binding vector
/// commitment scheme
impl PartialBindingCommScheme for HalfBinding {
    type PublicParams = PublicParams;
    type BindingIndex = Side;
    type CommitKey = CommitKey;
    type EquivKey = EquivKey;
    type Commitment = Commitment;
    type Randomness = Randomness;
    type Msg<'a, M: Message + 'a> = (Rc<M>, Rc<M>);

    /// Generate public parameters for the commitment scheme
    fn setup<R: CryptoRngCore>(&self, rng: &mut R) -> PublicParams {
        let h = &RistrettoPoint::random(rng);
        let g0 = &RistrettoPoint::random(rng);
        PublicParams(
            Rc::new(RistrettoBasepointTable::create(g0)),
            Rc::new(RistrettoBasepointTable::create(h)),
        )
    }

    /// Generate a commitment key and equivocation key pair,
    ///
    /// ## Parameters
    /// `pp`: Public parameters
    ///
    /// `side`: Binding side
    fn gen<R: CryptoRngCore>(
        &self,
        pp: &PublicParams,
        binding_side: Side,
        rng: &mut R,
    ) -> (CommitKey, EquivKey) {
        let PublicParams(g0, h) = pp;
        let trapdoor = Scalar::random(rng);
        match binding_side {
            Side::One => {
                let g2 = h.as_ref() * &trapdoor;
                let g1 = Self::g1_from_g2(&g2, g0);
                let commit_key = CommitKey(g1.compress());
                (
                    commit_key,
                    EquivKey {
                        binding_side,
                        trapdoor,
                        commit_key,
                    },
                )
            }
            Side::Two => {
                let g1 = h.as_ref() * &trapdoor;
                // let g2 = &g1 + g0.basepoint();
                let commit_key = CommitKey(g1.compress());
                (
                    commit_key,
                    EquivKey {
                        binding_side,
                        trapdoor,
                        commit_key,
                    },
                )
            }
        }
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
    /// 1. Derive the second side, regardless of binding
    /// side. We can do this because of how we derived
    /// g2 in `gen` method. 2. For each side, compute
    /// the commitment. Commit honestly to both sides as we
    /// don't know which side is the binding side.
    /// 3. Return the commitment for both sides together
    fn bind<M: Message + ?Sized>(
        &self,
        pp: &PublicParams,
        ck: &CommitKey,
        msg: &(Rc<M>, Rc<M>),
        randomness: &Randomness,
    ) -> Commitment {
        let PublicParams(g0, h) = pp;
        let CommitKey(g1) = ck;
        let g1 = g1
            .decompress()
            .unwrap();
        let g2 = Self::g2_from_g1(&g1, g0);

        let (m1, m2) = msg;
        let Randomness(r1, r2) = randomness;
        // We hash the message so that we can commit to longer
        // strings
        let comm1 = Self::commitment(&g1, h, m1.clone(), &r1);
        let comm2 = Self::commitment(&g2, h, m2.clone(), &r2);
        Commitment(*comm1.as_bytes(), *comm2.as_bytes())
    }

    /// Commit with access to the equivocation key. The
    /// difference between this and `bind` is that this
    /// method requires the user to have the equivocation
    /// key. This is useful as we have contextual
    /// information of which side is the binding side
    /// and can avoid unnecessary computation when
    /// committing as we can give the equivocable side
    /// the value of zero.
    ///
    /// ## Parameters
    /// `pp`: Public parameters
    /// `ek`: Equivocation key
    /// `msg`: Message to commit to
    /// `randomness`: Randomness to commit with
    ///
    /// ## Returns
    /// The 2-tuple of bytes representing the commitment of
    /// each side
    fn equivcom<M: Message + ?Sized>(
        &self,
        pp: &PublicParams,
        ek: &EquivKey,
        msg: &(Rc<M>, Rc<M>),
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

        (Self.bind(&pp, commit_key, msg, &rand), rand)
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
    /// The new auxiliary information for equivocation (i.e.
    /// updated randomness for the equivocable side)
    fn equiv<M: Message + ?Sized>(
        &self,
        _pp: &PublicParams,
        ek: &EquivKey,
        old: &(Rc<M>, Rc<M>),
        new: &(Rc<M>, Rc<M>),
        old_aux: &Randomness,
    ) -> Randomness {
        let EquivKey {
            binding_side,
            trapdoor,
            ..
        } = ek;
        let Randomness(r1, r2) = old_aux;

        // randomness for binding side does not change, equiv side
        // changes
        match binding_side {
            Side::One => {
                // equiv side is Two
                let old2 = hash(
                    old.1
                        .as_ref(),
                );
                let new_equiv = hash(
                    new.1
                        .as_ref(),
                );
                let delta = &new_equiv - &old2;
                Randomness(*r1, r2 - trapdoor * delta)
            }
            Side::Two => {
                // equiv side is left
                let old1 = hash(
                    old.0
                        .as_ref(),
                );
                let new_equiv = hash(
                    new.0
                        .as_ref(),
                );
                let delta = &new_equiv - &old1;
                Randomness(r1 - trapdoor * delta, *r2)
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
        let (pp, ck, ..) = HalfBinding
            .setupgen(&mut ChaCha20Rng::from_seed([0u8; 32]), Side::One);
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
        let (pp, ck, ..) = HalfBinding
            .setupgen(&mut ChaCha20Rng::from_seed([0u8; 32]), Side::Two);
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
    fn test_half_binding_works() {
        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let aux = Randomness::random(rng);
        let msg = "hello world";
        let msg2 = "goodbye world";
        let m = (Rc::new(msg.as_bytes()), Rc::new(<&[u8]>::default()));
        let m_equiv = (Rc::new(msg.as_bytes()), Rc::new(msg2.as_bytes()));
        let pp = HalfBinding.setup(rng);
        let (ck, ek) = HalfBinding.gen(&pp, Side::One, rng);

        let (comm_equivcom, aux_old) =
            HalfBinding.equivcom(&pp, &ek, &m, Some(aux));
        let aux_new = HalfBinding.equiv(&pp, &ek, &m, &m_equiv, &aux_old);
        let comm_bind = HalfBinding.bind(&pp, &ck, &m_equiv, &aux_new);
        assert_eq!(comm_equivcom, comm_bind);
    }

    #[test]
    fn test_half_binding_fails() {
        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let aux = Randomness::random(rng);
        let msg = "hello world";
        let msg2 = "goodbye world";
        let m = (Rc::new(msg.as_bytes()), Rc::new(<&[u8]>::default()));
        let m_equiv = (Rc::new(msg.as_bytes()), Rc::new(msg2.as_bytes()));
        let pp = HalfBinding.setup(rng);
        let (ck, ek) = HalfBinding.gen(&pp, Side::One, rng);

        let (comm1, aux1) = HalfBinding.equivcom(&pp, &ek, &m, Some(aux));

        let (comm2, aux2) = HalfBinding.equivcom(&pp, &ek, &m_equiv, Some(aux));

        assert_ne!(comm1, comm2); // TODO: Check if this is supposed to be indistinguishable

        let aux1_new = HalfBinding.equiv(&pp, &ek, &m, &m_equiv, &aux1);
        let aux2_new = HalfBinding.equiv(&pp, &ek, &m_equiv, &m, &aux2);

        let comm1_bind = HalfBinding.bind(&pp, &ck, &m_equiv, &aux1_new);
        let comm2_bind = HalfBinding.bind(&pp, &ck, &m, &aux2_new);

        assert_ne!(comm1_bind, comm2_bind);

        assert_eq!(comm1, comm1_bind);
        assert_eq!(comm2, comm2_bind);
    }
}
