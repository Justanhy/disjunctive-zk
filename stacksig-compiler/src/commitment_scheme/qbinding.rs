//! Implementation of 1-of-2^q partially-binding vector
//! commitment from discrete log using halfbinding comitment
//! schemes

use std::default;

use rand_core::CryptoRngCore;

use crate::stack::Message;

use super::halfbinding::{Commitment, HalfBinding, Side};

pub struct QBinding;

#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub enum BindingIndex {
    One,
    Two,
    Three,
    Four,
}

pub struct PublicParams {
    pub inner: super::halfbinding::PublicParams,
    pub outer: super::halfbinding::PublicParams,
}

#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub struct CommitKey {
    pub inner_ck: super::halfbinding::CommitKey,
    pub outer_ck: super::halfbinding::CommitKey,
}

#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub struct Randomness {
    pub inner: super::halfbinding::Randomness,
    pub outer: super::halfbinding::Randomness,
}

#[derive(Clone, Debug, PartialEq, Hash)]
pub struct EquivKey {
    pub inner_ek: super::halfbinding::EquivKey,
    pub outer_ek: super::halfbinding::EquivKey,
    pub binding_info: (BindingIndex, Side, Side),
}

/// Implementation of 1-of-2^2 partially-binding vector
/// commitment from discrete log using 2 halfbinding
/// comitment schemes.
///
/// We can obtain a 1-of-2^q partially-binding vector
/// commitment by using this iteratively.
impl QBinding {
    /// Setup public parameters
    pub fn setup<R: CryptoRngCore>(rng: &mut R) -> PublicParams {
        let inner = HalfBinding::setup(rng);
        let outer = HalfBinding::setup(rng);
        PublicParams { inner, outer }
    }

    /// Generate commitment key and equivocation key
    pub fn gen(
        pp: &PublicParams,
        binding_index: BindingIndex,
    ) -> (CommitKey, EquivKey) {
        let (inner_side, outer_side) = match binding_index {
            // According to the formula in the paper
            // ia = i mod la and ib = floor(i / la)
            // in our case la = 2
            BindingIndex::One => (Side::One, Side::One),
            BindingIndex::Two => (Side::Two, Side::One),
            BindingIndex::Three => (Side::One, Side::Two),
            BindingIndex::Four => (Side::Two, Side::Two),
        };
        let (inner_ck, inner_ek) = HalfBinding::gen(&pp.inner, inner_side);
        let (outer_ck, outer_ek) = HalfBinding::gen(&pp.outer, outer_side);
        (
            CommitKey { inner_ck, outer_ck },
            EquivKey {
                inner_ek,
                outer_ek,
                binding_info: (binding_index, inner_side, outer_side),
            },
        )
    }

    pub fn setupgen<R: CryptoRngCore>(
        rng: &mut R,
        binding_index: BindingIndex,
    ) -> (PublicParams, CommitKey, EquivKey) {
        let pp = Self::setup(rng);
        let (ck, ek) = Self::gen(&pp, binding_index);
        (pp, ck, ek)
    }

    /// Given equivocation key, commit to a 4-tuple message
    ///
    /// ## Parameters
    /// `pp`: Public parameters
    /// `ek`: Equivocation key
    /// `msg`: Message to commit to
    ///
    /// ## Returns
    /// Commitment and randomness
    pub fn equivcom<M: Message + ?Sized>(
        pp: &PublicParams,
        ek: &EquivKey,
        msg: (&M, &M, &M, &M),
        aux: Option<Randomness>,
    ) -> (Commitment, Randomness) {
        // Pattern match parameters
        let EquivKey {
            inner_ek,
            outer_ek,
            binding_info: (binding_index, inner_side, outer_side),
        } = ek;
        let (inner_rand, outer_rand) = match aux {
            Some(r) => {
                let Randomness { inner, outer } = r;
                (Some(inner), Some(outer))
            }
            None => (None, None),
        };
        // Create v_a which is None except at the binding index for
        // A
        let mdefault = &M::default();
        let inner_vec = match binding_index {
            BindingIndex::One => match inner_side {
                Side::One => (msg.0, mdefault),
                Side::Two => (mdefault, msg.0),
            },
            BindingIndex::Two => match inner_side {
                Side::One => (msg.1, mdefault),
                Side::Two => (mdefault, msg.1),
            },
            BindingIndex::Three => match inner_side {
                Side::One => (msg.2, mdefault),
                Side::Two => (mdefault, msg.2),
            },
            BindingIndex::Four => match inner_side {
                Side::One => (msg.3, mdefault),
                Side::Two => (mdefault, msg.3),
            },
        };
        // Commit to v_a
        let (inner_comm, inner_aux) =
            HalfBinding::equivcom(&pp.inner, inner_ek, inner_vec, inner_rand);
        // Create v_b which is None except at the binding index for
        // B
        let mut outer_vec: (&Commitment, &Commitment) =
            (&Commitment::default(), &Commitment::default());
        match outer_side {
            Side::One => outer_vec.0 = &inner_comm,
            Side::Two => outer_vec.1 = &inner_comm,
        };
        // Commit to v_b
        let (outer_comm, outer_aux) =
            HalfBinding::equivcom(&pp.outer, outer_ek, outer_vec, outer_rand);

        (
            outer_comm,
            Randomness {
                inner: inner_aux,
                outer: outer_aux,
            },
        )
    }

    /// Commit to a 4-tuple message which make up 2 chunks
    /// of 2-tuple messages We use the inner commitment
    /// scheme to commit to each of the 2 chunks and the
    /// outer commitment scheme to commit to the 2 inner
    /// commitments
    ///
    /// ## Parameters
    /// `pp`: Public parameters
    /// `ck`: Commitment key
    /// `msg`: Messages to commit to
    /// `r`: Randomness (auxiliary variables needed for
    /// commitment)
    pub fn bind<M: Message + ?Sized>(
        pp: &PublicParams,
        ck: CommitKey,
        msg: (&M, &M, &M, &M),
        r: Randomness,
    ) -> Commitment {
        let comm1 =
            HalfBinding::bind(&pp.inner, ck.inner_ck, (msg.0, msg.1), r.inner);
        let comm2 =
            HalfBinding::bind(&pp.inner, ck.inner_ck, (msg.2, msg.3), r.inner);
        HalfBinding::bind(&pp.outer, ck.outer_ck, (&comm1, &comm2), r.outer)
    }

    pub fn equiv<M: Message + ?Sized>(
        pp: &PublicParams,
        ek: &EquivKey,
        old: (&M, &M, &M, &M),
        new: (&M, &M, &M, &M),
        old_aux: Randomness,
    ) -> Randomness {
        // Pattern match parameters
        let EquivKey {
            inner_ek,
            outer_ek,
            binding_info: (binding_index, inner_side, outer_side),
        } = ek;
        let mdefault = &M::default();
        let inner_vec = match binding_index {
            BindingIndex::One => match inner_side {
                Side::One => (old.0, mdefault),
                Side::Two => (mdefault, old.0),
            },
            BindingIndex::Two => match inner_side {
                Side::One => (old.1, mdefault),
                Side::Two => (mdefault, old.1),
            },
            BindingIndex::Three => match inner_side {
                Side::One => (old.2, mdefault),
                Side::Two => (mdefault, old.2),
            },
            BindingIndex::Four => match inner_side {
                Side::One => (old.3, mdefault),
                Side::Two => (mdefault, old.3),
            },
        };
        let inner_new = Self::inner_new(new, outer_side);
        let new_inner_aux =
            HalfBinding::equiv(inner_ek, inner_vec, inner_new, old_aux.inner);
        // Recompute outer vector from inner vector (which is old)
        // but with new inner aux randomness
        let inner_comm = HalfBinding::bind(
            &pp.inner,
            inner_ek.commit_key,
            inner_vec,
            new_inner_aux,
        );
        let mut outer_vec = (&Commitment::default(), &Commitment::default());
        match outer_side {
            Side::One => outer_vec.0 = &inner_comm,
            Side::Two => outer_vec.1 = &inner_comm,
        };
        // Commit to inner_new with new inner aux to get new outer
        // aux
        let new_inner_comm1 = HalfBinding::bind(
            &pp.inner,
            inner_ek.commit_key,
            (new.0, new.1),
            new_inner_aux,
        );
        let new_inner_comm2 = HalfBinding::bind(
            &pp.inner,
            inner_ek.commit_key,
            (new.2, new.3),
            new_inner_aux,
        );

        let new_outer_aux = HalfBinding::equiv(
            outer_ek,
            outer_vec,
            (&new_inner_comm1, &new_inner_comm2),
            old_aux.outer,
        );
        Randomness {
            inner: new_inner_aux,
            outer: new_outer_aux,
        }
    }

    fn inner_new<'a, M: Message + ?Sized>(
        new: (&'a M, &'a M, &'a M, &'a M),
        outer_side: &'a Side,
    ) -> (&'a M, &'a M) {
        match outer_side {
            Side::One => (new.0, new.1),
            Side::Two => (new.2, new.3),
        }
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::commitment_scheme::halfbinding;

    use super::*;

    #[test]
    fn test_qbinding() {
        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let aux = Randomness {
            inner: halfbinding::Randomness(
                Scalar::random(&mut ChaCha20Rng::from_entropy()),
                Scalar::random(&mut ChaCha20Rng::from_entropy()),
            ),
            outer: halfbinding::Randomness(
                Scalar::random(&mut ChaCha20Rng::from_entropy()),
                Scalar::random(&mut ChaCha20Rng::from_entropy()),
            ),
        };
        let m1 = "hello".as_bytes();
        let m2 = "world".as_bytes();
        let m3 = "this is a test".as_bytes();
        let m4 = "can you hear me?".as_bytes();
        let none = "".as_bytes();
        let msg = (&none, &none, &m3, &none);
        let msg_equiv = (&m1, &m2, &m3, &m4);
        let pp = QBinding::setup(rng);
        let (ck, ek) = QBinding::gen(&pp, BindingIndex::Three);
        let (comm_equivcom, _) = QBinding::equivcom(&pp, &ek, msg, Some(aux));
        // let comm_old_bind = QBinding::bind(&pp, ck, msg, aux);
        // assert_eq!(comm_old, comm_old_bind);

        let aux_new = QBinding::equiv(&pp, &ek, msg, msg_equiv, aux);
        let comm_bind = QBinding::bind(&pp, ck, msg_equiv, aux_new);
        assert_eq!(comm_equivcom, comm_bind);
    }
}
