//! Implementation of 1-of-2^q partially-binding vector commitment
//! from discrete log using halfbinding comitment schemes

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
    pub a: super::halfbinding::PublicParams,
    pub b: super::halfbinding::PublicParams,
}

#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub struct CommitKey {
    pub a: super::halfbinding::CommitKey,
    pub b: super::halfbinding::CommitKey,
}

#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub struct Randomness {
    pub a: super::halfbinding::Randomness,
    pub b: super::halfbinding::Randomness,
}

#[derive(Clone, Debug, PartialEq, Hash)]
pub struct EquivKey {
    pub a: super::halfbinding::EquivKey,
    pub b: super::halfbinding::EquivKey,
    pub binding_info: (BindingIndex, Side, Side),
}

/// Implementation of 1-of-2^2 partially-binding vector commitment
/// from discrete log using 2 halfbinding comitment schemes.
///
/// We can obtain a 1-of-2^q partially-binding vector commitment by using
/// this iteratively.
impl QBinding {
    /// Setup public parameters
    pub fn setup<R: CryptoRngCore>(rng: &mut R) -> PublicParams {
        let a = HalfBinding::setup(rng);
        let b = HalfBinding::setup(rng);
        PublicParams { a, b }
    }

    /// Generate commitment key and equivocation key
    pub fn gen(
        pp: PublicParams,
        binding_index: BindingIndex,
    ) -> (CommitKey, EquivKey) {
        let (ia, ib) = match binding_index {
            // According to the formula in the paper
            // ia = i mod la and ib = floor(i / la)
            // in our case la = 2
            BindingIndex::One => (Side::One, Side::One),
            BindingIndex::Two => (Side::Two, Side::One),
            BindingIndex::Three => (Side::One, Side::Two),
            BindingIndex::Four => (Side::Two, Side::Two),
        };
        let (cka, eka) = HalfBinding::gen(&pp.a, ia);
        let (ckb, ekb) = HalfBinding::gen(&pp.b, ib);
        (
            CommitKey { a: cka, b: ckb },
            EquivKey {
                a: eka,
                b: ekb,
                binding_info: (binding_index, ia, ib),
            },
        )
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
    pub fn equivcom<M: Message>(
        pp: &PublicParams,
        ek: &EquivKey,
        msg: (&M, &M, &M, &M),
    ) -> (Commitment, Randomness) {
        let EquivKey {
            a: eka,
            b: ekb,
            binding_info: (binding_index, ia, ib),
        } = ek;
        // Create v_a which is None except at the binding index for A
        let v_a = Self::inner(binding_index, msg, ia);
        // Commit to v_a
        let (ca, ra) = HalfBinding::equivcom(&pp.a, eka, v_a, None);
        // Create v_b which is None except at the binding index for B
        let mut v_b: (Option<&Commitment>, Option<&Commitment>) = (None, None);
        match ib {
            Side::One => v_b.0 = Some(&ca),
            Side::Two => v_b.1 = Some(&ca),
        };
        // Commit to v_b
        let (cb, rb) = HalfBinding::equivcom(&pp.b, ekb, v_b, None);
        (cb, Randomness { a: ra, b: rb })
    }

    pub fn bind<M: Message>(
        pp: &PublicParams,
        ck: CommitKey,
        msg: (&M, &M, &M, &M),
        r: Randomness,
    ) -> Commitment {
        let v_b1 =
            HalfBinding::bind(&pp.a, ck.a, (Some(msg.0), Some(msg.1)), r.a);
        let v_b2 =
            HalfBinding::bind(&pp.a, ck.a, (Some(msg.2), Some(msg.3)), r.a);
        HalfBinding::bind(&pp.b, ck.b, (Some(&v_b1), Some(&v_b2)), r.b)
    }

    pub fn equiv<M: Message>(
        pp: &PublicParams,
        ek: &EquivKey,
        old: (&M, &M, &M, &M),
        new: (&M, &M, &M, &M),
        aux: Randomness,
    ) -> Randomness {
        let EquivKey {
            a: eka,
            b: ekb,
            binding_info: (binding_index, ia, ib),
        } = ek;
        let v_a = Self::inner(binding_index, old, ia);
        let v_a_new = Self::inner_new(new, ib);
        let ra = HalfBinding::equiv(eka, v_a, v_a_new, aux.a);
        // Recompute v_b from v_a (which is old) but with new ra
        let binding = HalfBinding::bind(&pp.a, eka.commit_key, v_a, ra);
        let v_b = match ib {
            Side::One => (Some(&binding), None),
            Side::Two => (None, Some(&binding)),
        };
        // Commit to v_a_new with ra to get v_b_new
        let v_b1 = HalfBinding::bind(
            &pp.a,
            eka.commit_key,
            (Some(new.0), Some(new.1)),
            ra,
        );
        let v_b2 = HalfBinding::bind(
            &pp.a,
            eka.commit_key,
            (Some(new.2), Some(new.3)),
            ra,
        );

        let rb =
            HalfBinding::equiv(ekb, v_b, (Some(&v_b1), Some(&v_b2)), aux.b);
        Randomness { a: ra, b: rb }
    }

    fn inner<'a, M: Message>(
        binding_index: &BindingIndex,
        msg: (&'a M, &'a M, &'a M, &'a M),
        inner_side: &Side,
    ) -> (Option<&'a M>, Option<&'a M>) {
        match binding_index {
            BindingIndex::One => match inner_side {
                Side::One => (Some(msg.0), None),
                Side::Two => (None, Some(msg.0)),
            },
            BindingIndex::Two => match inner_side {
                Side::One => (Some(msg.1), None),
                Side::Two => (None, Some(msg.1)),
            },
            BindingIndex::Three => match inner_side {
                Side::One => (Some(msg.2), None),
                Side::Two => (None, Some(msg.2)),
            },
            BindingIndex::Four => match inner_side {
                Side::One => (Some(msg.3), None),
                Side::Two => (None, Some(msg.3)),
            },
        }
    }

    fn inner_new<'a, M: Message>(
        new: (&'a M, &'a M, &'a M, &'a M),
        outer_side: &'a Side,
    ) -> (Option<&'a M>, Option<&'a M>) {
        match outer_side {
            Side::One => (Some(new.0), Some(new.1)),
            Side::Two => (Some(new.2), Some(new.3)),
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn test_qbinding() {
        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
    }
}
