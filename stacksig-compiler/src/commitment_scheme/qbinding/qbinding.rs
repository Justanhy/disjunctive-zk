//! Implementation of 1-of-2^q partially-binding vector
//! commitment from discrete log using halfbinding comitment
//! schemes
use crate::commitment_scheme::comm::PartialBindingCommScheme;
use crate::commitment_scheme::halfbinding::{Commitment, HalfBinding};

use super::*;

pub struct QBinding {
    pub q: usize,
}

impl QBinding {
    pub fn new(q: usize) -> Self {
        assert!(q >= MIN_Q);
        QBinding { q }
    }

    /// Initialise a new 1-of-2^q partially-binding
    /// commitment scheme together with a binding index
    /// that is compatible with it
    ///
    /// # Parameters
    /// `q`: the q in 1-of-2^q
    /// `index`: the 0-indexed binding position of the
    /// commitment scheme
    pub fn init(q: usize, index: usize) -> (Self, BindingIndex) {
        let scheme = QBinding::new(q);
        let binding_index = BindingIndex::new(q, index);
        (scheme, binding_index)
    }

    pub fn is_base(&self) -> bool {
        self.q == MIN_Q
    }

    pub fn inner_length(&self) -> usize {
        1 << (self.q - 1)
    }

    fn setupgen<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        binding_index: BindingIndex,
    ) -> (PublicParams, CommitKey, EquivKey) {
        let pp = self.setup(rng);
        let (ck, ek) = self.gen(&pp, binding_index, rng);
        (pp, ck, ek)
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
/// Implementation of 1-of-2^2 partially-binding vector
/// commitment from discrete log using 2 halfbinding
/// comitment schemes.
///
/// We can obtain a 1-of-2^q partially-binding vector
/// commitment by using this iteratively.
impl PartialBindingCommScheme for QBinding {
    type PublicParams = PublicParams;
    type BindingIndex = BindingIndex;
    type CommitKey = CommitKey;
    type EquivKey = EquivKey;
    type Commitment = Commitment;
    type Randomness = Randomness;
    type Msg<'a, M: Message + 'a> = Vec<&'a M>;

    /// Setup public parameters
    fn setup<R: CryptoRngCore>(&self, rng: &mut R) -> PublicParams {
        let base = PublicParams {
            inner: Inner::new(HalfBinding.setup(rng)),
            outer: HalfBinding.setup(rng),
        };
        (3..=self.q).fold(base, |inner, i| {
            // dbg!(i);
            let outer = HalfBinding.setup(rng);
            PublicParams {
                inner: inner.compose(),
                outer,
            }
        })
        // if self.is_base() {
        //     return PublicParams {
        //         inner:
        // Inner::new(HalfBinding.setup(rng)),
        //         outer: HalfBinding.setup(rng),
        //     };
        // }
        // let inner_pp = QBinding::new(self.q -
        // 1).setup(rng);

        // PublicParams {
        //     inner: inner_pp.compose(),
        //     outer: HalfBinding.setup(rng),
        // }
    }

    /// Generate commitment key and equivocation key
    fn gen<R: CryptoRngCore>(
        &self,
        pp: &PublicParams,
        binding_index: BindingIndex,
        rng: &mut R,
    ) -> (CommitKey, EquivKey) {
        // Base case
        if self.is_base() {
            let (inner_side, outer_side) = binding_index.base_inner_outer();
            let (inner_ck, inner_ek) =
                HalfBinding.gen(pp.base_inner(), inner_side, rng);
            let (outer_ck, outer_ek) =
                HalfBinding.gen(pp.get_outer(), outer_side, rng);
            let inner_ck = Inner::new(inner_ck);
            let ck = CommitKey { inner_ck, outer_ck };

            return (
                ck.clone(),
                EquivKey {
                    inner_ek: Inner::new(inner_ek),
                    ck,
                    outer_ek,
                    binding_index,
                },
            );
        }

        // Recursive case
        let inner_pp = pp.unroll(());
        let (inner_side, outer_side) = binding_index.get_inner_outer();
        let (inner_ck, inner_ek) =
            QBinding::new(self.q - 1).gen(&inner_pp, inner_side, rng);
        let (outer_ck, outer_ek) =
            HalfBinding.gen(pp.get_outer(), outer_side, rng);
        let inner_ck = inner_ck.compose();
        let ck = CommitKey { inner_ck, outer_ck };

        (
            ck.clone(),
            EquivKey {
                inner_ek: inner_ek.compose(),
                ck,
                outer_ek,
                binding_index,
            },
        )
    }

    /// Given equivocation key, commit to a vector of
    /// messages of length 2^q ## Parameters
    /// `pp`: Public parameters
    /// `ek`: Equivocation key
    /// `msg`: Message to commit to
    ///
    /// ## Returns
    /// Commitment and randomness
    fn equivcom<'a, M: Message + ?Sized>(
        &self,
        pp: &PublicParams,
        ek: &EquivKey,
        msg: &Vec<&'a M>,
        aux: Option<Randomness>,
    ) -> (Commitment, Randomness) {
        // dbg!("Committing", self.q);
        let (inner_rand, outer_rand) = match aux {
            Some(r) => {
                let inner = r.unroll(());
                let outer = *r.get_outer();
                (Some(inner), Some(outer))
            }
            None => (None, None),
        };
        let bound_index = ek
            .binding_index
            .index();

        let (inner_comm, inner_aux) = if self.is_base() {
            // Base case
            // Get sides from binding index
            let inner_side = ek
                .binding_index
                .base_inner()
                .unwrap();
            // Get base randomness
            let inner_rand = inner_rand.map(|r| *r.base_inner());
            // Create vector for the base binding
            let mdefault = M::default();
            let message = match inner_side {
                Side::One => (msg[bound_index], &mdefault),
                Side::Two => (&mdefault, msg[bound_index]),
            };
            // Get inner commitment and auxiliary randomness
            let (inner_comm, inner_aux) = HalfBinding.equivcom(
                pp.base_inner(),
                ek.base_inner(),
                &message,
                inner_rand,
            );

            (inner_comm, Inner::new(inner_aux))
        } else {
            // Recursive case
            // Get inner binding and outer side
            let inner_binding = ek
                .binding_index
                .get_inner();
            // Initialise vector of legnth 2^(q-1) == length of the
            // inner commitment scheme
            let mdefault = M::default();
            let message: Vec<&M> = (0..self.inner_length())
                .map(|i| {
                    if i == inner_binding.get_inner_raw() {
                        msg[bound_index]
                    } else {
                        &mdefault
                    }
                })
                .collect();
            // Get the commitment recursively for the inner commitment
            // tree
            let (inner_comm, inner_aux) = QBinding::new(self.q - 1).equivcom(
                &pp.unroll(()),
                &ek.unroll(),
                &message,
                inner_rand,
            );

            (inner_comm, inner_aux.compose())
        };

        // Create v_b which is deafult value except at the
        // binding index for B
        let mut outer_vec: (&Commitment, &Commitment) =
            (&Commitment::default(), &Commitment::default());
        match ek
            .binding_index
            .get_outer()
        {
            Side::One => outer_vec.0 = &inner_comm,
            Side::Two => outer_vec.1 = &inner_comm,
        };
        // Commit to v_b
        let (outer_comm, outer_aux) = HalfBinding.equivcom(
            pp.get_outer(),
            ek.get_outer(),
            &outer_vec,
            outer_rand,
        );

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
    fn bind<'a, M: Message + ?Sized>(
        &self,
        pp: &PublicParams,
        ck: &CommitKey,
        msg: &Vec<&'a M>,
        r: &Randomness,
    ) -> Commitment {
        // dbg!(self.q);
        let (comm1, comm2) = if self.is_base() {
            // Base case
            let (pp, ck, r) =
                (pp.base_inner(), ck.base_inner(), r.base_inner());
            let comm1 = HalfBinding.bind(pp, ck, &(msg[0], msg[1]), r);
            let comm2 = HalfBinding.bind(pp, ck, &(msg[2], msg[3]), r);

            (comm1, comm2)
        } else {
            // Recursive case
            let inner_q = QBinding::new(self.q - 1);
            let (pp, ck, r) = (&pp.unroll(()), &ck.unroll(()), &r.unroll(()));

            let comm1 =
                inner_q.bind(pp, ck, &msg[0..self.inner_length()].to_vec(), r);
            let comm2 =
                inner_q.bind(pp, ck, &msg[self.inner_length()..].to_vec(), r);

            (comm1, comm2)
        };

        return HalfBinding.bind(
            pp.get_outer(),
            ck.get_outer(),
            &(&comm1, &comm2),
            r.get_outer(),
        );
    }

    fn equiv<'a, M: Message + ?Sized>(
        &self,
        pp: &PublicParams,
        ek: &EquivKey,
        old: &Vec<&'a M>,
        new: &Vec<&'a M>,
        old_aux: &Randomness,
    ) -> Randomness {
        // dbg!("Equivocating", self.q);
        let bound_index = ek
            .binding_index
            .index();
        let mdefault = M::default();

        let (inner_comm, new_comm1, new_comm2, new_inner_aux) = if self
            .is_base()
        {
            // dbg!("Base case");
            // Base case
            // Get sides from binding index
            let (inner_side, outer_side) = ek
                .binding_index
                .base_inner_outer();
            // Equivocate the inner commitment
            // First recreate the old inner message
            let old_inner_message = match inner_side {
                Side::One => (old[0], &mdefault),
                Side::Two => (&mdefault, old[1]),
            };
            // Then determine the new inner message
            let new_inner_message = match outer_side {
                Side::One => (new[0], new[1]),
                Side::Two => (new[2], new[3]),
            };
            let (pp, ck, ek, old_aux) = (
                pp.base_inner(),
                &ek.base_inner()
                    .commit_key,
                ek.base_inner(),
                old_aux.base_inner(),
            );
            // Compute a new auxiliary variable for inner
            // commitment scheme
            let new_inner_aux = HalfBinding.equiv(
                pp,
                ek,
                &old_inner_message,
                &new_inner_message,
                old_aux,
            );
            // Recompute the outer commitment
            let inner_comm =
                HalfBinding.bind(pp, ck, &old_inner_message, &new_inner_aux);
            // Commit to every chunk with the new auxiliary
            // randomness
            let new_comm1 =
                HalfBinding.bind(pp, ck, &(new[0], new[1]), &new_inner_aux);
            let new_comm2 =
                HalfBinding.bind(pp, ck, &(new[2], new[3]), &new_inner_aux);

            (inner_comm, new_comm1, new_comm2, Inner::new(new_inner_aux))
        } else {
            // dbg!("Recursive case");
            // Recursive case
            let inner_q = QBinding::new(self.q - 1);
            let (inner_binding, outer_side) = ek
                .binding_index
                .get_inner_outer();
            // Equivocate the inner commitment
            // First recreate the old inner message
            let old_inner_message: Vec<&M> = (0..self.inner_length())
                .map(|i| {
                    if i == inner_binding.get_inner_raw() {
                        old[bound_index]
                    } else {
                        &mdefault
                    }
                })
                .collect();
            // Then determine the new inner message
            let new_inner_message: Vec<&M> = match outer_side {
                Side::One => new[0..self.inner_length()].to_vec(),
                Side::Two => new[self.inner_length()..].to_vec(),
            };
            let (pp, ck, ek, old_aux) = (
                &pp.unroll(()),
                &ek.ck()
                    .unroll(()),
                &ek.unroll(),
                &old_aux.unroll(()),
            );
            // Compute a new auxiliary variable for inner
            // commitment scheme
            let new_inner_aux = inner_q.equiv(
                pp,
                ek,
                &old_inner_message,
                &new_inner_message,
                old_aux,
            );
            // Recompute the inner commitment with new inner aux
            let inner_comm =
                inner_q.bind(pp, ck, &old_inner_message, &new_inner_aux);
            // Commit to every chunk with the new auxiliary
            // randomness
            let new_comm1 =
                inner_q.bind(pp, ck, &new_inner_message, &new_inner_aux);
            let new_comm2 =
                inner_q.bind(pp, ck, &new_inner_message, &new_inner_aux);
            // dbg!("Recursive case done");

            (inner_comm, new_comm1, new_comm2, new_inner_aux.compose())
        };

        let cdefault = Commitment::default();
        let old_outer_message = match ek
            .binding_index()
            .get_outer()
        {
            Side::One => (&inner_comm, &cdefault),
            Side::Two => (&cdefault, &inner_comm),
        };
        let new_outer_message = (&new_comm1, &new_comm2);
        let new_outer_aux = HalfBinding.equiv(
            pp.get_outer(),
            ek.get_outer(),
            &old_outer_message,
            &new_outer_message,
            old_aux.get_outer(),
        );

        Randomness {
            inner: new_inner_aux,
            outer: new_outer_aux,
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn test_qbinding_recursive_works() {
        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let mdefault = "default".as_bytes();
        let equiv = "equiv".as_bytes();
        let bounded_msg = "hello world".as_bytes();

        const Q: usize = 7;
        const B: usize = 72;
        let (qbinding, binding_index) = QBinding::init(Q, B);
        let mut msg = Vec::with_capacity(1 << Q);
        // dbg!(msg.capacity());
        for i in 0..(1 << Q) {
            if i == B {
                msg.push(&bounded_msg);
            } else {
                msg.push(&mdefault);
            }
        }
        let mut msg_equiv = Vec::with_capacity(1 << Q);
        // dbg!(msg_equiv.capacity());
        for i in 0..(1 << Q) {
            if i == B {
                msg_equiv.push(&bounded_msg);
            } else {
                msg_equiv.push(&equiv);
            }
        }
        // dbg!("tesa");
        let aux = Randomness::random(rng, Q);
        // dbg!("Beginning setup");
        let pp = qbinding.setup(rng);
        // dbg!("Beginning keygen");
        let (ck, ek) = qbinding.gen(&pp, binding_index, rng);

        // dbg!("Beginning protocol");
        let (comm_equivcom, _) =
            qbinding.equivcom(&pp, &ek, msg.as_ref(), Some(aux.clone()));
        let aux_new = qbinding.equiv(&pp, &ek, &msg, &msg_equiv, &aux);
        // dbg!("Done");
        let comm_bind = qbinding.bind(&pp, &ck, &msg_equiv, &aux_new);
        assert_eq!(comm_equivcom, comm_bind);
    }

    #[test]
    fn test_qbinding_base_works() {
        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let m1 = "hello".as_bytes();
        let m2 = "world".as_bytes();
        let m3 = "this is a test".as_bytes();
        let m4 = "can you hear me?".as_bytes();
        let none = "".as_bytes();
        let msg = vec![&none, &none, &m3, &none];
        let msg_equiv = vec![&m1, &m2, &m3, &m4];

        const Q: usize = 2;
        let (qbinding, binding_index) = QBinding::init(Q, 2);
        let aux = Randomness::random(rng, Q);
        let pp = qbinding.setup(rng);
        let (ck, ek) = qbinding.gen(&pp, binding_index, rng);

        let (comm_equivcom, _) =
            qbinding.equivcom(&pp, &ek, &msg, Some(aux.clone()));
        let aux_new = qbinding.equiv(&pp, &ek, &msg, &msg_equiv, &aux);
        let comm_bind = qbinding.bind(&pp, &ck, &msg_equiv, &aux_new);
        assert_eq!(comm_equivcom, comm_bind);
    }

    #[test]
    fn test_qbinding_fails() {
        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let m1 = "hello".as_bytes();
        let m2 = "world".as_bytes();
        let m3 = "this is a test".as_bytes();
        let m4 = "can you hear me?".as_bytes();
        let none = "".as_bytes();
        let msg = vec![&m1, &m2, &none, &none];
        let msg_equiv = vec![&m1, &m2, &m3, &m4];

        const Q: usize = 2;
        let aux = Randomness::random(rng, Q);
        let (qbinding, binding_index) = QBinding::init(Q, 2);
        let pp = qbinding.setup(rng);
        let (ck, ek) = qbinding.gen(&pp, binding_index, rng);

        let (comm1, aux1) =
            qbinding.equivcom(&pp, &ek, &msg, Some(aux.clone()));
        let (comm2, aux2) = qbinding.equivcom(&pp, &ek, &msg_equiv, Some(aux));

        assert_ne!(comm1, comm2);

        let comm1_bind = qbinding.bind(&pp, &ck, &msg_equiv, &aux1);
        let comm2_bind = qbinding.bind(&pp, &ck, &msg, &aux2);

        assert_ne!(comm1_bind, comm2_bind);
    }
}
