//! Implementation of 1-of-2^q partially-binding vector
//! commitment from discrete log using halfbinding comitment
//! schemes
use std::rc::Rc;

pub use crate::commitment_scheme::comm::PartialBindingCommScheme;
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

    pub fn fold<A, F>(&self, init: A, fold: F) -> A
    where
        F: FnMut(A, usize) -> A,
    {
        (3..=self.q).fold(init, fold)
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
    type Msg<'a, M: Message + 'a> = Vec<Rc<M>>;

    /// Setup public parameters
    fn setup<R: CryptoRngCore>(&self, rng: &mut R) -> PublicParams {
        let base = PublicParams {
            inner: Inner::new(HalfBinding.setup(rng)),
            outer: HalfBinding.setup(rng),
        };
        self.fold(base, |inner, _| {
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
        let (inner_ck, inner_ek) = if self.is_base() {
            let (inner_ck, inner_ek) = HalfBinding.gen(
                pp.base_inner(),
                binding_index
                    .base_inner()
                    .unwrap(),
                rng,
            );

            (Inner::new(inner_ck), Inner::new(inner_ek))
        } else {
            // Recursive case
            let inner_side = binding_index.get_inner();
            let (inner_ck, inner_ek) =
                QBinding::new(self.q - 1).gen(&pp.extract(()), inner_side, rng);

            (inner_ck.compose(), inner_ek.compose())
        };

        let outer_side = binding_index.get_outer();
        let (outer_ck, outer_ek) =
            HalfBinding.gen(pp.get_outer(), outer_side, rng);
        let ck = CommitKey { inner_ck, outer_ck };

        (
            ck.clone(),
            EquivKey {
                inner_ek,
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
        msg: &Vec<Rc<M>>,
        aux: Option<Randomness>,
    ) -> (Commitment, Randomness) {
        let bound_index = ek
            .binding_index
            .index();

        let (inner_comm, inner_aux, outer_rand) = if self.is_base() {
            // Base case
            let (inner_rand, outer_rand) = match aux {
                Some(r) => (Some(*r.base_inner()), Some(*r.get_outer())),
                None => (None, None),
            };
            // Get sides from binding index
            let inner_side = ek
                .binding_index
                .base_inner()
                .unwrap();
            // Create vector for the base binding
            let mdefault = Rc::new(M::default());
            let message = match inner_side {
                Side::One => (msg[bound_index].clone(), mdefault),
                Side::Two => (mdefault, msg[bound_index].clone()),
            };
            // Get inner commitment and auxiliary randomness
            let (inner_comm, inner_aux) = HalfBinding.equivcom(
                pp.base_inner(),
                ek.base_inner(),
                &message,
                inner_rand,
            );

            (inner_comm, Inner::new(inner_aux), outer_rand)
        } else {
            // Recursive case
            let (inner_rand, outer_rand) = match aux {
                Some(r) => (Some(r.extract(())), Some(*r.get_outer())),
                None => (None, None),
            };
            // Initialise vector of legnth 2^(q-1) == length of the
            // inner commitment scheme
            let mdefault = Rc::new(M::default());
            let message: Vec<Rc<M>> = (0..self.inner_length())
                .map(|i| {
                    // get the raw value of the inner binding index
                    // from the current binding index
                    let inner_index = ek
                        .binding_index()
                        .get_inner_raw();
                    if i == inner_index {
                        msg[bound_index].clone()
                    } else {
                        mdefault.clone()
                    }
                })
                .collect();
            // Get the commitment recursively for the inner commitment
            // tree
            let (inner_comm, inner_aux) = QBinding::new(self.q - 1).equivcom(
                &pp.extract(()),
                &ek.extract(),
                &message,
                inner_rand,
            );

            (inner_comm, inner_aux.compose(), outer_rand)
        };

        // Create v_b which is deafult value except at the
        // binding index for B
        let def_comm = Rc::new(Commitment::default());
        let outer_vec = match ek
            .binding_index
            .get_outer()
        {
            Side::One => (Rc::new(inner_comm), def_comm),
            Side::Two => (def_comm, Rc::new(inner_comm)),
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
        msg: &Vec<Rc<M>>,
        r: &Randomness,
    ) -> Commitment {
        let (comm1, comm2) = if self.is_base() {
            // Base case
            let (pp, ck, r) =
                (pp.base_inner(), ck.base_inner(), r.base_inner());
            let comm1 =
                HalfBinding.bind(pp, ck, &(msg[0].clone(), msg[1].clone()), r);
            let comm2 =
                HalfBinding.bind(pp, ck, &(msg[2].clone(), msg[3].clone()), r);

            (comm1, comm2)
        } else {
            // Recursive case
            let inner_q = QBinding::new(self.q - 1);
            let (pp, ck, r) =
                (&pp.extract(()), &ck.extract(()), &r.extract(()));

            let comm1 =
                inner_q.bind(pp, ck, &msg[0..self.inner_length()].to_vec(), r);
            let comm2 =
                inner_q.bind(pp, ck, &msg[self.inner_length()..].to_vec(), r);

            (comm1, comm2)
        };

        return HalfBinding.bind(
            pp.get_outer(),
            ck.get_outer(),
            &(Rc::new(comm1), Rc::new(comm2)),
            r.get_outer(),
        );
    }

    fn equiv<'a, M: Message + ?Sized>(
        &self,
        pp: &PublicParams,
        ek: &EquivKey,
        old: &Vec<Rc<M>>,
        new: &Vec<Rc<M>>,
        old_aux: &Randomness,
    ) -> Randomness {
        let bound_index = ek
            .binding_index
            .index();
        let mdefault = Rc::new(M::default());

        let (inner_comm, new_comm1, new_comm2, new_inner_aux) = if self
            .is_base()
        {
            // Base case
            // Get sides from binding index
            let (inner_side, outer_side) = ek
                .binding_index
                .base_inner_outer();
            // Equivocate the inner commitment
            // First recreate the old inner message
            let old_inner_message = match inner_side {
                Side::One => (old[0].clone(), mdefault),
                Side::Two => (mdefault, old[1].clone()),
            };
            // Then determine the new inner message
            let new_inner_message = match outer_side {
                Side::One => (new[0].clone(), new[1].clone()),
                Side::Two => (new[2].clone(), new[3].clone()),
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
            let new_comm1 = HalfBinding.bind(
                pp,
                ck,
                &(new[0].clone(), new[1].clone()),
                &new_inner_aux,
            );
            let new_comm2 = HalfBinding.bind(
                pp,
                ck,
                &(new[2].clone(), new[3].clone()),
                &new_inner_aux,
            );

            (
                Rc::new(inner_comm),
                Rc::new(new_comm1),
                Rc::new(new_comm2),
                Inner::new(new_inner_aux),
            )
        } else {
            // Recursive case
            let inner_q = QBinding::new(self.q - 1);

            // We first equivocate the inner commitment
            // Start by recreating the old inner message
            let old_inner_message: Vec<Rc<M>> = (0..self.inner_length())
                .map(|i| {
                    // Get the raw value of the inner index with respect
                    // to the lower level commitment scheme
                    let inner_index = ek
                        .binding_index()
                        .get_inner_raw();
                    if i == inner_index {
                        old[bound_index].clone()
                    } else {
                        mdefault.clone()
                    }
                })
                .collect();

            // Then determine the new inner message by obtaining the
            // appropriate slice of the new message vector based on the
            // outer binding side
            let outer_side = ek
                .binding_index
                .get_outer();
            let chunk1 = new[0..self.inner_length()].to_vec();
            let chunk2 = new[self.inner_length()..].to_vec();
            let new_inner_message: &Vec<Rc<M>> = match outer_side {
                Side::One => &chunk1,
                Side::Two => &chunk2,
            };

            // Here we transform the current level components into inner
            // level components
            let (pp, ck, ek, old_aux) = (
                &pp.extract(()),
                &ek.ck()
                    .extract(()),
                &ek.extract(),
                &old_aux.extract(()),
            );

            // Here, we equivocate our old inner message with our new
            // inner message
            let new_inner_aux = inner_q.equiv(
                pp,
                ek,
                &old_inner_message,
                new_inner_message,
                old_aux,
            );

            // Recompute the inner commitment with new inner aux so that
            // we can recompute our outer level vector later
            let inner_comm =
                inner_q.bind(pp, ck, &old_inner_message, &new_inner_aux);

            // Commit to every chunk with the new auxiliary
            // randomness
            let new_comm1 = inner_q.bind(pp, ck, &chunk1, &new_inner_aux);
            let new_comm2 = inner_q.bind(pp, ck, &chunk2, &new_inner_aux);

            (
                Rc::new(inner_comm),
                Rc::new(new_comm1),
                Rc::new(new_comm2),
                new_inner_aux.compose(),
            )
        };

        // Recompute our outer level commitment vector with the new
        // inner commitment that has been equivocated
        let cdefault = Rc::new(Commitment::default());
        let old_outer_message = match ek
            .binding_index()
            .get_outer()
        {
            Side::One => (inner_comm, cdefault),
            Side::Two => (cdefault, inner_comm),
        };
        // Create our new outer message which we got by binding to
        // each chunk of our new message
        let new_outer_message = (new_comm1, new_comm2);
        // Equivocate the outer layer commitment vector
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
    fn sandbox() {
        let rng1 = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let rng2 = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let mdefault = Rc::new("default".as_bytes());
        let equiv = Rc::new("equiv".as_bytes());
        let bounded_msg = Rc::new("hello world".as_bytes());

        const Q1: usize = 2;
        const B: usize = 2;
        const Q2: usize = 3;
        let (qbinding1, binding_index1) = QBinding::init(Q1, B);
        let (qbinding2, binding_index2) = QBinding::init(Q2, B);

        let mut msg1 = Vec::with_capacity(1 << Q1);
        let mut msg_equiv1 = Vec::with_capacity(1 << Q1);
        for i in 0..binding_index1.length() {
            if i == B {
                msg1.push(bounded_msg.clone());
                msg_equiv1.push(bounded_msg.clone());
            } else {
                msg1.push(mdefault.clone());
                msg_equiv1.push(equiv.clone());
            }
        }
        let mut msg2 = Vec::with_capacity(1 << Q2);
        let mut msg_equiv2 = Vec::with_capacity(1 << Q2);
        for i in 0..binding_index2.length() {
            if i == B {
                msg2.push(bounded_msg.clone());
                msg_equiv2.push(bounded_msg.clone());
            } else {
                msg2.push(mdefault.clone());
                msg_equiv2.push(equiv.clone());
            }
        }
        let aux1 = Randomness::random(&mut rng1.clone(), Q1);
        let aux2 = Randomness {
            inner: aux1.compose(),
            outer: halfbinding::Randomness::random(&mut rng2.clone()),
        };
        let pp1 = qbinding1.setup(&mut rng1.clone());
        let pp2 = qbinding2.setup(&mut rng2.clone());
        assert!(pp1 == pp2.extract(()));
        let (ck1, ek1) = qbinding1.gen(&pp1, binding_index1, &mut rng1.clone());
        let (ck2, ek2) = qbinding2.gen(&pp2, binding_index2, &mut rng2.clone());
        assert!(ck1 == ck2.extract(()));
        assert!(ek1 == ek2.extract());
        let (comm_equivcom1, aux_old1) =
            qbinding1.equivcom(&pp1, &ek1, &msg1, Some(aux1));
        let (comm_equivcom2, aux_old2) =
            qbinding2.equivcom(&pp2, &ek2, &msg2, Some(aux2));
        assert!(aux_old1 == aux_old2.extract(()));
        let aux_new1 =
            qbinding1.equiv(&pp1, &ek1, &msg1, &msg_equiv1, &aux_old1);
        let aux_new2 =
            qbinding2.equiv(&pp2, &ek2, &msg2, &msg_equiv2, &aux_old2);
        assert!(aux_new1 == aux_new2.extract(()));
        let comm_bind1 = qbinding1.bind(&pp1, &ck1, &msg_equiv1, &aux_new1);
        let comm_bind2 = qbinding2.bind(&pp2, &ck2, &msg_equiv2, &aux_new2);
        assert_eq!(comm_equivcom1, comm_bind1);
        assert_eq!(comm_equivcom2, comm_bind2);
    }

    #[test]
    fn test_qbinding_recursive_works() {
        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let mdefault = Rc::new("default".as_bytes());
        let equiv = Rc::new("equiv".as_bytes());
        let bounded_msg = Rc::new("hello world".as_bytes());

        const Q: usize = 3;
        const B: usize = 2;
        let (qbinding, binding_index) = QBinding::init(Q, B);
        let mut msg = Vec::with_capacity(1 << Q);
        let mut msg_equiv = Vec::with_capacity(1 << Q);
        for i in 0..binding_index.length() {
            if i == B {
                msg.push(bounded_msg.clone());
                msg_equiv.push(bounded_msg.clone());
            } else {
                msg.push(mdefault.clone());
                msg_equiv.push(equiv.clone());
            }
        }
        let aux = Randomness::random(&mut rng.clone(), Q);
        let pp = qbinding.setup(&mut rng.clone());
        let (ck, ek) = qbinding.gen(&pp, binding_index, &mut rng.clone());

        let (comm_equivcom, aux_old) =
            qbinding.equivcom(&pp, &ek, &msg, Some(aux));
        let aux_new = qbinding.equiv(&pp, &ek, &msg, &msg_equiv, &aux_old);
        let comm_bind = qbinding.bind(&pp, &ck, &msg_equiv, &aux_new);
        assert_eq!(comm_equivcom, comm_bind);
    }

    #[test]
    fn test_qbinding_base_works() {
        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let m1 = Rc::new("hello".as_bytes());
        let m2 = Rc::new("world".as_bytes());
        let m3 = Rc::new("this is a test".as_bytes());
        let m4 = Rc::new("can you hear me?".as_bytes());
        let none = Rc::new("".as_bytes());
        let msg = vec![none.clone(), none.clone(), m3.clone(), none];
        let msg_equiv = vec![m1, m2, m3, m4];

        const Q: usize = 2;
        let (qbinding, binding_index) = QBinding::init(Q, 2);
        let aux = Randomness::random(rng, Q);
        let pp = qbinding.setup(rng);
        let (ck, ek) = qbinding.gen(&pp, binding_index, rng);

        let (comm_equivcom, aux) =
            qbinding.equivcom(&pp, &ek, &msg, Some(aux.clone()));
        let aux_new = qbinding.equiv(&pp, &ek, &msg, &msg_equiv, &aux);
        let comm_bind = qbinding.bind(&pp, &ck, &msg_equiv, &aux_new);
        assert_eq!(comm_equivcom, comm_bind);
    }

    #[test]
    fn test_qbinding_base_fails_when_equiv_vs_bind_msg_differs() {
        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let m1 = Rc::new("hello".as_bytes());
        let m2 = Rc::new("world".as_bytes());
        let m3 = Rc::new("this is a test".as_bytes());
        let m4 = Rc::new("can you hear me?".as_bytes());
        let none = Rc::new("".as_bytes());
        let msg = vec![none.clone(), none.clone(), m3.clone(), none];
        let msg_equiv = vec![m1, m2, m3, m4];

        const Q: usize = 2;
        let (qbinding, binding_index) = QBinding::init(Q, 2);
        let aux = Randomness::random(rng, Q);
        let pp = qbinding.setup(rng);
        let (ck, ek) = qbinding.gen(&pp, binding_index, rng);

        let (comm_equivcom, aux) =
            qbinding.equivcom(&pp, &ek, &msg, Some(aux.clone()));
        let aux_new = qbinding.equiv(&pp, &ek, &msg, &msg_equiv, &aux);
        let comm_bind = qbinding.bind(&pp, &ck, &msg, &aux_new);
        assert_ne!(comm_equivcom, comm_bind);
    }

    #[test]
    fn test_qbinding_fails_when_bound_msg_changes() {
        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let m1 = Rc::new("hello".as_bytes());
        let m2 = Rc::new("world".as_bytes());
        let m3 = Rc::new("this is a test".as_bytes());
        let m4 = Rc::new("can you hear me?".as_bytes());
        let none = Rc::new("".as_bytes());
        let msg = vec![m1.clone(), m2.clone(), none.clone(), none];
        let msg_equiv = vec![m1, m2, m3, m4];

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
