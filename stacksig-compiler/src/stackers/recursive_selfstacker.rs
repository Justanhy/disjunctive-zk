use std::fmt;
use std::io::Write;
use std::marker::PhantomData;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::CryptoRngCore;
use sigmazk::{EHVzk, SigmaProtocol};

use crate::commitment_scheme::comm::PartialBindingCommScheme;
use crate::commitment_scheme::halfbinding::{
    CommitKey, Commitment, EquivKey, HalfBinding, PublicParams, Randomness,
    Side,
};
use crate::commitment_scheme::qbinding::BindingIndex;
use crate::stackable::{Challenge, Message, Stackable};

#[derive(Debug)]
pub struct SelfStacker<S: Stackable>(PhantomData<S>);

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Binding {
    pub inner: Side,
    pub outer: Option<Side>,
}

impl From<BindingIndex> for Binding {
    fn from(binding_index: BindingIndex) -> Self {
        match binding_index {
            BindingIndex::One => Binding {
                inner: Side::One,
                outer: Some(Side::One),
            },
            BindingIndex::Two => Binding {
                inner: Side::Two,
                outer: Some(Side::One),
            },
            BindingIndex::Three => Binding {
                inner: Side::One,
                outer: Some(Side::Two),
            },
            BindingIndex::Four => Binding {
                inner: Side::Two,
                outer: Some(Side::Two),
            },
        }
    }
}

impl From<Side> for Binding {
    fn from(side: Side) -> Self {
        Binding {
            inner: side,
            outer: None,
        }
    }
}

pub struct StackedStatement<S: Stackable> {
    pub pp: PublicParams,
    one: S::Statement,
    two: S::Statement,
    // three: S::Statement,
    // four: S::Statement,
}

impl<S: Stackable> StackedStatement<S> {
    pub fn new(
        pp: &PublicParams,
        one: S::Statement,
        two: S::Statement,
        // three: S::Statement,
        // four: S::Statement,
    ) -> Self {
        StackedStatement {
            pp: pp.clone(),
            one,
            two,
        }
    }

    fn one(&self) -> &S::Statement {
        &self.one
    }

    fn two(&self) -> &S::Statement {
        &self.two
    }

    pub fn bound_statement(&self, binding: &Side) -> &S::Statement {
        match binding {
            Side::One => return self.one(),
            Side::Two => return self.two(),
        }
    }

    // fn three(&self) -> &S::Statement {
    //     &self.three
    // }

    // fn four(&self) -> &S::Statement {
    //     &self.four
    // }

    // pub fn bound_statement(&self, binding: &Binding) ->
    // &S::Statement {     let Binding { outer, inner } =
    // binding;

    //     if outer.is_some() {
    //         let outer = outer.unwrap();
    //         match (inner, outer) {
    //             (Side::One, Side::One) => return self.one(),
    //             (Side::Two, Side::One) => return self.two(),
    //             (Side::One, Side::Two) => return
    // self.three(),             (Side::Two, Side::Two) =>
    // return self.four(),         }
    //     } else {
    //         match inner {
    //             Side::One => return self.one(),
    //             Side::Two => return self.two(),
    //         }
    //     }
    // }
}

#[derive(Debug, PartialEq)]
pub struct StackedWitness<W> {
    nested_witness: W,
    binding: Side,
}

impl<W> StackedWitness<W> {
    pub fn init(nested_witness: W, binding: Side) -> Self {
        StackedWitness {
            nested_witness,
            binding,
        }
    }
}

#[derive(PartialEq)]
pub struct StackedZ<S: Stackable> {
    ck: CommitKey,
    message: S::MessageZ,
    aux: Randomness,
}

impl<S: Stackable> fmt::Debug for StackedZ<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StackedZ")
            .field("ck (CommitKey)", &self.ck)
            .field("z (MessageZ)", &self.message)
            .field("r (Scalar)", &self.aux)
            .finish()
    }
}

impl<S: Stackable> Default for StackedZ<S> {
    fn default() -> Self {
        StackedZ {
            ck: CommitKey::default(),
            message: S::MessageZ::default(),
            aux: Randomness::random(&mut ChaCha20Rng::from_entropy()),
        }
    }
}

impl<S: Stackable> Message for StackedZ<S> {
    fn write<W: Write>(&self, writer: &mut W) {
        self.ck
            .write(writer);
        self.message
            .write(writer);
    }
}

#[derive(Debug, PartialEq)]
pub struct StackedState<S: Stackable> {
    nested_state: S::State,
    message: S::MessageA,
    ck: CommitKey,
    ek: EquivKey,
    aux: Randomness,
}

#[derive(Debug, Default, PartialEq)]
pub struct StackedA(CommitKey, Commitment);

impl Message for StackedA {
    fn write<W: Write>(&self, writer: &mut W) {
        self.0
            .write(writer);
        self.1
            .write(writer);
    }
}

impl<S: Stackable> Stackable for SelfStacker<S> {
    // type CommScheme = HalfBinding;
    const CLAUSES: usize = S::CLAUSES * 2;
}

impl<S: Stackable> SigmaProtocol for SelfStacker<S> {
    type Statement = StackedStatement<S>;
    type Witness = StackedWitness<S::Witness>;
    type State = StackedState<S>;
    type MessageA = StackedA;
    type Challenge = S::Challenge;
    type MessageZ = StackedZ<S>;
    type ProverContext = S::ProverContext;

    fn first<R: CryptoRngCore>(
        statement: &StackedStatement<S>,
        witness: &StackedWitness<S::Witness>,
        prover_rng: &mut R, /* TODO: Check if we need to split
                             * it as mentioned in
                             * the paper */
        prover_context: &S::ProverContext,
    ) -> (Self::State, Self::MessageA) {
        let StackedWitness {
            nested_witness,
            binding,
        } = witness;

        let (nested_state, message) = S::first(
            statement.bound_statement(binding),
            nested_witness,
            prover_rng,
            prover_context,
        );

        // We appear to reuse the same prover_rng but it is mutated
        // and thus different. Still, the change is deterministic.
        let (ck, ek) =
            HalfBinding::gen(&statement.pp, (*binding).into(), prover_rng);

        // Derive auxiliary value from prover's rng
        let aux = Randomness::random(prover_rng);

        let def = &S::MessageA::default();
        let v = match binding {
            Side::One => (&message, def),
            Side::Two => (def, &message),
        };
        // let v = if binding
        //     .outer
        //     .is_some()
        // {
        //     let binding_index: BindingIndex = (*binding).into();
        //     match binding_index {
        //         BindingIndex::One => (&message, def, def, def),
        //         BindingIndex::Two => (def, &message, def, def),
        //         BindingIndex::Three => (def, def, &message, def),
        //         BindingIndex::Four => (def, def, def, &message),
        //     }
        // } else {
        //     match binding.inner {
        //         Side::One => (&message, def, def, def),
        //         Side::Two => (def, &message, def, def),
        //     }
        // };

        let (comm, aux) =
            HalfBinding::equivcom(&statement.pp, &ek, v, Some(aux));
        (
            StackedState {
                nested_state,
                message,
                ck,
                ek,
                aux,
            },
            StackedA(ck, comm),
        )
    }

    fn second<R: CryptoRngCore>(verifier_rng: &mut R) -> Self::Challenge
    where
        Self: Sized,
    {
        let mut buffer = [0u8; 64];
        verifier_rng.fill_bytes(&mut buffer);
        Challenge::new(&buffer)
    }

    fn third<R: CryptoRngCore>(
        statement: &Self::Statement,

        state: &Self::State,
        witness: &Self::Witness,
        challenge: &Self::Challenge,
        prover_rng: &mut R,
        prover_context: &S::ProverContext,
    ) -> Self::MessageZ {
        let StackedState {
            nested_state,
            message: a,
            ck,
            ek,
            aux,
        } = state;

        let StackedWitness {
            nested_witness,
            binding,
        } = witness;
        // let binding_index: BindingIndex = (*binding).into();

        let nested_z = S::third(
            statement.bound_statement(binding),
            nested_state,
            nested_witness,
            challenge,
            prover_rng,
            prover_context,
        );

        let def = &S::MessageA::default();
        let v_old = match binding {
            Side::One => (a, def),
            Side::Two => (def, a),
        };
        // let v_old = match binding_index {
        //     BindingIndex::One => (a, def, def, def),
        //     BindingIndex::Two => (def, a, def, def),
        //     BindingIndex::Three => (def, def, a, def),
        //     BindingIndex::Four => (def, def, def, a),
        // };

        let one = || S::simulate(statement.one(), challenge, &nested_z);
        let two = || S::simulate(statement.two(), challenge, &nested_z);
        // let three = || S::simulate(statement.three(), challenge,
        // &nested_z); let four = ||
        // S::simulate(statement.four(), challenge, &nested_z);
        let temp = match binding {
            Side::One => two(),
            Side::Two => one(),
        };
        let v = match binding {
            Side::One => (a, &temp),
            Side::Two => (&temp, a),
        };
        // let temp = match binding_index {
        //     BindingIndex::One => (two(), three(), four()),
        //     BindingIndex::Two => (one(), three(), four()),
        //     BindingIndex::Three => (one(), two(), four()),
        //     BindingIndex::Four => (one(), two(), three()),
        // };

        // let v = match binding_index {
        //     BindingIndex::One => (a, &temp.0, &temp.1, &temp.2),
        //     BindingIndex::Two => (&temp.0, a, &temp.1, &temp.2),
        //     BindingIndex::Three => (&temp.0, &temp.1, a,
        // &temp.2),     BindingIndex::Four => (&temp.0,
        // &temp.1, &temp.2, a), };

        let aux_new = HalfBinding::equiv(&statement.pp, ek, v_old, v, aux);
        StackedZ {
            ck: *ck,
            message: nested_z,
            aux: aux_new,
        }
    }

    fn verify(
        statement: &Self::Statement,
        a: &Self::MessageA,
        c: &Self::Challenge,
        z: &Self::MessageZ,
    ) -> bool
    where
        Self: Sized,
    {
        let StackedA(ck_a, comm) = a;
        let StackedZ {
            ck: ck_z,
            message,
            aux,
        } = z;
        let v = (
            &S::simulate(statement.one(), c, &message),
            &S::simulate(statement.two(), c, &message),
        );

        let comm_check = HalfBinding::bind(&statement.pp, *ck_a, v, *aux);
        let nested_check = S::verify(statement.one(), v.0, c, &message)
            && S::verify(statement.two(), v.1, c, &message);

        ck_a == ck_z && *comm == comm_check && nested_check
    }
}

impl<S: Stackable> EHVzk for SelfStacker<S> {
    fn simulate(
        // precom: &S::Precompute,
        statement: &StackedStatement<S>,
        challenge: &S::Challenge,
        z: &StackedZ<S>,
    ) -> Self::MessageA {
        let one = S::simulate(statement.one(), challenge, &z.message);
        let two = S::simulate(statement.two(), challenge, &z.message);
        // let three = S::simulate(statement.three(), challenge,
        // &z.message); let four =
        // S::simulate(statement.four(), challenge, &z.message);

        let comm = HalfBinding::bind(&statement.pp, z.ck, (&one, &two), z.aux);
        StackedA(z.ck, comm)
    }
}
