use std::fmt;
use std::io::Write;
use std::marker::PhantomData;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::CryptoRngCore;
use sigmazk::{EHVzk, SigmaProtocol};

use crate::commitment_scheme::halfbinding::Commitment;
use crate::commitment_scheme::qbinding::{
    BindingIndex, CommitKey, EquivKey, PublicParams, QBinding, Randomness,
};
use crate::stackable::{Challenge, Message, Stackable};

#[derive(Debug)]
pub struct StackedSigma<S: Stackable>(PhantomData<S>);

pub struct StackedStatement<S: Stackable> {
    pp: PublicParams,
    one: S::Statement,
    two: S::Statement,
    three: S::Statement,
    four: S::Statement,
}

impl<S: Stackable> StackedStatement<S> {
    pub fn new(
        pp: &PublicParams,
        one: S::Statement,
        two: S::Statement,
        three: S::Statement,
        four: S::Statement,
    ) -> Self {
        StackedStatement {
            pp: pp.clone(),
            one,
            two,
            three,
            four,
        }
    }

    fn one(&self) -> &S::Statement {
        &self.one
    }

    fn two(&self) -> &S::Statement {
        &self.two
    }

    fn three(&self) -> &S::Statement {
        &self.three
    }

    fn four(&self) -> &S::Statement {
        &self.four
    }

    pub fn bound_statement(
        &self,
        binding_index: &BindingIndex,
    ) -> &S::Statement {
        match binding_index {
            BindingIndex::One => self.one(),
            BindingIndex::Two => self.two(),
            BindingIndex::Three => self.three(),
            BindingIndex::Four => self.four(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct StackedWitness<S: Stackable> {
    nested_witness: S::Witness,
    binding_index: BindingIndex,
}

impl<S: Stackable> StackedWitness<S> {
    pub fn init(
        nested_witness: S::Witness,
        binding_index: BindingIndex,
    ) -> Self {
        StackedWitness {
            nested_witness,
            binding_index,
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

impl<S: Stackable> Stackable for StackedSigma<S> {
    const CLAUSES: usize = S::CLAUSES * 2;
}

impl<S: Stackable> SigmaProtocol for StackedSigma<S> {
    type Statement = StackedStatement<S>;
    type Witness = StackedWitness<S>;
    type State = StackedState<S>;
    type MessageA = StackedA;
    type Challenge = S::Challenge;
    type MessageZ = StackedZ<S>;
    type ProverContext = S::ProverContext;
    // type Precompute = S::Precompute;

    // type MessageA = S::MessageA;
    // type Challenge = S::Challenge;
    // type MessageZ = S::MessageZ;
    // type State = S::State;

    fn first<R: CryptoRngCore>(
        statement: &StackedStatement<S>,
        witness: &StackedWitness<S>,
        prover_rng: &mut R, /* TODO: Check if we need to split
                             * it as mentioned in
                             * the paper */
        prover_context: &S::ProverContext,
    ) -> (Self::State, Self::MessageA) {
        let StackedWitness {
            nested_witness,
            binding_index,
        } = witness;
        let (nested_state, message) = S::first(
            statement.bound_statement(binding_index),
            nested_witness,
            prover_rng,
            prover_context,
        );

        let def = &S::MessageA::default();
        let v = match binding_index {
            BindingIndex::One => (&message, def, def, def),
            BindingIndex::Two => (def, &message, def, def),
            BindingIndex::Three => (def, def, &message, def),
            BindingIndex::Four => (def, def, def, &message),
        };
        let (ck, ek) = QBinding::gen(&statement.pp, *binding_index, prover_rng);

        // Derive auxiliary value from prover's rng
        let aux = Randomness::random(prover_rng);

        let (comm, aux) = QBinding::equivcom(&statement.pp, &ek, v, Some(aux));
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
            binding_index,
        } = witness;

        let nested_z = S::third(
            statement.bound_statement(binding_index),
            nested_state,
            nested_witness,
            challenge,
            prover_rng,
            prover_context,
        );

        let def = &S::MessageA::default();
        let v_old = match binding_index {
            BindingIndex::One => (a, def, def, def),
            BindingIndex::Two => (def, a, def, def),
            BindingIndex::Three => (def, def, a, def),
            BindingIndex::Four => (def, def, def, a),
        };

        let temp = match binding_index {
            BindingIndex::One => {
                let two = S::simulate(statement.two(), challenge, &nested_z);
                let three =
                    S::simulate(statement.three(), challenge, &nested_z);
                let four = S::simulate(statement.four(), challenge, &nested_z);
                (two, three, four)
            }
            BindingIndex::Two => {
                let one = S::simulate(statement.one(), challenge, &nested_z);
                let three =
                    S::simulate(statement.three(), challenge, &nested_z);
                let four = S::simulate(statement.four(), challenge, &nested_z);
                (one, three, four)
            }
            BindingIndex::Three => {
                let one = S::simulate(statement.one(), challenge, &nested_z);
                let two = S::simulate(statement.two(), challenge, &nested_z);
                let four = S::simulate(statement.four(), challenge, &nested_z);
                (one, two, four)
            }
            BindingIndex::Four => {
                let one = S::simulate(statement.one(), challenge, &nested_z);
                let two = S::simulate(statement.two(), challenge, &nested_z);
                let three =
                    S::simulate(statement.three(), challenge, &nested_z);
                (one, two, three)
            }
        };

        let v = match binding_index {
            BindingIndex::One => (a, &temp.0, &temp.1, &temp.2),
            BindingIndex::Two => (&temp.0, a, &temp.1, &temp.2),
            BindingIndex::Three => (&temp.0, &temp.1, a, &temp.2),
            BindingIndex::Four => (&temp.0, &temp.1, &temp.2, a),
        };

        let aux_new = QBinding::equiv(&statement.pp, ek, v_old, v, *aux);
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
            &S::simulate(statement.three(), c, &message),
            &S::simulate(statement.four(), c, &message),
        );

        let comm_check = QBinding::bind(&statement.pp, *ck_a, v, *aux);
        let nested_check = S::verify(statement.one(), v.0, c, &message)
            && S::verify(statement.two(), v.1, c, &message)
            && S::verify(statement.three(), v.2, c, &message)
            && S::verify(statement.four(), v.3, c, &message);

        ck_a == ck_z && *comm == comm_check && nested_check
    }
}

impl<S: Stackable> EHVzk for StackedSigma<S> {
    fn simulate(
        // precom: &S::Precompute,
        statement: &StackedStatement<S>,
        challenge: &S::Challenge,
        z: &StackedZ<S>,
    ) -> Self::MessageA {
        let one = S::simulate(statement.one(), challenge, &z.message);
        let two = S::simulate(statement.two(), challenge, &z.message);
        let three = S::simulate(statement.three(), challenge, &z.message);
        let four = S::simulate(statement.four(), challenge, &z.message);

        let comm = QBinding::bind(
            &statement.pp,
            z.ck,
            (&one, &two, &three, &four),
            z.aux,
        );
        StackedA(z.ck, comm)
    }
}
