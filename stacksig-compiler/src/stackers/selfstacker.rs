use std::fmt;
use std::io::Write;
use std::iter::Map;
use std::rc::Rc;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::CryptoRngCore;
use sigmazk::{EHVzk, SigmaProtocol};

use crate::commitment_scheme::comm::PartialBindingCommScheme;
use crate::commitment_scheme::halfbinding::Commitment;
use crate::commitment_scheme::qbinding::{
    BindingIndex, CommitKey, EquivKey, PublicParams, QBinding, Randomness,
};
use crate::stackable::{Challenge, Message, Stackable};

pub struct StackedStatement<S: Stackable> {
    pp: PublicParams,
    clauses: usize,
    statements: Vec<S::Statement>,
}

impl<S: Stackable> StackedStatement<S> {
    pub fn pp(&self) -> &PublicParams {
        &self.pp
    }

    pub fn clauses(&self) -> usize {
        self.clauses
    }

    pub fn height(&self) -> usize {
        self.clauses
            .to_be_bytes()
            .len()
    }

    pub fn statements(&self) -> &Vec<S::Statement> {
        &self.statements
    }

    pub fn bound_statement(&self, binding: &BindingIndex) -> &S::Statement {
        &self.statements[binding.index()]
    }

    pub fn statement_at(&self, index: usize) -> &S::Statement {
        &self.statements[index]
    }
}

#[derive(Debug, PartialEq)]
pub struct StackedWitness<W> {
    nested_witness: W,
    binding: BindingIndex,
}

impl<W> StackedWitness<W> {
    pub fn init(nested_witness: W, binding: BindingIndex) -> Self {
        StackedWitness {
            nested_witness,
            binding,
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct StackedZ<S: Stackable> {
    ck: CommitKey,
    message: S::MessageZ,
    aux: Randomness,
}

impl<S: Stackable> StackedZ<S> {
    pub fn new(ck: CommitKey, message: S::MessageZ, aux: Randomness) -> Self {
        StackedZ { ck, message, aux }
    }

    pub fn ck(&self) -> &CommitKey {
        &self.ck
    }

    pub fn message(&self) -> &S::MessageZ {
        &self.message
    }

    pub fn aux(&self) -> &Randomness {
        &self.aux
    }
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
            aux: Randomness::random(&mut ChaCha20Rng::from_entropy(), 1),
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
    bound_message: Rc<S::MessageA>,
    initial_messages: Vec<Rc<S::MessageA>>,
    ck: CommitKey,
    ek: EquivKey,
    aux: Randomness,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct StackedA(CommitKey, Commitment);

impl Message for StackedA {
    fn write<W: Write>(&self, writer: &mut W) {
        self.0
            .write(writer);
        self.1
            .write(writer);
    }
}

#[derive(Clone, Debug)]
pub struct SelfStacker<S: Stackable> {
    clauses: usize, // number of clauses being composed
    base: S,
    q: usize,
}

impl<S: Stackable> SelfStacker<S> {
    pub fn new(clauses: usize, base: S) -> Self {
        assert!(clauses > 1);
        let q = clauses
            .to_be_bytes()
            .len();

        SelfStacker {
            clauses: 1 << q,
            base,
            q,
        }
    }

    pub fn initial_messages(clauses: usize) -> Vec<Rc<S::MessageA>> {
        let default = Rc::new(S::MessageA::default());
        (0..clauses)
            .map(|_| default.clone())
            .collect()
    }
}

impl<S: Stackable> Stackable for SelfStacker<S> {}

impl<S: Stackable> EHVzk for SelfStacker<S> {
    fn simulate(
        // precom: &S::Precompute,
        statement: &StackedStatement<S>,
        challenge: &S::Challenge,
        z: &StackedZ<S>,
    ) -> Self::MessageA {
        let v: Vec<Rc<S::MessageA>> = statement
            .statements()
            .iter()
            .map(|s| Rc::new(S::simulate(s, challenge, z.message())))
            .collect();

        let comm = QBinding::new(statement.height()).bind(
            statement.pp(),
            z.ck(),
            &v,
            z.aux(),
        );
        StackedA(
            z.ck()
                .clone(),
            comm,
        )
    }
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
        prover_rng: &mut R,
        prover_context: &S::ProverContext,
    ) -> (Self::State, Self::MessageA) {
        let StackedWitness {
            nested_witness,
            binding,
        } = witness;

        let (nested_state, bound_message) = S::first(
            statement.bound_statement(binding),
            nested_witness,
            prover_rng,
            prover_context,
        );
        // Instance of partial binding commitment scheme that we
        // will use
        let q = statement.height();
        let qbinding = QBinding::new(q); // TODO: test height
        let bound_message = Rc::new(bound_message);

        // Determine our message vector
        let def = Rc::new(S::MessageA::default());
        let initial_messages: Vec<Rc<S::MessageA>> = (0..statement.clauses())
            .map(|i| {
                if i == binding.index() {
                    bound_message.clone()
                } else {
                    def.clone()
                }
            })
            .collect();

        // Here we compute commitment key and equivocation key for
        // the protocol. We appear to reuse the same
        // prover_rng but it is mutated and thus different.
        // Still, the change is deterministic.
        let (ck, ek) = qbinding.gen(&statement.pp, *binding, prover_rng);

        // Derive auxiliary value from prover's rng
        let aux = Randomness::random(prover_rng, q);
        // Compute commitment
        let (comm, aux) =
            qbinding.equivcom(&statement.pp, &ek, &initial_messages, Some(aux));

        (
            StackedState {
                nested_state,
                bound_message,
                initial_messages,
                ck: ck.clone(),
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
        state: Self::State,
        witness: &Self::Witness,
        challenge: &Self::Challenge,
        prover_rng: &mut R,
        prover_context: &S::ProverContext,
    ) -> Self::MessageZ {
        let StackedState {
            nested_state,
            bound_message,
            initial_messages,
            ck,
            ek,
            aux,
        } = state;

        let StackedWitness {
            nested_witness,
            binding,
        } = witness;
        let qbinding = QBinding::new(statement.height());

        let nested_z = S::third(
            statement.bound_statement(binding),
            nested_state,
            nested_witness,
            challenge,
            prover_rng,
            prover_context,
        );

        let new_messages: Vec<Rc<S::MessageA>> = (0..statement.clauses())
            .map(|i| {
                if i == binding.index() {
                    bound_message.clone()
                } else {
                    Rc::new(S::simulate(
                        statement.statement_at(i),
                        challenge,
                        &nested_z,
                    ))
                }
            })
            .collect();

        let aux_new = qbinding.equiv(
            &statement.pp,
            &ek,
            &initial_messages,
            &new_messages,
            &aux,
        );
        StackedZ {
            ck,
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

        let v: Vec<Rc<S::MessageA>> = statement
            .statements()
            .iter()
            .map(|s| Rc::new(S::simulate(s, c, &message)))
            .collect();

        let comm_check = QBinding::new(statement.height()).bind(
            &statement.pp,
            ck_a,
            &v,
            aux,
        );
        let nested_check = statement
            .statements()
            .iter()
            .zip(v.iter())
            .all(|(s, m)| S::verify(s, m, c, &message));

        ck_a == ck_z && *comm == comm_check && nested_check
    }
}
