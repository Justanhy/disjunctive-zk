use std::fmt;
use std::io::Write;
use std::rc::Rc;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::CryptoRngCore;
use sigmazk::{Challenge, EHVzk, SigmaProtocol};

use crate::commitment_scheme::halfbinding::Commitment;
pub use crate::commitment_scheme::qbinding::*;
use crate::stackable::{Message, Stackable};

#[derive(Clone)]
pub struct StackedStatement<S: Stackable> {
    pp: PublicParams,
    height: usize,
    clauses: usize,
    statements: Vec<S::Statement>,
}

impl<S: Stackable> fmt::Display for StackedStatement<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "StackedStatement {{ 
                height: {}, 
                clauses: {} 
            }}",
            self.height, self.clauses
        )
    }
}

impl<S: Stackable> StackedStatement<S> {
    /// Creates a new stacked statement from a list of
    /// statements.
    ///
    /// # Parameters
    /// `pp`: Public Parameters generated by the
    /// 1-out-of-2^q partially binding commitment
    /// scheme.
    ///
    /// `height`: The height of the commitment
    /// scheme tree. This is also the `q` in 1-out-of-2^q.
    ///
    /// `statements`: A list of statements to be stacked.
    pub fn new(
        pp: PublicParams,
        height: usize,
        statements: Vec<S::Statement>,
    ) -> Self {
        StackedStatement {
            pp,
            height,
            clauses: 1 << height,
            statements,
        }
    }

    pub fn pp(&self) -> &PublicParams {
        &self.pp
    }

    pub fn clauses(&self) -> usize {
        self.clauses
    }

    pub fn height(&self) -> usize {
        self.height
    }

    pub fn statements(&self) -> &Vec<S::Statement> {
        &self.statements
    }

    pub fn bound_statement(
        &self,
        binding: &BindingIndex,
    ) -> &S::Statement {
        &self.statements[binding.index()]
    }

    pub fn statement_at(
        &self,
        index: usize,
    ) -> Option<&S::Statement> {
        self.statements
            .get(index)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct StackedWitness<W> {
    nested_witness: W,
    binding: BindingIndex,
}

impl<W: fmt::Display> fmt::Display for StackedWitness<W> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "StackedWitness {{ 
                binding: {}, 
                nested_witness: {} 
            }}",
            self.binding, self.nested_witness
        )
    }
}

impl<W> StackedWitness<W> {
    pub fn init(
        nested_witness: W,
        binding: BindingIndex,
    ) -> Self {
        StackedWitness {
            nested_witness,
            binding,
        }
    }
}

#[derive(Clone)]
pub struct StackedZ<S: Stackable> {
    ck: CommitKey,
    message: S::MessageZ,
    aux: Randomness,
}

impl<S: Stackable> StackedZ<S> {
    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn new(
        ck: CommitKey,
        message: S::MessageZ,
        aux: Randomness,
    ) -> Self {
        StackedZ { ck, message, aux }
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn ck(&self) -> &CommitKey {
        &self.ck
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn message(&self) -> &S::MessageZ {
        &self.message
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn aux(&self) -> &Randomness {
        &self.aux
    }
}

impl<S: Stackable> fmt::Debug for StackedZ<S> {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
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
            aux: Randomness::random(
                &mut ChaCha20Rng::from_entropy(),
                1,
            ),
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

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[test]
fn test_traits_stacked_a() {
    // Test message for stacked A
    let rng = ChaCha20Rng::from_seed([0u8; 32]);
    let ck = CommitKey::default();
    let commitment =
        Commitment(rng.get_seed(), rng.get_seed());
    let stacked_a = StackedA::default();
    let stacked_a2 = StackedA(ck, commitment);
    let mut buf = Vec::new();
    stacked_a2.write(&mut buf);
    let mut buf2 = Vec::new();
    stacked_a.write(&mut buf2);
    assert_eq!(buf, buf2);
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
        let q = (clauses as f64)
            .log2()
            .ceil() as usize;
        dbg!(q);

        SelfStacker {
            clauses: 1 << q,
            base,
            q,
        }
    }

    pub fn clauses(&self) -> usize {
        self.clauses
    }

    pub fn base(&self) -> &S {
        &self.base
    }

    pub fn q(&self) -> usize {
        self.q
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
            .map(|s| {
                Rc::new(S::simulate(
                    s,
                    challenge,
                    z.message(),
                ))
            })
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

/// Sigma protocol implementation for self-stacking compiler
impl<S: Stackable> SigmaProtocol for SelfStacker<S> {
    type Statement = StackedStatement<S>;
    type Witness = StackedWitness<S::Witness>;
    type State = StackedState<S>;
    type MessageA = StackedA;
    type Challenge = S::Challenge;
    type MessageZ = StackedZ<S>;

    /// First round of the protocol
    fn first<R: CryptoRngCore + Clone>(
        statement: &StackedStatement<S>,
        witness: &StackedWitness<S::Witness>,
        prover_rng: &mut R,
    ) -> (Self::State, Self::MessageA) {
        // Deconstruct witness
        let StackedWitness {
            nested_witness,
            binding,
        } = witness;

        // First call the underlying protocol with the statement at the active clause
        let (nested_state, bound_message) = S::first(
            statement.bound_statement(binding),
            nested_witness,
            prover_rng,
        );
        // Instance of partial binding commitment scheme that we will use
        let q = statement.height();
        let qbinding = QBinding::new(q);
        // Instantiate pointer to the message from the active clause
        let bound_message = Rc::new(bound_message);

        // Determine our message vector
        let def = Rc::new(S::MessageA::default());
        let initial_messages: Vec<Rc<S::MessageA>> = (0
            ..statement.clauses())
            .map(|i| {
                // If active clause, we use the message from earlier
                if i == binding.index() {
                    bound_message.clone()
                } else {
                    // Otherwise we use the default message
                    def.clone()
                }
            })
            .collect();

        // Here we compute commitment key and equivocation key for the protocol. We appear to reuse the same
        // prover_rng but it is mutated and thus different. Still, the change is deterministic.
        let (ck, ek) = qbinding.gen(
            &statement.pp,
            *binding,
            prover_rng,
        );

        // Derive auxiliary value from prover's rng
        let aux = Randomness::random(prover_rng, q);
        // Compute commitment
        let (comm, aux) = qbinding.equivcom(
            &statement.pp,
            &ek,
            &initial_messages,
            Some(aux),
        );

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

    /// Second round of the protocol. Random challenge.
    fn second<R: CryptoRngCore>(
        verifier_rng: &mut R,
    ) -> Self::Challenge
    where
        Self: Sized,
    {
        let mut buffer = [0u8; 64];
        verifier_rng.fill_bytes(&mut buffer);
        Challenge::new(&buffer)
    }

    /// Third round of the protocol.
    fn third<R: CryptoRngCore + Clone>(
        statement: &Self::Statement,
        state: Self::State,
        witness: &Self::Witness,
        challenge: &Self::Challenge,
        prover_rng: &mut R,
    ) -> Self::MessageZ {
        // Deconstruct the state struct
        let StackedState {
            nested_state,
            bound_message,
            initial_messages,
            ck,
            ek,
            aux,
        } = state;

        // Deconstruct the witness struct
        let StackedWitness {
            nested_witness,
            binding,
        } = witness;
        let qbinding = QBinding::new(statement.height());

        // Call third round algorithm of underlying protocol
        let nested_z = S::third(
            statement.bound_statement(binding),
            nested_state,
            nested_witness,
            challenge,
            prover_rng,
        );

        let new_messages: Vec<Rc<S::MessageA>> = (0
            ..statement.clauses())
            .map(|i| {
                // Same as earlier, if active clause, we use the message from first round
                if i == binding.index() {
                    bound_message.clone()
                } else {
                    // Otherwise, we need to simulate the first message from statement, challenge and z from earlier
                    Rc::new(S::simulate(
                        statement
                            .statement_at(i)
                            .unwrap(),
                        challenge,
                        &nested_z,
                    ))
                }
            })
            .collect();

        // Equivocate the initial vector of messages with new messages
        // obtaining new auxiliary value
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

    /// Verification algorithm for the protocol
    fn verify(
        statement: &Self::Statement,
        a: &Self::MessageA,
        c: &Self::Challenge,
        z: &Self::MessageZ,
    ) -> bool
    where
        Self: Sized,
    {
        // Deconstruct variables from structs
        // Here we get the commitment key, and commitment from first round of stacking protocol
        let StackedA(ck_a, comm) = a;
        // Here we get the commitment key, messages, and aux variable from the third round of stacker
        let StackedZ {
            ck: ck_z,
            message,
            aux,
        } = z;

        // Now we go through every statement and simulate with the recyclable third round message
        // and challenge from 2nd round
        let v: Vec<Rc<S::MessageA>> = statement
            .statements()
            .iter()
            .map(|s| Rc::new(S::simulate(s, c, &message)))
            .collect();

        // Using bindcom algorithm, we compute the commitment to this vector of messages
        let comm_check = QBinding::new(statement.height())
            .bind(&statement.pp, ck_a, &v, aux);

        // Now we want to verify that the messages are valid for every clause
        let nested_check = statement
            .statements()
            .iter()
            .zip(v.iter())
            .all(|(s, m)| S::verify(s, m, c, &message));

        ck_a == ck_z && *comm == comm_check && nested_check
    }
}
