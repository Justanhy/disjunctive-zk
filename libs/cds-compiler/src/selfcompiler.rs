//! CDS94 Compiler for a single protocol
use std::collections::HashSet;
use std::marker::PhantomData;

use shareable::Shareable;
use sigmazk::Challenge;

use crate::*;

#[derive(Clone, Debug, Copy, Default)]
pub struct SelfCompiler94<S: Composable> {
    clauses: usize,
    threshold: usize,
    base: PhantomData<S>,
}

impl<S: Composable> SelfCompiler94<S> {
    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn new(clauses: usize, threshold: usize) -> Self {
        Self {
            clauses,
            threshold,
            base: PhantomData,
        }
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn clauses(&self) -> usize {
        self.clauses
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn threshold(&self) -> usize {
        self.threshold
    }
}

#[derive(Clone, Debug)]
pub struct Statement94<S: SigmaProtocol> {
    clauses: usize,
    threshold: usize,
    statements: Vec<S::Statement>,
}

impl<S: SigmaProtocol> Statement94<S> {
    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn new(
        clauses: usize,
        threshold: usize,
        statements: Vec<S::Statement>,
    ) -> Self {
        Self {
            clauses,
            threshold,
            statements,
        }
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn clauses(&self) -> usize {
        self.clauses
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn statements(&self) -> &Vec<S::Statement> {
        &self.statements
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn len(&self) -> usize {
        self.statements
            .len()
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn pattern_match(
        &self,
    ) -> (&usize, &usize, &Vec<S::Statement>) {
        (&self.clauses, &self.threshold, &self.statements)
    }
}

#[derive(Clone, Debug)]
pub struct State94<S: SigmaProtocol> {
    inner_states: Vec<Option<S::State>>,
    challenges: Vec<Option<S::Challenge>>,
    zs: Vec<Option<S::MessageZ>>,
}

impl<S: Composable> State94<S> {
    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn new(
        inner_states: Vec<Option<S::State>>,
        challenges: Vec<Option<S::Challenge>>,
        zs: Vec<Option<S::MessageZ>>,
    ) -> Self {
        Self {
            inner_states,
            challenges,
            zs,
        }
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn pattern_match(
        &self,
    ) -> (
        &Vec<Option<S::State>>,
        &Vec<Option<S::Challenge>>,
        &Vec<Option<S::MessageZ>>,
    ) {
        (&self.inner_states, &self.challenges, &self.zs)
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn inner_states(&self) -> &Vec<Option<S::State>> {
        &self.inner_states
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn challenges(&self) -> &Vec<Option<S::Challenge>> {
        &self.challenges
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn zs(&self) -> &Vec<Option<S::MessageZ>> {
        &self.zs
    }
}

#[derive(Clone, Debug)]
pub struct Witness94<S: Composable> {
    witnesses: Vec<S::Witness>,
    active_clauses: HashSet<usize>,
}

impl<S: Composable> Witness94<S> {
    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn new(
        witnesses: Vec<S::Witness>,
        active_clauses: HashSet<usize>,
    ) -> Self {
        Self {
            witnesses,
            active_clauses,
        }
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn active_clauses(&self) -> &HashSet<usize> {
        &self.active_clauses
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn witnesses(&self) -> &Vec<S::Witness> {
        &self.witnesses
    }

    #[cfg_attr(coverage_nightly, no_coverage)]
    pub fn pattern_match(
        &self,
    ) -> (&Vec<S::Witness>, &HashSet<usize>) {
        (&self.witnesses, &self.active_clauses)
    }
}

impl<S: Composable> fmt::Display for SelfCompiler94<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let n = self.clauses;
        let t = self.threshold;
        write!(
            f,
            "Clauses: {}, Active Clauses: {}, Threshold: \
             {}",
            n,
            n - t + 1,
            t
        )
    }
}

#[test]
fn test_selfcompiler_display() {
    let compiler: SelfCompiler94<Schnorr> =
        SelfCompiler94::new(10, 5);
    assert_eq!(
        format!("{}", compiler),
        "Clauses: 10, Active Clauses: 6, Threshold: 5"
    );
}

#[derive(Clone, Default, Debug)]
pub struct CompiledZ94<S: Composable>(
    usize,
    S::Challenge,
    S::MessageZ,
);

impl<S: Composable + Default + Debug> Message
    for CompiledZ94<S>
{
    fn write<W: std::io::Write>(&self, writer: &mut W)
    where
        Self: Sized,
    {
        self.0
            .write(writer);
        self.1
            .write(writer);
        self.2
            .write(writer);
    }
}

/// Implementation of the Sigma Protocol trait for the CDS94 compiler protocol.
///
/// This implementation requires a SigmaProtocol (denoted by
/// S) that implements the Composable trait.
impl<S: Composable> SigmaProtocol for SelfCompiler94<S> {
    type Statement = Statement94<S>;
    type Witness = Witness94<S>;
    type State = State94<S>;
    type MessageA = Vec<S::MessageA>;
    type Challenge = S::Challenge;
    type MessageZ = Vec<CompiledZ94<S>>;

    /// The algorithm for the first round of the protocol.
    fn first<R: CryptoRngCore + Clone>(
        statement: &Self::Statement,
        witness: &Self::Witness,
        prover_rng: &mut R,
    ) -> (Self::State, Self::MessageA)
    where
        Self: Sized,
    {
        // Clone the prover_rng as we need it to be the same value for third round
        let mut prover_rng = prover_rng.clone();
        // Deconstruct variables
        let (clauses, _cds_threshold, statements) =
            statement.pattern_match();
        let (witnesses, active_clauses) =
            witness.pattern_match();
        // Intialize vectors
        let mut inner_states: Vec<Option<S::State>> =
            Vec::with_capacity(*clauses);
        let mut challenges: Vec<Option<S::Challenge>> =
            Vec::with_capacity(*clauses);
        let mut zs: Vec<Option<S::MessageZ>> =
            Vec::with_capacity(*clauses);
        let mut message_as: Vec<S::MessageA> =
            Vec::with_capacity(*clauses);

        for i in 0..*clauses {
            // If the clause is active, run the first round of the underlying sigma protocol
            if active_clauses.contains(&i) {
                let (state, message_a) = S::first(
                    &statements[i],
                    &witnesses[i],
                    &mut prover_rng,
                );

                // Push relevant values to vectors
                message_as.push(message_a);
                inner_states.push(Some(state));
                challenges.push(None);
                zs.push(None);
            } else {
                // If the clause is not active, simulate the underyling sigma protocol
                let (message_a, c, z) =
                    S::simulate(&statements[i]);

                // Push relevant values to vectors
                message_as.push(message_a);
                inner_states.push(None);
                challenges.push(Some(c));
                zs.push(Some(z));
            }
        }

        (
            State94::new(inner_states, challenges, zs),
            message_as,
        )
    }

    /// Second round of the protocol. Simply generates a random challenge.
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

    /// Third roud of the protocol
    fn third<R: CryptoRngCore + Clone>(
        statement: &Self::Statement,
        state: Self::State,
        witness: &Self::Witness,
        challenge: &Self::Challenge,
        prover_rng: &mut R,
    ) -> Self::MessageZ
    where
        Self: Sized,
    {
        // Deconstruct variables
        let (clauses, cds_threshold, statements) =
            statement.pattern_match();
        let (witnesses, active_clauses) =
            witness.pattern_match();

        // Create instance of Shamir Secret Sharing
        let shamirs_threshold = clauses - cds_threshold + 1;
        let active_count = active_clauses.len();

        let shamir = ShamirSecretSharing {
            threshold: shamirs_threshold,
            shares: *clauses,
        };

        // Initalize vectors
        let mut shares =
            Vec::with_capacity(shamirs_threshold);
        let mut remaining_xs =
            Vec::with_capacity(active_count);

        let challenges = state.challenges();
        for (i, ci) in challenges
            .iter()
            .enumerate()
        {
            // If clause is active, add the x-coordinate value to the remaining_xs vector
            if active_clauses.contains(&i) {
                remaining_xs.push(
                    <S::Challenge as Shareable>::F::from(
                        (i + 1) as u64,
                    ),
                );
            } else {
                // Otherwise, add the share to the shares vector
                let share = Share {
                    x: <S::Challenge as Shareable>::F::from(
                        (i + 1) as u64,
                    ),
                    y: ci
                        .clone()
                        .unwrap()
                        .share(),
                };

                shares.push(share);
            }
        }

        // Get the missing shares by completing the shares vector with the remaining_xs vector x_values
        let mut missing_shares = shamir
            .complete_shares(
                &challenge.share(),
                &shares,
                &remaining_xs,
            )
            .unwrap();

        // Append the missing shares to the shares vector
        shares.append(&mut missing_shares);

        // Get the message_zs and inner_states of underyling sigma protocols
        let message_zs = state.zs();
        let inner_states = state.inner_states();

        shares
            .iter()
            .map(|share| {
                // Derive the usize from the field element
                let i = S::Challenge::to_usize(share.x) - 1;

                match &challenges[i] {
                    // If this is simulated, return the simulated values
                    Some(ci) => CompiledZ94(
                        i,
                        ci.clone(),
                        message_zs[i]
                            .clone()
                            .unwrap(),
                    ),
                    // If not simulated, run the third round of the underlying sigma protocol
                    None => {
                        let ci = Shareable::derive(share.y);
                        let zi = S::third(
                            &statements[i],
                            inner_states[i]
                                .clone()
                                .unwrap(),
                            &witnesses[i],
                            &ci,
                            prover_rng,
                        );

                        CompiledZ94(i, ci, zi)
                    }
                }
            })
            .collect_vec()
    }

    /// Verification algorithm
    fn verify(
        statement: &Self::Statement,
        a: &Self::MessageA,
        secret: &Self::Challenge,
        z: &Self::MessageZ,
    ) -> bool
    where
        Self: Sized,
    {
        let valid = a.len() == z.len();

        let (clauses, cds_threshold, statements) =
            statement.pattern_match();

        let mut shares = Vec::with_capacity(*clauses);

        for CompiledZ94(i, c, m2) in z {
            let m1 = &a[*i];

            // Firstly verify that the transcript for current index is valid for the instance
            if !S::verify(&statements[*i], m1, &c, &m2) {
                return false;
            }

            // Then add the share to the shares vector
            let share = Share {
                x: <S::Challenge as Shareable>::F::from(
                    (i + 1) as u64,
                ),
                y: c.share(),
            };

            shares.push(share);
        }

        let shamir = ShamirSecretSharing {
            threshold: clauses - cds_threshold + 1,
            shares: *clauses,
        };

        // Use shamir secret sharing to reconstruct secret
        let res = shamir.reconstruct_secret(&shares);

        let combined_secret = res.unwrap_or(
            <S::Challenge as Shareable>::F::default(),
        );

        combined_secret == secret.share() && valid
    }
}

impl<S: Composable> HVzk for SelfCompiler94<S> {
    fn simulate(
        statement: &Self::Statement,
    ) -> (Self::MessageA, Self::Challenge, Self::MessageZ)
    {
        let (clauses, cds_threshold, statements) =
            statement.pattern_match();

        let shamir = ShamirSecretSharing {
            threshold: clauses - cds_threshold + 1,
            shares: *clauses,
        };

        let mut shares = Vec::with_capacity(*clauses);
        let mut message_as = Vec::with_capacity(*clauses);
        let mut message_zs = Vec::with_capacity(*clauses);

        for i in 0..*clauses {
            let (message_a, c, z) =
                S::simulate(&statements[i]);

            message_as.push(message_a);
            message_zs.push(CompiledZ94(i, c.clone(), z));

            let share = Share {
                x: <S::Challenge as Shareable>::F::from(
                    (i + 1) as u64,
                ),
                y: c.share(),
            };

            shares.push(share);
        }

        let secret = shamir.reconstruct_secret(&shares);

        let combined_secret = secret.unwrap_or(
            <S::Challenge as Shareable>::F::default(),
        );

        (
            message_as,
            Shareable::derive(combined_secret),
            message_zs,
        )
    }
}

impl<S: Composable> Composable for SelfCompiler94<S> {}
