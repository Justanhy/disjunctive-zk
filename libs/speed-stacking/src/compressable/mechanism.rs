use core::ops::Mul;
use group::ff::{Field, PrimeField};
use group::prime::PrimeGroup;
use group::{Group, ScalarMul};
use rand_core::CryptoRngCore;
use sigmazk::SigmaProtocol;
use std::rc::Rc;
use wrapped_ristretto::scalar::WrappedScalar;

use crate::homomorphism::Hom;

use super::{multi_exponentiation, Base};

/// Compressing Mechanism for our base compressable sigma
/// protocol.
pub struct CompMechanism<
    G1: PrimeGroup,
    F: PrimeField,
    G2: PrimeGroup,
    L: Hom<F, G2>,
> {
    pub n: usize,
    pub base: Base<G1, F, G2, L>,
    _marker: std::marker::PhantomData<(G1, F, G2, L)>,
}

impl<G1, F, G2, L> CompMechanism<G1, F, G2, L>
where
    G1: PrimeGroup,
    F: PrimeField,
    G2: PrimeGroup + ScalarMul<F>,
    L: Hom<F, G2>,
{
    pub fn new(n: usize) -> Self {
        Self {
            n,
            base: Base::new(n),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn unique_or_rand(current_f: G2) -> G2 {
        current_f
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ComposedHom<G: PrimeGroup> {
    pub challenge_i: G::Scalar,
}

impl<G: PrimeGroup> ComposedHom<G> {
    pub fn new(challenge_i: G::Scalar) -> Self {
        Self { challenge_i }
    }
}

impl<G> Hom<G::Scalar, G::Scalar> for ComposedHom<G>
where
    G: PrimeGroup,
    G::Scalar: Group,
{
    fn fleft(&self, x: &[G::Scalar]) -> G::Scalar {
        x.iter()
            .fold(G::Scalar::ZERO, |acc, x| acc + *x * self.challenge_i)
    }

    fn fright(&self, x: &[G::Scalar]) -> G::Scalar {
        x.iter()
            .fold(G::Scalar::ZERO, |acc, x| acc + x)
    }
}

#[derive(Clone, Debug)]
pub struct History<G1: PrimeGroup, G2: PrimeGroup, L: Hom<G1::Scalar, G2>> {
    pub base_f: Rc<L>,
    pub base_g1: Rc<G1>,
    pub base_g2: Rc<G2>,
    pub past_a: Vec<G2>,
    pub past_b: Vec<G2>,
    pub past_c: Vec<G1::Scalar>,
}

pub struct ComposedStatement<
    G1: PrimeGroup,
    G2: PrimeGroup,
    L: Hom<G1::Scalar, G2>,
> {
    pub history: History<G1, G2, L>,
    pub n: usize,
    pub generators: Vec<G1>,
    pub hom_f: L,
    pub g1_public_key: G1,
    pub g2_public_key: G2, // y_i
}

pub struct ComposedA<G1: PrimeGroup, G2: PrimeGroup> {
    pub big_a: G1,
    pub big_b: G1,
    pub a: G2,
    pub b: G2,
}

pub struct ComposedState<G2: PrimeGroup> {
    pub a: G2,
    pub b: G2,
}

impl<G1, G2, L> SigmaProtocol for CompMechanism<G1, G1::Scalar, G2, L>
where
    G1: PrimeGroup,
    G2: PrimeGroup + ScalarMul<G1::Scalar>,
    L: Hom<G1::Scalar, G2>,
{
    type Statement = ComposedStatement<G1, G2, L>;
    type Witness = Vec<G1::Scalar>;
    type State = ComposedState<G2>;

    type MessageA = ComposedA<G1, G2>;
    type MessageZ = ();
    type Challenge = G1::Scalar;

    type ProverContext = ();

    fn first<R: CryptoRngCore>(
        statement: &Self::Statement,
        witness: &Self::Witness,
        prover_rng: &mut R,
        _prover_context: &Self::ProverContext,
    ) -> (Self::State, Self::MessageA)
    where
        Self: Sized,
    {
        let midpoint = statement.n / 2;

        let (g_left, g_right) = statement
            .generators
            .as_slice()
            .split_at(midpoint);

        let (xleft, xright) = witness
            .as_slice()
            .split_at(midpoint);

        let big_a = multi_exponentiation(g_right, xleft);
        let big_b = multi_exponentiation(g_left, xright);

        // TODO: Fully implement unique_or_rand
        let a = Self::unique_or_rand(
            statement
                .hom_f
                .fright(xleft),
        );
        let b = Self::unique_or_rand(
            statement
                .hom_f
                .fleft(xright),
        );

        (ComposedState { a, b }, ComposedA { big_a, big_b, a, b })
    }

    fn second<R: rand_core::CryptoRngCore>(
        verifier_rng: &mut R,
    ) -> Self::Challenge
    where
        Self: Sized,
    {
        G1::Scalar::random(verifier_rng)
    }

    fn third<R: rand_core::CryptoRngCore>(
        statement: &Self::Statement,
        state: Self::State,
        witness: &Self::Witness,
        challenge: &Self::Challenge,
        prover_rng: &mut R,
        prover_context: &Self::ProverContext,
    ) -> Self::MessageZ
    where
        Self: Sized,
    {
        let challenge = *challenge;
        if statement.n == 4 {
            vec![
                challenge * witness[2] + witness[0],
                challenge * witness[3] + witness[1],
            ];
        } else {
            let midpoint = statement.n / 2;
            // Create witness vector for next round
            let (xleft, xright) = witness
                .as_slice()
                .split_at(midpoint);
            let x_new: Vec<G1::Scalar> = xleft
                .iter()
                .zip(xright.iter())
                .map(|(l, r)| challenge * l + r)
                .collect();
            // Create generator vector for next round
            let (gleft, gright) = statement
                .generators
                .as_slice()
                .split_at(midpoint);
            let g_new: Vec<G1> = gleft
                .iter()
                .zip(gright.iter())
                .map(|(l, r)| *l * challenge + r)
                .collect();

            // Create homomorphism for next round
            let hom_f: ComposedHom<G1> = ComposedHom::new(challenge);

            // Create new g2_public_key (y_{i + 1} in the paper)
            // y_{i + 1} = ai + c_i*y_i + b_i * c_i^2
            let g2_public_key = state.a
                + statement.g2_public_key * challenge
                + state.b * challenge.square();

            // Update history for next round
            let mut history = statement
                .history
                .clone();
            history
                .past_a
                .push(state.a);
            history
                .past_b
                .push(state.b);
            history
                .past_c
                .push(challenge);

            // Create new statement for next round
            let statement: ComposedStatement<G1, G2, L> = ComposedStatement {
                history,
                n: midpoint,
                generators: g_new,
                hom_f: hom_f as Hom<G1::Scalar, G2>,
                g1_public_key: statement.g1_public_key,
                g2_public_key,
            };
        }
        unimplemented!()
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
        unimplemented!()
    }
}
