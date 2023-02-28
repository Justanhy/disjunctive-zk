use group::ff::{Field, PrimeField};
use group::prime::PrimeGroup;
use group::ScalarMul;
use rand_core::CryptoRngCore;
use sigmazk::SigmaProtocol;

use crate::homomorphism::Hom;

pub struct Base<G1: PrimeGroup, F: PrimeField, G2: PrimeGroup, L: Hom<F, G2>> {
    pub n: usize,
    _marker: std::marker::PhantomData<(G1, F, G2, L)>,
}

impl<G1, F, G2, L> Base<G1, F, G2, L>
where
    G1: PrimeGroup,
    F: PrimeField,
    G2: PrimeGroup + ScalarMul<F>,
    L: Hom<F, G2>,
{
    pub fn new(n: usize) -> Self {
        Self {
            n,
            _marker: std::marker::PhantomData,
        }
    }
}

pub fn multi_exponentiation<G: PrimeGroup>(
    bases: &[G],
    exponents: &[G::Scalar],
) -> G {
    bases
        .iter()
        .zip(exponents.iter())
        .fold(G::identity(), |acc, (g, r)| acc + *g * r)
}

pub struct BaseStatement<G1: PrimeGroup, G2: PrimeGroup, L: Hom<G1::Scalar, G2>>
{
    pub generators: Vec<G1>,
    pub f: L,
    pub g1_public_key: G1,
    pub g2_public_key: G2,
}

impl<G1, G2, L> SigmaProtocol for Base<G1, G1::Scalar, G2, L>
where
    G1: PrimeGroup,
    G2: PrimeGroup + ScalarMul<G1::Scalar>,
    L: Hom<G1::Scalar, G2>,
{
    type Statement = BaseStatement<G1, G2, L>;
    type Witness = Vec<G1::Scalar>;

    type MessageA = (G1, G2);

    type Challenge = G1::Scalar;

    type MessageZ = Vec<G1::Scalar>;

    type State = Vec<G1::Scalar>;
    type ProverContext = ();

    fn first<R: CryptoRngCore>(
        statement: &Self::Statement,
        _witness: &Self::Witness,
        prover_rng: &mut R,
        _prover_context: &Self::ProverContext,
    ) -> (Self::State, Self::MessageA)
    where
        Self: Sized,
    {
        let n = statement
            .generators
            .len();
        let r: Vec<G1::Scalar> = (0..n)
            .map(|_| G1::Scalar::random(prover_rng.as_rngcore()))
            .collect();
        let t2 = statement
            .f
            .f(&r);
        let t1 = statement
            .generators
            .iter()
            .zip(r.iter())
            .fold(G1::identity(), |acc, (g, r)| acc + *g * r);
        (r, (t1, t2))
    }

    fn second<R: rand_core::CryptoRngCore>(
        verifier_rng: &mut R,
    ) -> Self::Challenge
    where
        Self: Sized,
    {
        G1::Scalar::random(verifier_rng.as_rngcore())
    }

    fn third<R: rand_core::CryptoRngCore>(
        _statement: &Self::Statement,
        state: Self::State,
        witness: &Self::Witness,
        challenge: &Self::Challenge,
        _prover_rng: &mut R,
        _prover_context: &Self::ProverContext,
    ) -> Self::MessageZ
    where
        Self: Sized,
    {
        witness
            .iter()
            .zip(state.iter())
            .map(|(w, r)| *w * challenge + r)
            .collect()
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
        let fz = statement
            .f
            .f(z);
        let gz = statement
            .generators
            .iter()
            .zip(z.iter())
            .fold(G1::identity(), |acc, (g, z)| acc + *g * z);
        fz == statement.g2_public_key * *c + a.1
            && gz == a.0 + statement.g1_public_key * c
    }
}
