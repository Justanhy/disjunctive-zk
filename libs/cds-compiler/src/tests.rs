use std::collections::HashSet;

use curve25519_dalek::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::selfcompiler::{
    SelfCompiler94, Statement94, Witness94,
};

use super::*;

pub type CDS94Test = (
    SelfCompiler94<Schnorr>,
    Statement94<Schnorr>,
    Witness94<Schnorr>,
    Witness94<Schnorr>,
    ChaCha20Rng,
    ChaCha20Rng,
);

fn test_init<const N: usize, const D: usize>(
    is_positive: bool,
) -> CDS94Test {
    // INIT //
    assert!(D <= N);
    // closure to generate random witnesses
    let m = |_| {
        Scalar::random(&mut ChaCha20Rng::from_entropy())
    };
    // generate witnesses
    let actual_witnesses: Vec<Scalar> = (0..N)
        .map(m)
        .collect();
    // generate the prover's witnesses - for inactive clauses
    // the prover generates a random witness

    let provers_witnesses: Vec<Scalar> = if is_positive {
        actual_witnesses
            .to_owned()
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if i < D {
                    s.clone()
                } else {
                    Scalar::random(
                        &mut ChaCha20Rng::from_entropy(),
                    )
                }
            })
            .collect()
    } else {
        actual_witnesses
            .to_owned()
            .iter()
            .enumerate()
            .map(|(_i, _s)| {
                Scalar::random(
                    &mut ChaCha20Rng::from_entropy(),
                )
            })
            .collect()
    };
    // Set of booleans indicating which clauses are active
    let active_clauses: HashSet<usize> = (0..D).collect();
    // generate the statement (aka protocol) for each clause
    let statements = actual_witnesses
        .to_owned()
        .iter()
        .map(|w| Schnorr::init(*w))
        .collect_vec();

    let protocol = SelfCompiler94::new(N, D);

    let statement = Statement94::new(N, D, statements);

    let actual_witnesses = Witness94::new(
        actual_witnesses,
        active_clauses.clone(),
    );

    let provers_witnesses = Witness94::new(
        provers_witnesses,
        active_clauses.clone(),
    );

    let provers_rng = ChaCha20Rng::from_seed([0u8; 32]);
    let verifiers_rng = ChaCha20Rng::from_seed([1u8; 32]);

    (
        protocol,
        statement,
        actual_witnesses,
        provers_witnesses,
        provers_rng,
        verifiers_rng,
    )
}

#[test]
fn first_message_works() {
    const N: usize = 2;
    const D: usize = 1;
    let (
        _protocol,
        statement,
        actual_witnesses,
        provers_witnesses,
        provers_rng,
        _verifiers_rng,
    ) = test_init::<N, D>(true);

    let (.., statements) = statement.pattern_match();

    let (_state, message_a) = SelfCompiler94::first(
        &statement,
        &provers_witnesses,
        &mut provers_rng.clone(),
    );
    assert!(message_a.len() == N);
    let (_, testc) = Schnorr::first(
        &statements[0],
        &actual_witnesses.witnesses()[0],
        &mut provers_rng.clone(),
    );
    assert!(testc == message_a[0]);
}

#[test]
fn third_message_works() {
    const N: usize = 3;
    const D: usize = 1;
    let (
        _protocol,
        statement,
        _actual_witnesses,
        provers_witnesses,
        mut provers_rng,
        verifiers_rng,
    ) = test_init::<N, D>(true);

    let (state, message_a) = SelfCompiler94::first(
        &statement,
        &provers_witnesses,
        &mut provers_rng.clone(),
    );
    let challenge = SelfCompiler94::<Schnorr>::second(
        &mut verifiers_rng.clone(),
    );
    // Third message
    let proof = SelfCompiler94::third(
        &statement,
        state,
        &provers_witnesses,
        &challenge,
        &mut provers_rng,
    );

    assert!(SelfCompiler94::verify(
        &statement, &message_a, &challenge, &proof
    ));
}

#[test]
fn cds_works() {
    // INIT //
    // number of clauses
    const N: usize = 128;
    const D: usize = 1;
    let (
        _protocol,
        statement,
        _actual_witnesses,
        provers_witnesses,
        mut provers_rng,
        verifiers_rng,
    ) = test_init::<N, D>(true);

    let (state, message_a) = SelfCompiler94::first(
        &statement,
        &provers_witnesses,
        &mut provers_rng,
    );

    let challenge = SelfCompiler94::<Schnorr>::second(
        &mut verifiers_rng.clone(),
    );
    // Third message
    let proof = SelfCompiler94::third(
        &statement,
        state,
        &provers_witnesses,
        &challenge,
        &mut provers_rng,
    );

    assert!(SelfCompiler94::verify(
        &statement, &message_a, &challenge, &proof
    ));
}

#[test]
fn cds_fails() {
    // INIT //
    // number of clauses
    const N: usize = 128;
    const D: usize = 1;
    let (
        _protocol,
        statement,
        _actual_witnesses,
        provers_witnesses,
        mut provers_rng,
        verifiers_rng,
    ) = test_init::<N, D>(false);

    let (state, message_a) = SelfCompiler94::first(
        &statement,
        &provers_witnesses,
        &mut provers_rng,
    );
    let challenge = SelfCompiler94::<Schnorr>::second(
        &mut verifiers_rng.clone(),
    );
    // Third message
    let proof = SelfCompiler94::third(
        &statement,
        state,
        &provers_witnesses,
        &challenge,
        &mut provers_rng,
    );

    assert!(!SelfCompiler94::verify(
        &statement, &message_a, &challenge, &proof
    ));
}

#[test]
fn cds_hvzk_works() {
    const N: usize = 64;
    const D: usize = 1;
    let (_protocol, statement, ..) =
        test_init::<N, D>(false);

    let (a, c, z) =
        SelfCompiler94::<Schnorr>::simulate(&statement);

    assert!(SelfCompiler94::verify(&statement, &a, &c, &z));
}
