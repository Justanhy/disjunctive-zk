use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sigmazk::SigmaProtocol;

use crate::commitment_scheme::qbinding::{
    BindingIndex, PublicParams, QBinding,
};
use crate::stackable::schnorr::Schnorr;

use super::{StackedSigma, StackedStatement, StackedWitness};

type S2 = StackedSigma<Schnorr>;

#[allow(dead_code)]
struct StackerTest {
    actual_witness: Scalar,
    provers_witness: Scalar,
    base_schnorr: Schnorr,
    pp: PublicParams,
    s2_statement: StackedStatement<Schnorr>,
    valid_witness: StackedWitness<Schnorr>,
    s2_witness: StackedWitness<Schnorr>,
}

fn testinit(rng: &mut ChaCha20Rng) -> StackerTest {
    let actual_witness = Scalar::from_bits([0u8; 32]);
    let provers_witness = Scalar::from_bits([0u8; 32]);
    let base_schnorr = Schnorr::init(actual_witness);
    let pp = QBinding::setup(rng);
    let s2_statement: StackedStatement<Schnorr> = StackedStatement::new(
        &pp,
        base_schnorr,
        base_schnorr,
        base_schnorr,
        base_schnorr,
    );
    let s2_witness: StackedWitness<Schnorr> =
        StackedWitness::init(provers_witness, BindingIndex::One);
    let valid_witness: StackedWitness<Schnorr> =
        StackedWitness::init(actual_witness, BindingIndex::One);
    StackerTest {
        actual_witness,
        provers_witness,
        base_schnorr,
        pp,
        s2_statement,
        valid_witness,
        s2_witness,
    }
}

#[test]
fn first_message_works() {
    let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
    let StackerTest {
        s2_statement,
        valid_witness,
        s2_witness,
        ..
    } = testinit(rng);

    let (state, message_a) =
        S2::first(&s2_statement, &s2_witness, &mut rng.clone(), &());
    let (actual_state, actual_a) =
        S2::first(&s2_statement, &valid_witness, rng, &());
    assert!(message_a == actual_a);
    assert!(state == actual_state);
}

#[test]
fn third_message_works() {
    let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
    let verifier_rng = &mut ChaCha20Rng::from_entropy();
    let StackerTest {
        s2_statement,
        s2_witness,
        ..
    } = testinit(rng);

    let (state, message_a) =
        S2::first(&s2_statement, &s2_witness, &mut rng.clone(), &());
    let challenge = S2::second(verifier_rng);
    let message_z =
        S2::third(&s2_statement, &state, &s2_witness, &challenge, rng, &());
    assert!(S2::verify(
        &s2_statement,
        &message_a,
        &challenge,
        &message_z
    ));
}
