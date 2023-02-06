use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sigmazk::SigmaProtocol;

use super::{SelfStacker, StackedStatement, StackedWitness};
use crate::commitment_scheme::comm::PartialBindingCommScheme;
use crate::commitment_scheme::qbinding::{
    BindingIndex, PublicParams, QBinding,
};
use crate::stackable::schnorr::Schnorr;
use crate::stackable::Stackable;

use selfstack_macro::selfstack;

type S2Test = SelfStacker<Schnorr>;

// fn binding_path(clauses: usize, binding_index: usize) ->
// Vec<BindingIndex> {     let mut path = Vec::new();
//     let mut i = binding_index;

//     let two = clauses / 2;
//     let one = two / 2;
//     let three = two + one;
//     let four = clauses;
//     if binding_index <= one {
//         path.push(BindingIndex::One);
//         let tail = binding_path()
//     } else if binding_index <= two {
//         path.push(BindingIndex::Two);
//     } else if binding_index <= three {
//         path.push(BindingIndex::Three);
//     } else if binding_index <= four {
//         path.push(BindingIndex::Four);
//     }
// }

#[test]
fn selfstacker_works() {
    const CLAUSES: usize = 128;
    const BI: usize = 78;
    // TODO: Macro should work with variables (not just
    // literals)
    selfstack!(128, Schnorr, StackedSig);
    assert!(StackedSig::CLAUSES == CLAUSES);
    let witness = Scalar::random(&mut ChaCha20Rng::from_seed([0u8; 32]));
    let mut pk: Vec<RistrettoPoint> = Vec::with_capacity(CLAUSES);
    for i in 1..=128 {
        if i == BI {
            pk.push(&witness * RISTRETTO_BASEPOINT_POINT)
        } else {
            pk.push(RistrettoPoint::random(&mut ChaCha20Rng::from_entropy()))
        }
    }
}

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
        S2Test::first(&s2_statement, &s2_witness, &mut rng.clone(), &());
    let (actual_state, actual_a) =
        S2Test::first(&s2_statement, &valid_witness, rng, &());
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
        S2Test::first(&s2_statement, &s2_witness, &mut rng.clone(), &());
    let challenge = S2Test::second(verifier_rng);
    let message_z =
        S2Test::third(&s2_statement, &state, &s2_witness, &challenge, rng, &());
    assert!(S2Test::verify(
        &s2_statement,
        &message_a,
        &challenge,
        &message_z
    ));
}

// #[test]
// fn selfstack_works() {
//     let ss = SelfStacker::<>::selfstack(
//         255,
//         3,
//         Schnorr::init(Scalar::from(1u8)),
//     );
//     <SelfStacker as Stackable>::CLAUSES == 255;
// }
