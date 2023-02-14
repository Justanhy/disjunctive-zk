// use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
// use curve25519_dalek::ristretto::RistrettoPoint;
// use curve25519_dalek::scalar::Scalar;
// use rand::SeedableRng;
// use rand_chacha::ChaCha20Rng;
// use sigmazk::SigmaProtocol;

// use super::{SelfStacker, StackedStatement,
// StackedWitness};
// use crate::commitment_scheme::comm::PartialBindingCommScheme;
// use crate::commitment_scheme::halfbinding::{HalfBinding,
// PublicParams, Side};
// use crate::commitment_scheme::qbinding::{BindingIndex,
// QBinding}; use crate::stackable::schnorr::Schnorr;
// use crate::stackable::Stackable;

// type S2Test = SelfStacker<Schnorr>;

// /// 1-indexed (index starts from 1 instead of 0)
// fn binding_path(clauses: usize, binding_index: usize) ->
// Vec<Side> {     if clauses == 1 {
//         return Vec::new();
//     }

//     let half = clauses / 2;
//     if binding_index <= half {
//         let mut path = binding_path(half, binding_index);
//         path.push(Side::One);
//         path
//     } else {
//         let mut path = binding_path(half, binding_index -
// half);         path.push(Side::Two);
//         path
//     }
// }

// // macro_rules! compile {
// //     ($s:expr, $pp:expr, $pks:expr, $sk:expr) => {{
// //         let sk = StackedWitness::init($sk, Side::One);
// //         let len = $pks.len() / 2;
// //         let mut pk: Vec<_> = Vec::with_capacity(len);
// //         let mut pks = $pks.into_iter();
// //         for _ in 0..len {
// //             let l = pks
// //                 .next()
// //                 .unwrap();
// //             let r = pks
// //                 .next()
// //                 .unwrap();
// //             pk.push(StackedStatement::<$s>::new(&$pp,
// l, // r))         }
// //         (pk, sk)
// //     }};
// // }

// // macro_rules! use_compilen {
// //     (1 , $ pp : expr , $ pks : expr , $ sk : expr) =>
// {{ //         compile!(S1, $pp, $pks, $sk)
// //     }};
// //     (2 , $ pp : expr , $ pks : expr , $ sk : expr) =>
// {{ //         let (pk, sk) = compile!(S2, $pp, $pks,
// $sk); //         use_compilen!(1, $pp, pk, sk)
// //     }};
// //     (3 , $ pp : expr , $ pks : expr , $ sk : expr) =>
// {{ //         let (pk, sk) = compile!(S3, $pp, $pks,
// $sk); //         use_compilen!(2, $pp, pk, sk)
// //     }};
// //     (4 , $ pp : expr , $ pks : expr , $ sk : expr) =>
// {{ //         let (pk, sk) = compile!(S4, $pp, $pks,
// $sk); //         use_compilen!(3, $pp, pk, sk)
// //     }};
// //     (5 , $ pp : expr , $ pks : expr , $ sk : expr) =>
// {{ //         let (pk, sk) = compile!(S5, $pp, $pks,
// $sk); //         use_compilen!(4, $pp, pk, sk)
// //     }};
// //     (6 , $ pp : expr , $ pks : expr , $ sk : expr) =>
// {{ //         let (pk, sk) = compile!(S6, $pp, $pks,
// $sk); //         use_compilen!(5, $pp, pk, sk)
// //     }};
// //     (7 , $ pp : expr , $ pks : expr , $ sk : expr) =>
// {{ //         let (pk, sk) = compile!(S7, $pp, $pks,
// $sk); //         use_compilen!(6, $pp, pk, sk)
// //     }};
// // }

// // #[test]
// // fn selfstacker_works() {
// //     const CLAUSES: usize = 128;
// //     const BI: usize = 1;
// //     selfstack!(128, Schnorr, StackedSig);
// //     assert!(StackedSig::CLAUSES == CLAUSES);

// //     let witness = Scalar::random(&mut
// // ChaCha20Rng::from_seed([0u8; 32]));
// //     let base_statement = Schnorr::init(witness);
// //     let pp = HalfBinding::setup(&mut
// // ChaCha20Rng::from_entropy());

// //     let mut pk: Vec<Schnorr> =
// // Vec::with_capacity(CLAUSES);     for i in 1..=128 {
// //         if i == BI {
// //             pk.push(Schnorr::init(witness))
// //         } else {
// //             pk.push(Schnorr::init(Scalar::random(
// //                 &mut ChaCha20Rng::from_entropy(),
// //             )))
// //         }
// //     }
// //     let (pk, sk) = use_compilen!(7, pp, pk, witness);
// // }

// #[allow(dead_code)]
// struct StackerTest {
//     actual_witness: Scalar,
//     provers_witness: Scalar,
//     base_schnorr: Schnorr,
//     pp: PublicParams,
//     s2_statement: StackedStatement<Schnorr>,
//     valid_witness: StackedWitness<Scalar>,
//     s2_witness: StackedWitness<Scalar>,
// }

// fn testinit(rng: &mut ChaCha20Rng) -> StackerTest {
//     let actual_witness = Scalar::from_bits([0u8; 32]);
//     let provers_witness = Scalar::from_bits([0u8; 32]);
//     let base_schnorr = Schnorr::init(actual_witness);
//     let dummy_schnorr =
//         Schnorr::init(Scalar::random(&mut
// ChaCha20Rng::from_entropy()));     let pp =
// HalfBinding::setup(rng);     let s2_statement:
// StackedStatement<Schnorr> =
//         StackedStatement::new(&pp, base_schnorr,
// dummy_schnorr);     let s2_witness:
// StackedWitness<Scalar> =
//         StackedWitness::init(provers_witness, Side::One);
//     let valid_witness: StackedWitness<Scalar> =
//         StackedWitness::init(actual_witness, Side::One);
//     StackerTest {
//         actual_witness,
//         provers_witness,
//         base_schnorr,
//         pp,
//         s2_statement,
//         valid_witness,
//         s2_witness,
//     }
// }

// #[test]
// fn first_message_works() {
//     let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
//     let StackerTest {
//         s2_statement,
//         valid_witness,
//         s2_witness,
//         ..
//     } = testinit(rng);

//     let (state, message_a) =
//         S2Test::first(&s2_statement, &s2_witness, &mut
// rng.clone(), &());     let (actual_state, actual_a) =
//         S2Test::first(&s2_statement, &valid_witness, rng,
// &());     assert!(message_a == actual_a);
//     assert!(state == actual_state);
// }

// #[test]
// fn third_message_works() {
//     let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
//     let verifier_rng = &mut ChaCha20Rng::from_entropy();
//     let StackerTest {
//         s2_statement,
//         s2_witness,
//         ..
//     } = testinit(rng);

//     let (state, message_a) =
//         S2Test::first(&s2_statement, &s2_witness, &mut
// rng.clone(), &());     let challenge =
// S2Test::second(verifier_rng);     let message_z =
//         S2Test::third(&s2_statement, &state, &s2_witness,
// &challenge, rng, &());     assert!(S2Test::verify(
//         &s2_statement,
//         &message_a,
//         &challenge,
//         &message_z
//     ));
// }

// // #[test]
// // fn selfstack_works() {
// //     let ss = SelfStacker::<>::selfstack(
// //         255,
// //         3,
// //         Schnorr::init(Scalar::from(1u8)),
// //     );
// //     <SelfStacker as Stackable>::CLAUSES == 255;
// // }
