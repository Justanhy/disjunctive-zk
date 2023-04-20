use crate::commitment_scheme::qbinding::{PartialBindingCommScheme, QBinding};
use crate::stackable::schnorr::Schnorr;
use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sigmazk::SigmaProtocol;

use super::*;

#[cfg(test)]
mod test_selfstacker {
    use super::*;

    #[allow(dead_code)]
    struct StackerTest {
        actual_witness: Scalar,
        provers_witness: Scalar,
        base_schnorr: Schnorr,
        s2_statement: StackedStatement<Schnorr>,
        valid_witness: StackedWitness<Scalar>,
        s2_witness: StackedWitness<Scalar>,
    }

    fn testinit(
        rng: &mut ChaCha20Rng,
        clauses: usize,
        binding_index: usize,
    ) -> StackerTest {
        assert!(clauses > 1);
        assert!(binding_index > 0 && binding_index < clauses);

        // Handle witness
        let actual_witness = Scalar::from_bits([0u8; 32]);
        let provers_witness = Scalar::from_bits([0u8; 32]);
        // Initialise base sigma + remaining sigma instances
        let base_schnorr = Schnorr::init(actual_witness);
        let dummy_schnorr =
            Schnorr::init(Scalar::random(&mut ChaCha20Rng::from_entropy()));

        // Initialise stacked sigma protocol
        let stackedsigma = SelfStacker::new(clauses, base_schnorr);
        // Setup public parameters
        let (qbinding, binding_index) =
            QBinding::init(stackedsigma.q(), binding_index);
        let pp = qbinding.setup(rng);

        // Setup vector of statements and stacked statement
        let mut statements: Vec<Schnorr> =
            vec![dummy_schnorr; stackedsigma.clauses()]; // TODO: Might cause stackoverflow
        statements[binding_index.index()] = base_schnorr;
        let s2_statement: StackedStatement<Schnorr> =
            StackedStatement::new(pp, stackedsigma.q(), statements);

        // Setup stacked witness
        let s2_witness: StackedWitness<Scalar> =
            StackedWitness::init(provers_witness, binding_index);
        let valid_witness: StackedWitness<Scalar> =
            StackedWitness::init(actual_witness, binding_index);

        StackerTest {
            actual_witness,
            provers_witness,
            base_schnorr,
            s2_statement,
            valid_witness,
            s2_witness,
        }
    }

    #[test]
    fn first_message_works() {
        const CLAUSES: usize = 7;
        const B: usize = 5;
        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let StackerTest {
            s2_statement,
            valid_witness,
            s2_witness,
            ..
        } = testinit(rng, CLAUSES, B);

        let (state, message_a) = SelfStacker::first(
            &s2_statement,
            &s2_witness,
            &mut rng.clone(),
            &(),
        );
        let (actual_state, actual_a) =
            SelfStacker::first(&s2_statement, &valid_witness, rng, &());
        assert!(message_a == actual_a);
        assert!(state == actual_state);
    }

    #[test]
    fn third_message_works() {
        const Q: usize = 13;
        const CLAUSES: usize = 1 << Q;
        const B: usize = 5;

        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let verifier_rng = &mut ChaCha20Rng::from_entropy();
        let StackerTest {
            s2_statement,
            s2_witness,
            ..
        } = testinit(rng, CLAUSES, B);

        let (state, message_a) = SelfStacker::first(
            &s2_statement,
            &s2_witness,
            &mut rng.clone(),
            &(),
        );
        let challenge = SelfStacker::<Schnorr>::second(verifier_rng);
        let message_z = SelfStacker::third(
            &s2_statement,
            state,
            &s2_witness,
            &challenge,
            rng,
            &(),
        );
        assert!(SelfStacker::verify(
            &s2_statement,
            &message_a,
            &challenge,
            &message_z
        ));
    }

    #[test]
    fn it_fails() {
        const Q: usize = 4;
        const CLAUSES: usize = 1 << Q;
        const B: usize = 5;

        let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let verifier_rng = &mut ChaCha20Rng::from_entropy();
        let StackerTest {
            s2_statement,
            s2_witness,
            ..
        } = testinit(rng, CLAUSES, B);

        let (state, message_a) = SelfStacker::first(
            &s2_statement,
            &s2_witness,
            &mut rng.clone(),
            &(),
        );
        let given_challenge = SelfStacker::<Schnorr>::second(verifier_rng);
        let spoof_challenge =
            SelfStacker::<Schnorr>::second(&mut ChaCha20Rng::from_entropy());

        let message_z = SelfStacker::third(
            &s2_statement,
            state,
            &s2_witness,
            &spoof_challenge,
            rng,
            &(),
        );
        assert!(!SelfStacker::verify(
            &s2_statement,
            &message_a,
            &given_challenge,
            &message_z
        ));
    }

    // #[test]
    // fn selfstack_works() {
    //     const CLAUSES: usize = 50000;
    //     const B: usize = 1028;

    //     let rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
    //     let verifier_rng = &mut
    // ChaCha20Rng::from_entropy();

    //     let StackerTest {
    //         s2_statement,
    //         s2_witness,
    //         ..
    //     } = testinit(rng, CLAUSES, B);

    // }
}
