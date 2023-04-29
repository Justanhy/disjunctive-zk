use wrapped_ristretto::ristretto::WrappedRistretto;
use wrapped_ristretto::scalar::WrappedScalar;

use crate::homomorphism::Hom;

use super::base::*;

#[derive(Clone, Copy, Debug)]
pub struct Hom25519;

impl Hom25519 {}

impl Hom<WrappedScalar, WrappedScalar> for Hom25519 {
    /// We override default implementation of this function
    /// for better performance
    fn f(&self, x: &Vec<WrappedScalar>) -> WrappedScalar {
        x.iter()
            .sum()
    }

    fn fleft(&self, x: &[WrappedScalar]) -> WrappedScalar {
        x.iter()
            .sum()
    }

    fn fright(&self, x: &[WrappedScalar]) -> WrappedScalar {
        x.iter()
            .sum()
    }
}

pub type Base25519 =
    Base<WrappedRistretto, WrappedScalar, WrappedScalar, Hom25519>;

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sigmazk::SigmaProtocol;
    use wrapped_ristretto::ristretto::WrappedRistretto;
    use wrapped_ristretto::scalar::WrappedScalar;

    use crate::compressable::base25519::{Base25519, Hom25519};
    use crate::compressable::{multi_exponentiation, BaseStatement};
    use crate::homomorphism::Hom;

    #[test]
    fn it_works() {
        let generators =
            vec![
                WrappedRistretto::random(&mut ChaCha20Rng::from_entropy());
                10
            ];
        let witness =
            vec![WrappedScalar::random(&mut ChaCha20Rng::from_entropy(),); 10];
        let g1_public_key = multi_exponentiation(&generators, &witness);
        let g2_public_key = Hom25519.f(&witness);
        let statement = BaseStatement {
            generators,
            f: Hom25519,
            g1_public_key,
            g2_public_key,
        };

        let prover_rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let (state, message_a) =
            Base25519::first(&statement, &witness, prover_rng);
        let challenge = Base25519::second(&mut ChaCha20Rng::from_entropy());
        let message_z = Base25519::third(
            &statement, state, &witness, &challenge, prover_rng,
        );
        assert!(Base25519::verify(
            &statement, &message_a, &challenge, &message_z
        ));
    }

    #[test]
    fn it_fails() {
        let generators =
            vec![
                WrappedRistretto::random(&mut ChaCha20Rng::from_entropy());
                10
            ];
        let actual_witness =
            vec![WrappedScalar::random(&mut ChaCha20Rng::from_entropy(),); 10];
        let false_witness =
            vec![WrappedScalar::random(&mut ChaCha20Rng::from_entropy(),); 10];
        let g1_public_key = multi_exponentiation(&generators, &actual_witness);
        let g2_public_key = Hom25519.f(&actual_witness);
        let statement = BaseStatement {
            generators,
            f: Hom25519,
            g1_public_key,
            g2_public_key,
        };

        let prover_rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let (state, message_a) =
            Base25519::first(&statement, &false_witness, prover_rng);
        let challenge = Base25519::second(&mut ChaCha20Rng::from_entropy());
        let message_z = Base25519::third(
            &statement,
            state,
            &false_witness,
            &challenge,
            prover_rng,
        );
        assert!(!Base25519::verify(
            &statement, &message_a, &challenge, &message_z
        ));
    }
}
