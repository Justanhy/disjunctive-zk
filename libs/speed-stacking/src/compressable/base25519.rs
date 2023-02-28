use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use wrapped_ristretto::ristretto::WrappedRistretto;
use wrapped_ristretto::scalar::WrappedScalar;

use crate::homomorphism::Hom;

use super::base::*;

pub struct Hom25519;

impl Hom<WrappedScalar, WrappedScalar> for Hom25519 {
    fn f(a: &Vec<WrappedScalar>) -> WrappedScalar {
        a.iter()
            .sum::<WrappedScalar>()
    }
}

pub type Base25519 =
    Base<WrappedRistretto, WrappedScalar, WrappedScalar, Hom25519>;

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sigmazk::SigmaProtocol;

    use super::*;

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
        let g2_public_key = Hom25519::f(&witness);
        let statement = BaseStatement {
            generators,
            g1_public_key,
            g2_public_key,
        };

        let prover_rng = &mut ChaCha20Rng::from_seed([0u8; 32]);
        let (state, message_a) =
            Base25519::first(&statement, &witness, prover_rng, &());
        let challenge = Base25519::second(&mut ChaCha20Rng::from_entropy());
        let message_z = Base25519::third(
            &statement,
            state,
            &witness,
            &challenge,
            prover_rng,
            &(),
        );
        assert!(Base25519::verify(
            &statement, &message_a, &challenge, &message_z
        ));
    }
}
