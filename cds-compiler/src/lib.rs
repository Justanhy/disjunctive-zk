pub extern crate curve25519_dalek_ml as curve25519_dalek;
extern crate itertools;
extern crate rand_chacha;
extern crate rand_core;
pub extern crate shamir_ss;
pub extern crate sigmazk;
pub mod compiler;

use curve25519_dalek::scalar::Scalar;

pub use compiler::*;
use itertools::{izip, Itertools};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use shamir_ss::vsss_rs::curve25519::WrappedScalar;
use shamir_ss::{Shamir, Share, WithShares};
use sigmazk::{
    Schnorr, SchnorrProver, SchnorrTranscript, SchnorrVerifier, SigmaProtocol,
    SigmaProver, SigmaTranscript, SigmaVerifier,
};
use std::fmt;

#[derive(Clone, Debug)]
pub struct CDS94Prover {
    /// Needs to have index of active clauses
    /// Needs to have list of witnesses for each active
    /// clause
    active_clauses: Vec<bool>,
    witnesses: Vec<Scalar>,
    prover_rng: ChaCha20Rng,
}

impl SigmaProver<ChaCha20Rng> for CDS94Prover {
    type Protocol = CDS94;

    fn get_rng(&self) -> ChaCha20Rng {
        self.prover_rng
            .clone()
    }
}

impl CDS94Prover {
    pub fn new(
        n: usize,
        witnesses: &Vec<Scalar>,
        active_clauses: &Vec<bool>,
    ) -> Self {
        Self {
            witnesses: witnesses.to_owned(),
            active_clauses: active_clauses.to_owned(),
            prover_rng: ChaCha20Rng::from_entropy(),
        }
    }

    pub fn borrow_witnesses(&self) -> &Vec<Scalar> {
        &self.witnesses
    }
}

#[derive(Clone, Debug)]
pub struct CDS94Verifier {
    verifier_rng: ChaCha20Rng,
}

impl SigmaVerifier<ChaCha20Rng> for CDS94Verifier {
    type Protocol = CDS94;

    fn get_rng(&self) -> ChaCha20Rng {
        self.verifier_rng
            .clone()
    }
}

impl CDS94Verifier {
    pub fn new() -> Self {
        Self {
            verifier_rng: ChaCha20Rng::from_entropy(),
        }
    }
}

pub type CDS94Test = (
    CDS94,
    CDS94Prover,
    CDS94Verifier,
    Vec<Box<Schnorr>>,
    Vec<SchnorrProver>,
    Vec<SchnorrVerifier>,
    Vec<Scalar>,
    Vec<Scalar>,
    Vec<bool>,
);

#[cfg(test)]
pub mod tests {

    use super::*;

    fn test_init<const N: usize, const D: usize>() -> CDS94Test {
        // INIT //
        assert!(D <= N);
        // closure to generate random witnesses
        let m = |_| Scalar::random(&mut ChaCha20Rng::from_entropy());
        // generate witnesses
        let actual_witnesses: Vec<Scalar> = (0..N)
            .map(m)
            .collect();
        // generate the prover's witnesses - for inactive clauses
        // the prover generates a random witness
        let provers_witnesses: Vec<Scalar> = actual_witnesses
            .to_owned()
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if i < D {
                    s.clone()
                } else {
                    Scalar::random(&mut ChaCha20Rng::from_entropy())
                }
            })
            .collect();
        // vector of booleans indicating which clauses are active
        let active_clauses: Vec<bool> = (0..N)
            .map(|i| i < D)
            .collect();
        // generate the statement (aka protocol) for each clause
        let protocols = actual_witnesses
            .to_owned()
            .iter()
            .map(|w| Box::new(Schnorr::init(*w)))
            .collect_vec();
        // generate the prover for each clause
        let provers = provers_witnesses
            .to_owned()
            .iter()
            .map(|w| SchnorrProver::new(&w))
            .collect_vec();
        // generate the verifier for each clause
        let verifiers = (0..N)
            .map(|_| SchnorrVerifier::new())
            .collect_vec();

        let protocol = CDS94::init(D, N, &protocols, &provers, &verifiers);
        let prover: CDS94Prover =
            CDS94Prover::new(N, &provers_witnesses, &active_clauses);

        let verifier: CDS94Verifier = CDS94Verifier::new();

        (
            protocol,
            prover,
            verifier,
            protocols,
            provers,
            verifiers,
            actual_witnesses,
            provers_witnesses,
            active_clauses,
        )
    }

    #[test]
    fn first_message_works() {
        const N: usize = 2;
        const D: usize = 1;
        let (
            protocol,
            cdsprover,
            _cdsverifier,
            _protocols,
            _provers,
            _verifiers,
            actual_witnesses,
            provers_witnesses,
            active_clauses,
        ) = test_init::<N, D>();

        let (transcripts, commitments) = CDS94::first(
            &protocol,
            &provers_witnesses,
            &mut cdsprover.get_rng(),
            &active_clauses,
        );
        assert!(commitments.len() == N);
        let (_, testc) = Schnorr::first(
            &protocol.protocols[0],
            &actual_witnesses[0],
            &mut protocol.provers[0].get_rng(),
            &(),
        );
        assert!(testc == commitments[0]);
        assert!(
            commitments[0]
                == transcripts[0]
                    .get_commitment()
                    .unwrap()
        );
        assert!(
            commitments[1]
                == transcripts[1]
                    .get_commitment()
                    .unwrap()
        );
    }

    #[test]
    fn third_message_works() {
        const N: usize = 2;
        const D: usize = 1;
        let (
            protocol,
            cdsprover,
            cdsverifier,
            _protocols,
            _provers,
            _verifiers,
            _actual_witnesses,
            provers_witnesses,
            active_clauses,
        ) = test_init::<N, D>();

        let (transcripts, commitments) = CDS94::first(
            &protocol,
            &provers_witnesses,
            &mut cdsprover.get_rng(),
            &active_clauses,
        );
        let challenge = CDS94::second(&mut cdsverifier.get_rng());
        // Third message
        let proof = CDS94::third(
            &protocol,
            transcripts,
            cdsprover.borrow_witnesses(),
            &challenge,
            &mut cdsprover.get_rng(),
            &active_clauses,
        );

        assert!(CDS94::verify(&protocol, &commitments, &challenge, &proof));
    }

    #[test]
    fn cds_works() {
        // INIT //
        // number of clauses
        const N: usize = 255;
        const D: usize = 200;
        let (
            protocol,
            cdsprover,
            cdsverifier,
            _protocols,
            _provers,
            _verifiers,
            _actual_witnesses,
            provers_witnesses,
            active_clauses,
        ) = test_init::<N, D>();

        // First message
        let (transcripts, commitments) = CDS94::first(
            &protocol,
            &provers_witnesses,
            &mut cdsprover.get_rng(),
            &active_clauses,
        );
        // Second message
        let challenge = CDS94::second(&mut cdsverifier.get_rng());
        // Third message
        let proof = CDS94::third(
            &protocol,
            transcripts,
            cdsprover.borrow_witnesses(),
            &challenge,
            &mut cdsprover.get_rng(),
            &active_clauses,
        );
        assert!(CDS94::verify(&protocol, &commitments, &challenge, &proof));
    }
}
