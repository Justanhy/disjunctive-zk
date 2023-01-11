use core::fmt;

use cds_compiler::*;
use criterion::{
    black_box, criterion_group, criterion_main, Bencher, BenchmarkId, Criterion,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use schnorr::*;

fn bench_init<const N: usize, const D: usize>() -> CDS94Test {
    // INIT //
    assert!(D <= N);
    // closure to generate random witnesses
    let m = |_| Scalar::random(&mut ChaCha20Rng::from_entropy());
    // generate witnesses
    let actual_witnesses: Vec<Scalar> = (0..N)
        .map(m)
        .collect();
    // generate the prover's witnesses - for inactive clauses the prover generates a random witness
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
    let protocols: Vec<Box<Schnorr>> = actual_witnesses
        .to_owned()
        .iter()
        .map(|w| Box::new(Schnorr::init(*w)))
        .collect();
    // generate the prover for each clause
    let provers: Vec<SchnorrProver> = provers_witnesses
        .to_owned()
        .iter()
        .map(|w| SchnorrProver::new(&w))
        .collect();
    // generate the verifier for each clause
    let verifiers: Vec<SchnorrVerifier> = (0..N)
        .map(|_| SchnorrVerifier::new())
        .collect();

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

fn prover(
    mut protocol: CDS94,
    cdsprover: CDS94Prover,
    active_clauses: Vec<bool>,
    challenge: Scalar,
) -> (Vec<RistrettoPoint>, Vec<(Scalar, Scalar)>) {
    let commitment = protocol.first_message(&active_clauses);
    let proof = protocol.second_message(
        cdsprover.borrow_witnesses(),
        challenge,
        &active_clauses,
        &mut cdsprover.get_rng(),
    );
    (commitment, proof)
}

struct ProverBenchParam(CDS94, CDS94Prover, Vec<bool>, Scalar);

impl fmt::Display for ProverBenchParam {
    /// Implementation of Display for the Benchmark parameters given to the CDS94 prover
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let n = self.0.n;
        let t = self
            .0
            .threshold;
        write!(
            f,
            "Clauses: {}, Active Clauses: {}, Threshold: {}",
            n,
            n - t + 1,
            t
        )
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let (
        protocol,
        cdsprover,
        cdsverifier,
        _protocols,
        _provers,
        _verifiers,
        _actual_witnesses,
        _provers_witnesses,
        active_clauses,
    ) = bench_init::<255, 200>();

    let challenge = Scalar::random(&mut cdsverifier.get_rng());

    let proverparams =
        ProverBenchParam(protocol, cdsprover, active_clauses, challenge);

    c.bench_with_input(
        BenchmarkId::new("proverbench", &proverparams),
        &proverparams,
        |b, s| {
            b.iter(|| {
                prover(s.0.clone(), s.1.clone(), s.2.clone(), s.3.clone())
            })
        },
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
