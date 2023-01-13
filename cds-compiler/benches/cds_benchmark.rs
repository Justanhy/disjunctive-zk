use core::fmt;
use std::{borrow::BorrowMut, time::Duration};

use cds_compiler::*;
use criterion::{
    black_box, criterion_group, criterion_main, Bencher, BenchmarkId,
    Criterion, Throughput,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use schnorr::*;

fn bench_init(n: usize, d: usize) -> CDS94Test {
    // INIT //
    assert!(d <= n);
    // closure to generate random witnesses
    let m = |_| Scalar::random(&mut ChaCha20Rng::from_entropy());
    // generate witnesses
    let actual_witnesses: Vec<Scalar> = (0..n)
        .map(m)
        .collect();
    // generate the prover's witnesses - for inactive clauses the prover generates a random witness
    let provers_witnesses: Vec<Scalar> = actual_witnesses
        .to_owned()
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if i < d {
                s.clone()
            } else {
                Scalar::random(&mut ChaCha20Rng::from_entropy())
            }
        })
        .collect();
    // vector of booleans indicating which clauses are active
    let active_clauses: Vec<bool> = (0..n)
        .map(|i| i < d)
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
    let verifiers: Vec<SchnorrVerifier> = (0..n)
        .map(|_| SchnorrVerifier::new())
        .collect();

    let protocol = CDS94::init(d, n, &protocols, &provers, &verifiers);
    let prover: CDS94Prover =
        CDS94Prover::new(n, &provers_witnesses, &active_clauses);

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
        write!(f, "{}", self.0)
    }
}

fn verifier(verifier_params: &VerifierBenchParam) -> bool {
    CDS94::verify(
        &verifier_params.0,
        &verifier_params.1,
        &verifier_params.2,
        &verifier_params.3,
    )
}

struct VerifierBenchParam(
    CDS94,
    Vec<RistrettoPoint>,
    Scalar,
    Vec<(Scalar, Scalar)>,
);

impl fmt::Display for VerifierBenchParam {
    /// Implementation of Display for the Benchmark parameters given to the CDS94 Verifier
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub fn cds94_benchmark(c: &mut Criterion) {
    let ns: [usize; 8] = [2, 4, 8, 16, 32, 64, 128, 255];

    let mut group = c.benchmark_group("cds94_benchmark");
    for n in ns.into_iter() {
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
        ) = bench_init(n, 1);

        let challenge = Scalar::random(&mut cdsverifier.get_rng());

        let mut proverparams: ProverBenchParam = ProverBenchParam(
            protocol.clone(),
            cdsprover,
            active_clauses,
            challenge,
        );
        group.measurement_time(Duration::from_secs(10));
        group.bench_with_input(
            BenchmarkId::new("prover_bench", &proverparams),
            &mut proverparams,
            |b, s| {
                b.iter(|| {
                    prover(s.0.clone(), s.1.clone(), s.2.clone(), s.3.clone())
                })
            },
        );

        let (commitment, proof) = prover(
            proverparams.0,
            proverparams.1,
            proverparams.2,
            proverparams.3,
        );

        let v_params: VerifierBenchParam =
            VerifierBenchParam(protocol, commitment, challenge, proof);

        group.bench_with_input(
            BenchmarkId::new("verifier_bench", &v_params),
            &v_params,
            |b, s| b.iter(|| verifier(s)),
        );
    }
    group.finish();
}

criterion_group!(benches, cds94_benchmark);
criterion_main!(benches);
