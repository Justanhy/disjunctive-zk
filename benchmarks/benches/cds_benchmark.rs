//! Benchmarking for the CDS94 compiler
use core::fmt;
use std::time::Duration;

use crate::curve25519_dalek::ristretto::CompressedRistretto;
use crate::curve25519_dalek::scalar::Scalar;
use benchmarks::plot_proofsize;
use cds_compiler::*;
use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sigmazk::*;

struct CDS94Benchmark {
    protocol: CDS94,
    cdsprover: CDS94Prover,
    cdsverifier: CDS94Verifier,
    active_clauses: Vec<bool>,
}

fn bench_init(n: usize, d: usize) -> CDS94Benchmark {
    // INIT //
    assert!(d <= n);
    // closure to generate random witnesses
    let m = |_| Scalar::random(&mut ChaCha20Rng::from_entropy());
    // generate witnesses
    let actual_witnesses: Vec<Scalar> = (0..n)
        .map(m)
        .collect();
    // generate the prover's witnesses - for inactive clauses
    // the prover generates a random witness
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

    CDS94Benchmark {
        protocol,
        cdsprover: prover,
        cdsverifier: verifier,
        active_clauses,
    }
}

struct ProverBenchParam {
    protocol: CDS94,
    prover: CDS94Prover,
    active_clauses: Vec<bool>,
    challenge: Scalar,
}

impl fmt::Display for ProverBenchParam {
    /// Implementation of Display for the Benchmark
    /// parameters given to the CDS94 prover
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<clauses: {}, threshold: {}>",
            self.protocol
                .n,
            self.protocol
                .threshold
        )
    }
}

struct VerifierBenchParam {
    pub statement: CDS94,
    pub message_a: Vec<CompressedRistretto>,
    pub challenge: Scalar,
    pub message_z: Vec<(Scalar, Scalar)>,
}

impl fmt::Display for VerifierBenchParam {
    /// Implementation of Display for the Benchmark
    /// parameters given to the CDS94 Verifier
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<clauses: {}, threshold: {}>",
            self.statement
                .n,
            self.statement
                .threshold
        )
    }
}

pub fn cds94_benchmark(c: &mut Criterion) {
    const Q: usize = 8;
    let mut ns: Vec<usize> = vec![0; Q];
    for i in 1..=Q {
        ns[i - 1] = 1 << i;
    }
    ns[Q - 1] -= 1; // needed due to limitation of 3rd party library for Shamir
    let mut communication_sizes: Vec<usize> = Vec::with_capacity(Q - 1);

    let mut group = c.benchmark_group("cds94_benchmark");
    for n in ns.iter() {
        let CDS94Benchmark {
            protocol,
            cdsprover,
            cdsverifier,
            active_clauses,
        } = bench_init(*n, 1);

        let challenge = Scalar::random(&mut cdsverifier.get_rng());

        let mut proverparams: ProverBenchParam = ProverBenchParam {
            protocol: protocol.clone(),
            prover: cdsprover,
            active_clauses,
            challenge,
        };

        group.throughput(Throughput::Elements(*n as u64));
        group.measurement_time(Duration::from_secs(10));

        let mut message_a: Vec<CompressedRistretto> = Vec::new();
        let mut message_z: Vec<(Scalar, Scalar)> = Vec::new();

        group.bench_with_input(
            BenchmarkId::new("prover_bench", &proverparams),
            &mut proverparams,
            |b, s| {
                b.iter(|| {
                    let (transcripts, commitments) = CDS94::first(
                        &s.protocol,
                        s.prover
                            .borrow_witnesses(),
                        &mut s
                            .prover
                            .get_rng(),
                        &s.active_clauses,
                    );
                    let proof = CDS94::third(
                        &s.protocol,
                        transcripts,
                        s.prover
                            .borrow_witnesses(),
                        &s.challenge,
                        &mut s
                            .prover
                            .get_rng(),
                        &s.active_clauses,
                    );
                    // Should have negligible cost
                    message_a = commitments;
                    message_z = proof;
                })
            },
        );

        communication_sizes.push(
            message_a.len() * 32
                + message_z.len() * 64
                + challenge
                    .as_bytes()
                    .len(),
        );

        let v_params: VerifierBenchParam = VerifierBenchParam {
            statement: protocol,
            message_a,
            challenge,
            message_z,
        };

        group.bench_with_input(
            BenchmarkId::new("verifier_bench", &v_params),
            &v_params,
            |b, s| {
                b.iter(|| {
                    CDS94::verify(
                        &s.statement,
                        &s.message_a,
                        &s.challenge,
                        &s.message_z,
                    )
                })
            },
        );
    }
    group.finish();
    let filename = format!("proofsize_plots/cds/proofsize{}", ns.len());
    plot_proofsize(ns, communication_sizes, "CDS94".into(), filename);
}

criterion_group!(benches, cds94_benchmark);
criterion_main!(benches);
