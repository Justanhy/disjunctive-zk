//! Benchmarking for the CDS94 compiler
use core::fmt;
use std::collections::HashSet;
use std::time::Duration;

use benchmarks::{plot_dir, plot_proofsize};
use cds_compiler::selfcompiler::{
    CompiledZ94, SelfCompiler94, Statement94, Witness94,
};
use cds_compiler::*;
use criterion::{
    criterion_group, criterion_main, BenchmarkId,
    Criterion, Throughput,
};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sigmazk::message::Message;
use sigmazk::*;

struct CDS94Benchmark {
    protocol: SelfCompiler94<Schnorr>,
    statement: Statement94<Schnorr>,
    prover_rng: ChaCha20Rng,
    verifier_rng: ChaCha20Rng,
    witness: Witness94<Schnorr>,
}

fn bench_init(n: usize, d: usize) -> CDS94Benchmark {
    // INIT //
    assert!(d <= n);
    // closure to generate random witnesses
    let m = |_| {
        Scalar::random(&mut ChaCha20Rng::from_entropy())
    };
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
                Scalar::random(
                    &mut ChaCha20Rng::from_entropy(),
                )
            }
        })
        .collect();
    // vector of booleans indicating which clauses are active
    let active_clauses: HashSet<usize> = (0..d).collect();
    // generate the statement (aka protocol) for each clause
    let statements: Vec<Schnorr> = actual_witnesses
        .to_owned()
        .iter()
        .map(|w| Schnorr::init(*w))
        .collect();

    let protocol = SelfCompiler94::new(n, d);

    let statement = Statement94::new(n, d, statements);

    let witness =
        Witness94::new(provers_witnesses, active_clauses);

    let prover_rng = ChaCha20Rng::from_seed([0u8; 32]);
    let verifier_rng = ChaCha20Rng::from_seed([1u8; 32]);

    CDS94Benchmark {
        protocol,
        statement,
        prover_rng,
        verifier_rng,
        witness,
    }
}

struct ProverBenchParam {
    statement: Statement94<Schnorr>,
    prover_rng: ChaCha20Rng,
    witness: Witness94<Schnorr>,
    challenge: Scalar,
}

impl fmt::Display for ProverBenchParam {
    /// Implementation of Display for the Benchmark
    /// parameters given to the CDS94 prover
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<clauses: {}, threshold: {}>",
            self.statement
                .clauses(),
            self.statement
                .threshold()
        )
    }
}

struct VerifierBenchParam {
    pub statement: Statement94<Schnorr>,
    pub message_a: Vec<CompressedRistretto>,
    pub challenge: Scalar,
    pub message_z: Vec<CompiledZ94<Schnorr>>,
}

impl fmt::Display for VerifierBenchParam {
    /// Implementation of Display for the Benchmark
    /// parameters given to the CDS94 Verifier
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<clauses: {}, threshold: {}>",
            self.statement
                .clauses(),
            self.statement
                .threshold()
        )
    }
}

pub fn cds94_benchmark(c: &mut Criterion) {
    const Q: usize = 8;
    let mut ns: Vec<usize> = vec![0; Q];
    for i in 1..=Q {
        ns[i - 1] = 1 << i;
    }
    let mut communication_sizes: Vec<usize> =
        Vec::with_capacity(Q);

    let mut group = c.benchmark_group("cds94_benchmark");
    for n in ns.iter() {
        let CDS94Benchmark {
            protocol: _,
            statement,
            prover_rng,
            mut verifier_rng,
            witness,
        } = bench_init(*n, 1);

        let challenge = Scalar::random(&mut verifier_rng);

        let mut proverparams: ProverBenchParam =
            ProverBenchParam {
                statement: statement.clone(),
                prover_rng,
                witness,
                challenge,
            };

        group.throughput(Throughput::Elements(*n as u64));
        group.measurement_time(Duration::from_secs(10));

        let mut message_a: Vec<CompressedRistretto> =
            Vec::new();
        let mut message_z: Vec<CompiledZ94<Schnorr>> =
            Vec::new();

        group.bench_with_input(
            BenchmarkId::new("prover_bench", &proverparams),
            &mut proverparams,
            |b, s| {
                b.iter(|| {
                    let prover_rng = &mut s
                        .prover_rng
                        .clone();
                    let (transcripts, commitments) =
                        SelfCompiler94::first(
                            &s.statement,
                            &s.witness,
                            prover_rng,
                        );
                    let proof = SelfCompiler94::third(
                        &s.statement,
                        transcripts,
                        &s.witness,
                        &s.challenge,
                        prover_rng,
                    );
                    // Should have negligible cost
                    message_a = commitments;
                    message_z = proof;
                })
            },
        );

        communication_sizes.push(
            message_a.size()
                + message_z.size()
                + challenge.size(),
        );

        let v_params: VerifierBenchParam =
            VerifierBenchParam {
                statement,
                message_a,
                challenge,
                message_z,
            };

        let verifier_rng = &mut ChaCha20Rng::from_entropy();

        group.bench_with_input(
            BenchmarkId::new("verifier_bench", &v_params),
            &v_params,
            |b, s| {
                b.iter(|| {
                    SelfCompiler94::<Schnorr>::second(
                        verifier_rng,
                    );
                    SelfCompiler94::verify(
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
    let filename = format!(
        "{}proofsize_plots/cds/proofsize{}",
        plot_dir,
        ns.len()
    );
    plot_proofsize(
        ns,
        communication_sizes,
        "CDS94".into(),
        filename,
    );
}

criterion_group!(benches, cds94_benchmark);
criterion_main!(benches);
