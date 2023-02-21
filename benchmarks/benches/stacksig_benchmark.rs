use std::fmt::Display;

use benchmarks::plot_proofsize;
use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sigmazk::SigmaProtocol;
use stacksig_compiler::stackable::schnorr::Schnorr;
use stacksig_compiler::stackable::Message;
use stacksig_compiler::stackers::*;

#[allow(dead_code)]
pub struct StackerBench {
    actual_witness: Scalar,
    provers_witness: Scalar,
    base_schnorr: Schnorr,
    s2_statement: StackedStatement<Schnorr>,
    valid_witness: StackedWitness<Scalar>,
    s2_witness: StackedWitness<Scalar>,
}

fn bench_init(
    rng: &mut ChaCha20Rng,
    clauses: usize,
    binding_index: usize,
) -> StackerBench {
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

    StackerBench {
        actual_witness,
        provers_witness,
        base_schnorr,
        s2_statement,
        valid_witness,
        s2_witness,
    }
}

struct ProverBenchParam {
    pub statement: StackedStatement<Schnorr>,
    pub witness: StackedWitness<Scalar>,
    pub challenge: Scalar,
    pub rng: ChaCha20Rng,
}

impl Display for ProverBenchParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<q: {}, clauses: {}>",
            self.statement
                .height(),
            self.statement
                .clauses(),
        )
    }
}

struct VerifierBenchParam {
    pub statement: StackedStatement<Schnorr>,
    pub message_a: StackedA,
    pub message_z: StackedZ<Schnorr>,
    pub challenge: Scalar,
}

impl Display for VerifierBenchParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<q: {}, clauses: {}>",
            self.statement
                .height(),
            self.statement
                .clauses(),
        )
    }
}

pub fn stacksig_benchmark(c: &mut Criterion) {
    const Q: usize = 17;
    let mut ns: Vec<usize> = vec![0; Q - 1];
    for i in 2..=Q {
        ns[i - 2] = 1 << i;
    }
    let samples = [
        100, 100, 100, 100, 100, 100, 100, 60, 30, 10, 10, 10, 10, 10, 10, 10,
        10, 10, 10, 10,
    ];
    const BINDING: usize = 1;

    let mut communication_sizes: Vec<usize> = Vec::with_capacity(Q - 1);

    let mut group = c.benchmark_group("stacksig_benchmark");
    for (i, n) in ns
        .iter()
        .enumerate()
    {
        let StackerBench {
            s2_statement,
            s2_witness,
            ..
        } = bench_init(&mut ChaCha20Rng::from_entropy(), *n, BINDING);

        let rng = ChaCha20Rng::from_entropy();
        let challenge =
            SelfStacker::<Schnorr>::second(&mut ChaCha20Rng::from_entropy());
        let mut prover_params: ProverBenchParam = ProverBenchParam {
            statement: s2_statement,
            witness: s2_witness,
            challenge,
            rng,
        };

        let mut message_z: StackedZ<Schnorr> = StackedZ::default();
        let mut message_a: StackedA = StackedA::default();
        group.sample_size(samples[i]);
        group.throughput(Throughput::Elements(*n as u64));
        // Benchmark the prover
        group.bench_with_input(
            BenchmarkId::new("prover_bench", &prover_params),
            &mut prover_params,
            |b, p| {
                b.iter(|| {
                    let rng = &mut p
                        .rng
                        .clone();
                    let (state, a) =
                        SelfStacker::first(&p.statement, &p.witness, rng, &());
                    let z = SelfStacker::third(
                        &p.statement,
                        state,
                        &p.witness,
                        &p.challenge,
                        rng,
                        &(),
                    );
                    // Should have negligible cost
                    message_a = a;
                    message_z = z;
                });
            },
        );

        communication_sizes
            .push(message_a.size() + message_z.size() + challenge.size());

        let mut verifier_params = VerifierBenchParam {
            statement: prover_params.statement,
            message_a,
            message_z,
            challenge,
        };

        // Benchmark the verifier
        group.bench_with_input(
            BenchmarkId::new("verifier_bench", &verifier_params),
            &mut verifier_params,
            |b, p| {
                b.iter(|| {
                    SelfStacker::<Schnorr>::verify(
                        &p.statement,
                        &p.message_a,
                        &p.challenge,
                        &p.message_z,
                    )
                });
            },
        );
    }

    group.finish();
    let filename = format!("proofsize_plots/stacksig/proofsize{}", ns.len());
    plot_proofsize(ns, communication_sizes, "Stacking Sigmas".into(), filename);
}

criterion_group!(benches, stacksig_benchmark);
criterion_main!(benches);
