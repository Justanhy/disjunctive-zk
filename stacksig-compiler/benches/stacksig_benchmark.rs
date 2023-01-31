use criterion::{
    black_box, criterion_group, criterion_main, Bencher, BenchmarkId, Criterion,
};

use stacksig_compiler::{compiler::*, fiat, schnorr, Side};

use rand_core::OsRng;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

type S2 = Compiled<schnorr::Schnorr>;
type S4 = Compiled<S2>;
type S8 = Compiled<S4>;
type S16 = Compiled<S8>;
type S32 = Compiled<S16>;
type S64 = Compiled<S32>;
type S128 = Compiled<S64>;
type S256 = Compiled<S128>;
type S512 = Compiled<S256>;
type S1024 = Compiled<S512>;
type S2048 = Compiled<S1024>;
type S4096 = Compiled<S2048>;

pub type Sig2 = fiat::SignatureScheme<S2>;
pub type Sig4 = fiat::SignatureScheme<S4>;
pub type Sig8 = fiat::SignatureScheme<S8>;
pub type Sig16 = fiat::SignatureScheme<S16>;
pub type Sig32 = fiat::SignatureScheme<S32>;
pub type Sig64 = fiat::SignatureScheme<S64>;
pub type Sig128 = fiat::SignatureScheme<S128>;
pub type Sig256 = fiat::SignatureScheme<S256>;
pub type Sig512 = fiat::SignatureScheme<S512>;
pub type Sig1024 = fiat::SignatureScheme<S1024>;
pub type Sig2048 = fiat::SignatureScheme<S2048>;
pub type Sig4096 = fiat::SignatureScheme<S4096>;

macro_rules! compile {
    ($pks:expr, $sk:expr) => {{
        let sk = CompiledWitness::new($sk, Side::Left); // for benchmarking the signer is always the left-most key
        let len = $pks.len() / 2;
        let mut pk: Vec<_> = Vec::with_capacity(len);
        let mut pks = $pks.into_iter();
        for _ in 0..len {
            let l = pks.next().unwrap();
            let r = pks.next().unwrap();
            pk.push(CompiledStatement::new(l, r));
        }
        (pk, sk)
    }};
}

macro_rules! compilen {
    (1, $pks:expr, $sk:expr) => {{
        compile!($pks, $sk)
    }};
    (2, $pks:expr, $sk:expr) => {{
        let (pk, sk) = compile!($pks, $sk);
        compilen!(1, pk, sk)
    }};
    (3, $pks:expr, $sk:expr) => {{
        let (pk, sk) = compile!($pks, $sk);
        compilen!(2, pk, sk)
    }};
    (4, $pks:expr, $sk:expr) => {{
        let (pk, sk) = compile!($pks, $sk);
        compilen!(3, pk, sk)
    }};
    (5, $pks:expr, $sk:expr) => {{
        let (pk, sk) = compile!($pks, $sk);
        compilen!(4, pk, sk)
    }};
    (6, $pks:expr, $sk:expr) => {{
        let (pk, sk) = compile!($pks, $sk);
        compilen!(5, pk, sk)
    }};
    (7, $pks:expr, $sk:expr) => {{
        let (pk, sk) = compile!($pks, $sk);
        compilen!(6, pk, sk)
    }};
    (8, $pks:expr, $sk:expr) => {{
        let (pk, sk) = compile!($pks, $sk);
        compilen!(7, pk, sk)
    }};
    (9, $pks:expr, $sk:expr) => {{
        let (pk, sk) = compile!($pks, $sk);
        compilen!(8, pk, sk)
    }};
    (10, $pks:expr, $sk:expr) => {{
        let (pk, sk) = compile!($pks, $sk);
        compilen!(9, pk, sk)
    }};
    (11, $pks:expr, $sk:expr) => {{
        let (pk, sk) = compile!($pks, $sk);
        compilen!(10, pk, sk)
    }};
    (12, $pks:expr, $sk:expr) => {{
        let (pk, sk) = compile!($pks, $sk);
        compilen!(11, pk, sk)
    }};
}

macro_rules! bench_scheme {
    ($b:expr, $n:tt, $s:tt) => {{
        let sk = Scalar::random(&mut OsRng);
        let mut pk: Vec<RistrettoPoint> = Vec::with_capacity(1 << $n);
        pk.push(&sk * RISTRETTO_BASEPOINT_TABLE);
        for _ in 1..(1 << $n) {
            pk.push(&Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_TABLE);
        }
        let (pk, sk) = compilen!($n, pk, sk);
        $b.iter(|| {
            $s::sign(&mut OsRng, &sk, &pk[0], &[]);
        });
    }};
}

fn bench_sig2(b: &mut Bencher) {
    bench_scheme!(b, 1, Sig2);
}

fn bench_sig4(b: &mut Bencher) {
    bench_scheme!(b, 2, Sig4);
}

fn bench_sig8(b: &mut Bencher) {
    bench_scheme!(b, 3, Sig8);
}

fn bench_sig16(b: &mut Bencher) {
    bench_scheme!(b, 4, Sig16);
}

fn bench_sig32(b: &mut Bencher) {
    bench_scheme!(b, 5, Sig32);
}

fn bench_sig64(b: &mut Bencher) {
    bench_scheme!(b, 6, Sig64);
}

fn bench_sig128(b: &mut Bencher) {
    bench_scheme!(b, 7, Sig128);
}

fn bench_sig256(b: &mut Bencher) {
    bench_scheme!(b, 8, Sig256);
}

fn bench_sig512(b: &mut Bencher) {
    bench_scheme!(b, 9, Sig512);
}

fn bench_sig1024(b: &mut Bencher) {
    bench_scheme!(b, 10, Sig1024);
}

fn bench_sig2048(b: &mut Bencher) {
    bench_scheme!(b, 11, Sig2048);
}

fn bench_sig4096(b: &mut Bencher) {
    bench_scheme!(b, 12, Sig4096);
}

pub fn stacksig_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("stacksig");
    group.bench_function("sig2", bench_sig2);
    group.bench_function("sig4", bench_sig4);
    group.bench_function("sig8", bench_sig8);
    group.bench_function("sig16", bench_sig16);
    group.bench_function("sig32", bench_sig32);
    group.bench_function("sig64", bench_sig64);
    group.bench_function("sig128", bench_sig128);
    group.bench_function("sig256", bench_sig256);
    group.bench_function("sig512", bench_sig512);
    group.bench_function("sig1024", bench_sig1024);
    group.bench_function("sig2048", bench_sig2048);
    group.bench_function("sig4096", bench_sig4096);
    group.finish();
}

criterion_group!(benches, stacksig_benchmark);
criterion_main!(benches);
