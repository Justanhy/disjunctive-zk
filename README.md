# Disjunctive Zero Knowledge

This project compares the performance of the general disjunctive zero-knowledge compilers introduced in [[CDS94]](https://link.springer.com/chapter/10.1007/3-540-48658-5_19) and [[Goe+21]](https://eprint.iacr.org/2021/422).

## Other works used in this project

We make use of Mathias Hall-Andersen's implementation of the Stacking Sigmas compiler in our benchmarks to compare the performance of our implementations with theirs. We have modified some of the original source code and everything relating to their implementation can be found in the `libs/stacksig-compiler/src/rot256` folder. Their original work is hosted on Github at https://github.com/rot256/research-stacksig under the GPL v3 License (the same as ours).

## Running Tests

Ensure that the current working directory is the root directory of this repository.

```bash
cargo test
```

### Code Coverage

We use `cargo llvm-cov` to run our code coverage tests. Specifically we use:

```bash
cargo llvm-cov --open --ignore-filename-regex libs/stacksig-compiler/src/rot256
```

We exclude the files within the `rot256` directory as the source code within that directory are related to [Hall-Andersen's implementation](https://github.com/rot256/research-stacksig) of the Stacking Sigmas compiler from [[Goe+21]](https://eprint.iacr.org/2021/422). We compare our implementation with Hall-Andersen's implementation within our benchmarks.

## Running Benchmarks

To run our benchmarks, we use the `cargo bench` command. To run the benchmarks for a specific compiler, we use the `--bench` flag. Below we provide an example of how to run each benchmark available:

```bash
  # run benchmark for CDS94 (as clauses increase)
  cargo bench --bench cds_benchmark
  # run benchmark for CDS94 (as active clauses increase)
  cargo bench --bench cds_benchmark2
  # run benchmark for Stacking Sigmas (as clauses increase)
  cargo bench --bench stacksig_benchmark
  # run benchmark for Hall-Andersen's implementation (as clauses increase)
  cargo bench --bench rot256_benchmark
  # run all benchmarks available: requires a long time
  cargo bench
```

# Disclaimers

The software produced in this project is not production ready, users should not use this in production environments.
