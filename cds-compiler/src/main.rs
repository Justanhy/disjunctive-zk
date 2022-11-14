extern crate blsttc;
extern crate curve25519_dalek;
extern crate itertools;
extern crate rand_chacha;
extern crate rand_core;
extern crate schnorr;
extern crate shamir_ss;

use blsttc::SecretKeySet;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use itertools::izip;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use schnorr::{Schnorr, SigmaProtocol, Transcript};
use shamir_ss::ShamirSecretSharing;
use std::collections::{HashMap, HashSet};

pub struct DisjunctiveProof<S>
where
    S: SigmaProtocol,
{
    total_statements: u8,
    sigma_protocol: S,
}

pub struct Prover {}

pub struct Verifier {}

impl<S> DisjunctiveProof<S>
where
    S: SigmaProtocol,
{
    pub fn new(total_statements: u8, sigma_protocol: S) -> DisjunctiveProof<S> {
        DisjunctiveProof {
            total_statements,
            sigma_protocol,
        }
    }
}

fn main() {}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_works() {
        // Initialise n statements
        let n = 10;
        // Vector of indices that prover knows a witness for
        let p_knows = HashSet::from([1, 2, 3]);
        let mut p_witnesses: HashMap<usize, Scalar> = HashMap::new();
        let mut known_statements: HashMap<usize, Schnorr> = HashMap::new();
        let mut unknown_statements: HashMap<usize, Schnorr> = HashMap::new();
        // Verifier generates a secret
        let v_secret = SecretKeySet::random(
            p_knows.len(),
            &mut ChaCha20Rng::from_entropy(),
        );

        for i in 0..n {
            // If this is the statement that p knows a witness for, save the witness
            if p_knows.contains(&i) {
                let witness = Scalar::random(&mut ChaCha20Rng::from_entropy());
                p_witnesses.insert(i, witness);
                known_statements.insert(i, Schnorr::init(witness));
            } else {
                unknown_statements.insert(
                    i,
                    Schnorr::init(Scalar::random(
                        &mut ChaCha20Rng::from_entropy(),
                    )),
                );
            }
        }

        fn ith_challenge(i: usize, secret: &SecretKeySet) -> Scalar {
            let mut ith_share = secret
                .secret_key_share(i)
                .to_bytes();
            ith_share.reverse();
            Scalar::from_bytes_mod_order(ith_share)
        }

        fn sim((i, secret): (usize, &SecretKeySet)) -> (Scalar, Scalar) {
            (
                ith_challenge(i, &secret),
                Scalar::random(&mut ChaCha20Rng::from_entropy()),
            )
        }

        let mut sim_transcripts: HashMap<usize, Transcript> =
            unknown_statements
                .iter()
                .map(|(&i, s)| (i, s.with_simulator(sim, (i, &v_secret))))
                .collect();

        let mut gen_m1s = Vec::new();

        for i in 0..n {
            // If this is the statement that p knows a witness for, save the witness
            if p_knows.contains(&i) {
                gen_m1s.insert(i, known_statements[&i].commitment());
            } else {
                gen_m1s.insert(i, sim_transcripts[&i].commitment);
            }
        }
        let mut gen_cs = Vec::new();
        // Step 3
        for i in 0..n {
            gen_cs.insert(i, ith_challenge(i, &v_secret));
        }

        let mut gen_m2s = Vec::new();
        for i in 0..n {
            if p_knows.contains(&i) {
                gen_m2s.insert(
                    i,
                    known_statements[&i].prove(&gen_cs[i], &p_witnesses[&i]),
                );
            } else {
                gen_m2s.insert(i, sim_transcripts[&i].proof);
            }
        }
        // Step 4
        let conversations = izip!(gen_m1s, gen_cs, gen_m2s);
        conversations
            .enumerate()
            .for_each(|(i, (m1, c, m2))| {
                // Step 5
                if p_knows.contains(&i) {
                    assert!(known_statements[&i].verify(&m1, &c, &m2));
                } else {
                    assert!(unknown_statements[&i].verify(&m1, &c, &m2));
                }
            });
    }
}
