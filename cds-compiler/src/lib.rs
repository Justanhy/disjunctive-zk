extern crate blsttc;
extern crate curve25519_dalek;
extern crate itertools;
extern crate rand_chacha;
extern crate rand_core;
extern crate schnorr;
extern crate shamir_ss;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use itertools::Itertools;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use schnorr::{
    Error, Schnorr, SchnorrProver, SchnorrTranscript, SchnorrVerifier,
    SigmaProtocol, SigmaProver, SigmaVerifier,
};
use std::{
    any::Any,
    borrow::Borrow,
    collections::{HashMap, HashSet},
};

type SW = Vec<Scalar>;
type SA = Result<Vec<RistrettoPoint>, Error>;
type SC = Result<Scalar, Error>;
type SZ = Result<Vec<Scalar>, Error>;
// TODO: Implement generic sigma type
// type SP<W, A, C, Z> = Box<
//     dyn SigmaProtocol<W, A, C, Z, Transcript = dyn SigmaTranscript<A, C, Z>>,
// >;
// type Sigma = SP<dyn Any, dyn Any, dyn Any, dyn Any>;
type Sigma = Box<Schnorr>;

pub struct CDS94<const N: usize> {
    transcript: CDS94Transcript,
    transcripts: Vec<SchnorrTranscript>,
    protocols: Vec<Sigma>,
    provers: Vec<SchnorrProver>,
    verifiers: Vec<SchnorrVerifier>,
}

pub struct CDS94Transcript {
    pub commitment: Option<Vec<RistrettoPoint>>,
    pub challenge: Option<Scalar>,
    pub proof: Option<Vec<Scalar>>,
}

// impl SigmaTranscript<SA, SC, SZ> for CDS94Transcript {
//     fn get_commitment(&self) -> SA {
//         match self.commitment {
//             Some(ref c) => Ok(c.clone()),
//             None => Err(Error::UninitializedCommitment),
//         }
//     }

//     fn get_challenge(&self) -> SC {
//         match self.challenge {
//             Some(c) => Ok(c),
//             None => Err(Error::UninitializedChallenge),
//         }
//     }

//     fn get_proof(&self) -> SZ {
//         match self.proof {
//             Some(ref p) => Ok(p.clone()),
//             None => Err(Error::UninitializedProof),
//         }
//     }
// }

impl CDS94Transcript {
    fn new() -> Self {
        Self {
            commitment: None,
            challenge: None,
            proof: None,
        }
    }

    fn is_commited(&self) -> bool {
        self.commitment != None && self.challenge == None && self.proof == None
    }

    fn is_challenged(&self) -> bool {
        self.commitment != None && self.challenge != None && self.proof == None
    }

    fn is_proven(&self) -> bool {
        self.commitment != None && self.challenge != None && self.proof != None
    }
}

impl<const N: usize> SigmaProtocol for CDS94<N> {
    type Statement = Vec<Box<dyn Any>>;
    type Witness = Vec<Box<dyn Any>>;
    type State = Vec<Box<dyn Any>>;

    type A = Vec<Box<dyn Any>>;
    type C = Scalar;
    type Z = Vec<Box<dyn Any>>;

    fn simulate(
        statement: &Self::Statement,
        challenge: &Self::C,
        z: &Self::Z,
    ) -> Self::A {
        unimplemented!()
    }

    fn a<R: CryptoRngCore>(
        statement: &Self::Statement,
        witness: &Self::Witness,
        prover_rng: &mut R,
    ) -> (Self::State, Self::A) {
        unimplemented!()
    }

    fn challenge<R: CryptoRngCore>(verifier_rng: &mut R) -> Self::C {
        Scalar::random(verifier_rng)
    }

    fn z<R: CryptoRngCore>(
        statement: &Self::Statement,
        state: &Self::State,
        witness: &Self::Witness,
        challenge: &Self::C,
        prover_rng: &mut R,
    ) -> Self::Z {
        unimplemented!()
    }

    fn verify(
        statement: &Self::Statement,
        a: &Self::A,
        c: &Self::C,
        z: &Self::Z,
    ) -> bool {
        unimplemented!()
    }
}

impl<const N: usize> CDS94<N> {
    pub fn first_message<R: CryptoRngCore>(
        &mut self,
        active_clauses: &Vec<bool>,
    ) -> Vec<RistrettoPoint> {
        let mut _error: Option<Error> = None; // For error propagation
        let tmap = active_clauses
            .into_iter()
            .enumerate()
            .map(|(i, &b)| {
                if b {
                    let (_state, commitment) = Schnorr::a(
                        &RISTRETTO_BASEPOINT_POINT,
                        &Scalar::default(),
                        &mut self.provers[i].get_rng(),
                    );
                    SchnorrTranscript {
                        commitment: Some(commitment),
                        challenge: None,
                        proof: None,
                    }
                } else {
                    let protocol: &Box<Schnorr> = self.protocols[i].borrow();

                    protocol.simulator()
                }
            });

        self.transcripts = tmap
            .to_owned()
            .collect();

        tmap.map(|t| {
            t.commitment
                .expect("Commitment should be present")
        })
        .collect()
    }

    fn second_message<R: CryptoRngCore>(
        &mut self,
        witness: &SW,
        challenge: SC,
        prover_rng: &mut R,
    ) -> SZ {
        // Given challenge (secret), and the simulated challenges,
        // generate remaining challenges that are consistent with the secret

        // With generated challenges, generate proofs for active clauses

        // Return vector of challenges and vector of proofs or a vector of tuples of them
        unimplemented!()
    }

    fn init(
        witnesses: SW,
        protocols: Vec<Sigma>,
        provers: Vec<SchnorrProver>,
        verifiers: Vec<SchnorrVerifier>,
    ) -> Self {
        Self {
            transcript: CDS94Transcript::new(),
            transcripts: Vec::with_capacity(N),
            protocols,
            provers,
            verifiers,
        }
    }
}

pub struct CDS94Prover<const N: usize> {
    /// Needs to have index of active clauses
    /// Needs to have list of witnesses for each active clause
    active_clauses: Vec<bool>,
    witnesses: Vec<Scalar>,
    prover_rng: ChaCha20Rng,
    transcripts: Vec<SchnorrTranscript>,
}

impl<const N: usize> SigmaProver<SW, SA, SC, SZ, ChaCha20Rng>
    for CDS94Prover<N>
{
    // type Transcript = CDS94Transcript;
    type Protocol = CDS94<N>;

    fn get_rng(&self) -> ChaCha20Rng {
        self.prover_rng
            .clone()
    }
}

impl<const N: usize> CDS94Prover<N> {
    pub fn new(witnesses: &Vec<Scalar>, active_clauses: &Vec<bool>) -> Self {
        Self {
            witnesses: witnesses.to_owned(),
            active_clauses: active_clauses.to_owned(),
            prover_rng: ChaCha20Rng::from_entropy(),
            transcripts: Vec::with_capacity(N),
        }
    }
}

pub struct CDS94Verifier<const N: usize> {
    verifier_rng: ChaCha20Rng,
}

impl<const N: usize> SigmaVerifier<SW, SA, SC, SZ, ChaCha20Rng>
    for CDS94Verifier<N>
{
    // type Transcript = CDS94Transcript;
    type Protocol = CDS94<N>;

    fn get_rng(&self) -> ChaCha20Rng {
        self.verifier_rng
            .clone()
    }
}

impl<const N: usize> CDS94Verifier<N> {
    pub fn new() -> Self {
        Self {
            verifier_rng: ChaCha20Rng::from_entropy(),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use blsttc::SecretKeySet;
    use itertools::{izip, Itertools};
    use schnorr::{Schnorr, SchnorrProver};

    // #[test]
    // fn it_works() {
    //     // Initialization //
    //     // init the number of statements n
    //     let n = 10;
    //     // init the indicies that the prover knows a witness for
    //     let p_knows = HashSet::from([1, 2, 3]);
    //     // init the actual_witnesses of each protocol
    //     let mut witnesses: HashMap<usize, Scalar> = HashMap::new();
    //     let mut active_clauses: HashMap<usize, Schnorr> = HashMap::new();
    //     let mut inactive_clauses: HashMap<usize, Schnorr> = HashMap::new();

    //     // Initialise all sigma protocols
    //     let mut protocols = (0..n)
    //         .into_iter()
    //         .map(|i| Schnorr::init(witnesses[&i]));
    //     // Initialise the Disjunctive Protocol
    //     // let djunc = DisjunctiveProof::new();
    //     // Get first message from all sigma protocols
    //     let mut first_ms = first_message();
    //     // Get secret from verifier
    //     let mut v_secret = Scalar::random(&mut ChaCha20Rng::from_entropy());
    //     // Get array of challenges and second messages from Prover
    //     let mut second_ms = second_message(v_secret, first_ms);
    //     // Verify that challenges are consistent with secret
    //     // and second message is accepted for each clause
    //     assert!(verify(second_ms));

    //     for i in 0..n {
    //         // If this is the statement that p knows a witness for, save the witness
    //         if p_knows.contains(&i) {
    //             // Run prover algorithm in SigmaProtocol to obtain first message
    //             // ideally something like DisjunctiveProof.SigmaProtocol.first_m()
    //             let witness = Scalar::random(&mut ChaCha20Rng::from_entropy());
    //             witnesses.insert(i, witness);
    //             active_clauses.insert(i, Schnorr::init(witness));
    //         } else {
    //             // Run simulator to obtain first message
    //             inactive_clauses.insert(
    //                 i,
    //                 Schnorr::init(Scalar::random(
    //                     &mut ChaCha20Rng::from_entropy(),
    //                 )),
    //             );
    //         }
    //     }

    //     fn ith_challenge(i: usize, secret: &SecretKeySet) -> Scalar {
    //         let mut ith_share = secret
    //             .secret_key_share(i)
    //             .to_bytes();
    //         ith_share.reverse();
    //         Scalar::from_bytes_mod_order(ith_share)
    //     }

    //     fn sim((i, secret): (usize, &SecretKeySet)) -> (Scalar, Scalar) {
    //         (
    //             ith_challenge(i, &secret),
    //             Scalar::random(&mut ChaCha20Rng::from_entropy()),
    //         )
    //     }

    //     let mut sim_transcripts: HashMap<usize, Transcript> = inactive_clauses
    //         .iter()
    //         .map(|(&i, s)| (i, s.with_simulator(sim, (i, &v_secret))))
    //         .collect();

    //     let mut gen_m1s = Vec::new();

    //     for i in 0..n {
    //         // If this is the statement that p knows a witness for, save the witness
    //         if p_knows.contains(&i) {
    //             gen_m1s.insert(i, active_clauses[&i].commitment());
    //         } else {
    //             gen_m1s.insert(i, sim_transcripts[&i].commitment);
    //         }
    //     }
    //     let mut gen_cs = Vec::new();
    //     // Step 3
    //     for i in 0..n {
    //         gen_cs.insert(i, ith_challenge(i, &v_secret));
    //     }

    //     let mut gen_m2s = Vec::new();
    //     for i in 0..n {
    //         if p_knows.contains(&i) {
    //             gen_m2s.insert(
    //                 i,
    //                 active_clauses[&i].prove(&gen_cs[i], &witnesses[&i]),
    //             );
    //         } else {
    //             gen_m2s.insert(i, sim_transcripts[&i].proof);
    //         }
    //     }
    //     // Step 4
    //     let conversations = izip!(gen_m1s, gen_cs, gen_m2s);
    //     conversations
    //         .enumerate()
    //         .for_each(|(i, (m1, c, m2))| {
    //             // Step 5
    //             if p_knows.contains(&i) {
    //                 assert!(active_clauses[&i].verify(&m1, &c, &m2));
    //             } else {
    //                 assert!(inactive_clauses[&i].verify(&m1, &c, &m2));
    //             }
    //         });
    // }

    #[test]
    fn cds_works() {
        // INIT //
        // number of clauses
        const N: usize = 10;
        // closure to generate random witnesses
        let m = |_| Scalar::random(&mut ChaCha20Rng::from_entropy());
        // generate witnesses
        let actual_witnesses = (0..N).map(m);
        // number of active clauses
        const D: usize = 3;
        // generate the prover's witnesses - for inactive clauses the prover generates a random witness
        let provers_witnesses = actual_witnesses
            .to_owned()
            .take(D)
            .chain((0..N - D).map(m));
        // vector of booleans indicating which clauses are active
        let active_clauses: Vec<bool> = (0..N)
            .map(|i| i < D)
            .collect();
        // generate the statement (aka protocol) for each clause
        let protocols = actual_witnesses
            .to_owned()
            .map(|w| Box::new(Schnorr::init(w)))
            .collect_vec();
        // generate the prover for each clause
        let provers = actual_witnesses
            .to_owned()
            .map(|w| SchnorrProver::new(&w))
            .collect_vec();
        // generate the verifier for each clause
        let verifiers = protocols
            .to_owned()
            .into_iter()
            .map(|p| SchnorrVerifier::new(&p.pub_key))
            .collect_vec();
        // transform the witnesses into a vector
        let actual_witnesses = actual_witnesses.collect_vec();
        let provers_witnesses = provers_witnesses.collect_vec();
        // CDS Protocol //
        let mut protocol: CDS94<N> =
            CDS94::init(actual_witnesses, protocols, provers, verifiers);
        // PROVER //
        let prover: CDS94Prover<N> =
            CDS94Prover::new(&provers_witnesses, &active_clauses);
        // VERIFIER //
        let verifier: CDS94Verifier<N> = CDS94Verifier::new();
        // First message
        let commitment = protocol.first_message(&active_clauses);
        // Second message
        let challenge = CDS94::<N>::challenge(&mut verifier.get_rng());
        // Third message
        let proof = protocol
            .second_message(
                prover.borrow_witnesses(),
                Ok(challenge),
                &mut prover.get_rng(),
            )
            .unwrap();
        assert!(protocol.verify(CDS94Transcript {
            commitment: Some(commitment),
            challenge: Some(challenge),
            proof: Some(proof),
        }));
    }
}
