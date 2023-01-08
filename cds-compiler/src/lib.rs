extern crate blsttc;
extern crate curve25519_dalek_ml as curve25519_dalek;
extern crate itertools;
extern crate rand_chacha;
extern crate rand_core;
extern crate schnorr;
extern crate shamir_ss;

use curve25519_dalek::constants::{
    RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use itertools::{izip, Itertools};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use schnorr::{
    Error as SchnorrError, Schnorr, SchnorrProver, SchnorrTranscript,
    SchnorrVerifier, SigmaProtocol, SigmaProver, SigmaVerifier,
};
use shamir_ss::{
    vsss_rs::curve25519::WrappedScalar, Shamir, Share, WithShares,
};
use std::{any::Any, borrow::Borrow};

type SW = Vec<Scalar>;
type SA = Result<Vec<RistrettoPoint>, SchnorrError>;
type SC = Result<Scalar, SchnorrError>;
type SZ = Result<Vec<Scalar>, SchnorrError>;
// TODO: Implement generic sigma type
// type SP<W, A, C, Z> = Box<
//     dyn SigmaProtocol<W, A, C, Z, Transcript = dyn SigmaTranscript<A, C, Z>>,
// >;
// type Sigma = SP<dyn Any, dyn Any, dyn Any, dyn Any>;
type Sigma = Box<Schnorr>;

pub struct CDS94 {
    pub threshold: usize,
    pub n: usize,
    transcripts: Vec<SchnorrTranscript>,
    protocols: Vec<Sigma>,
    provers: Vec<SchnorrProver>,
    verifiers: Vec<SchnorrVerifier>,
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

// impl CDS94Transcript {
//     fn new() -> Self {
//         Self {
//             commitment: None,
//             challenge: None,
//             proof: None,
//         }
//     }

//     fn is_commited(&self) -> bool {
//         self.commitment != None && self.challenge == None && self.proof == None
//     }

//     fn is_challenged(&self) -> bool {
//         self.commitment != None && self.challenge != None && self.proof == None
//     }

//     fn is_proven(&self) -> bool {
//         self.commitment != None && self.challenge != None && self.proof != None
//     }
// }

impl SigmaProtocol for CDS94 {
    type Statement = CDS94;
    type Witness = Vec<Box<dyn Any>>;
    type State = Vec<Box<dyn Any>>;

    type A = Vec<RistrettoPoint>;
    type C = Scalar;
    type Z = Vec<(Scalar, Scalar)>;

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
        secret: &Self::C,
        z: &Self::Z,
    ) -> bool {
        let cs = z
            .iter()
            .map(|x| x.0)
            .collect_vec();
        let m2s = z
            .iter()
            .map(|x| x.1)
            .collect_vec();

        assert!(a.len() == cs.len(), "Invalid input lengths");

        let mut shares: Vec<Share> = Vec::with_capacity(statement.n);

        for (i, (m1, c, m2)) in izip!(a, cs, m2s).enumerate() {
            if !Schnorr::verify(&statement.protocols[i], &m1, &c, &m2) {
                dbg!(i);
                return false;
            }

            let mut s = vec![0u8; 33];
            s[0] = (i + 1) as u8;
            s[1..].copy_from_slice(c.as_bytes());
            shares.push(Share(s));
        }

        let shamir = Shamir {
            t: statement.threshold,
            n: statement.n,
        };

        let res = shamir.combine_shares(&shares);
        let combined_secret = res.unwrap_or(WrappedScalar::default());

        dbg!(&combined_secret.0);
        dbg!(*secret);

        combined_secret.0 == *secret
    }
}

impl CDS94 {
    pub fn first_message(
        &mut self,
        active_clauses: &Vec<bool>,
    ) -> Vec<RistrettoPoint> {
        assert!(active_clauses.len() == self.n);

        for (i, &is_active) in active_clauses
            .iter()
            .enumerate()
        {
            if is_active {
                let (_state, commitment) = Schnorr::a(
                    &self.protocols[i],
                    &Scalar::default(),
                    &mut self.provers[i].get_rng(),
                );
                self.transcripts[i] = SchnorrTranscript {
                    commitment: Some(commitment),
                    challenge: None,
                    proof: None,
                };
            } else {
                self.transcripts[i] = self.protocols[i].simulator();
            }
        }

        // let mut _error: Option<Error> = None; // For error propagation

        self.transcripts
            .iter()
            .map(|t| {
                t.commitment
                    .expect("Commitment should be present")
            })
            .collect()
    }

    fn fill_missing_shares(
        &self,
        challenge: Scalar,
        active_clauses: &Vec<bool>,
    ) -> Vec<Share> {
        let mut inactive_count: usize = 0;
        let mut active_count: usize = 0;

        for b in active_clauses {
            if *b {
                active_count += 1;
            } else {
                inactive_count += 1;
            }
        }

        let t: usize = inactive_count + 1;
        let n: usize = inactive_count + active_count;

        let shamir = Shamir { t, n };

        let mut shares = Vec::with_capacity(t);
        let mut xs_to_fill = Vec::with_capacity(active_count);

        for (i, t) in self
            .transcripts
            .iter()
            .enumerate()
        {
            if active_clauses[i] {
                xs_to_fill.push(WrappedScalar::from((i + 1) as u64));
            } else {
                let mut s = [0u8; 33];
                s[0] = (i + 1) as u8;
                s[1..].copy_from_slice(
                    t.challenge
                        .expect("Challenge should be present")
                        .as_bytes(),
                );
                shares.push(Share(s.into()));
            }
        }

        let mut missing_shares = shamir
            .split_secret_filling_shares::<WrappedScalar>(
                &challenge.into(),
                &shares,
                &xs_to_fill,
            )
            .unwrap();

        shares.append(&mut missing_shares);

        // Check shares can combine to the challenge
        let combineshares = shamir.combine_shares::<WrappedScalar>(&shares);
        assert!(combineshares.is_ok());
        let combined_secret = combineshares.unwrap();
        assert!(combined_secret.0 == challenge);

        shares
    }

    pub fn second_message<R: CryptoRngCore>(
        &mut self,
        witness: &Vec<Scalar>,
        challenge: Scalar,
        active_clauses: &Vec<bool>,
        prover_rng: &mut R,
    ) -> Vec<(Scalar, Scalar)> {
        // Given challenge (secret), and the simulated challenges,
        // generate remaining challenges that are consistent with the secret
        // let mut _error: Option<Error> = None; // For error propagation

        let shares = self.fill_missing_shares(challenge, active_clauses);

        for share in shares {
            let i = share.identifier() as usize - 1;

            match self.transcripts[i].challenge {
                Some(_) => continue,
                None => {
                    let mut c = [0u8; 32];
                    c.copy_from_slice(share.value());
                    self.transcripts[i].challenge =
                        Some(Scalar::from_bytes_mod_order(c))
                }
            }
        }

        self.transcripts = self.transcripts.iter().enumerate().map(|(i, transcript)| {
            if !transcript.is_challenged() {
                panic!("Transcript should have a challenge and commitment");
            } 
            if transcript.is_proven() {
                if active_clauses[i] {
                    panic!("Transcript should not be proven yet as it is an active clause");
                }
                transcript.clone()
            } else {
                let proof = Schnorr::z(
                    &self.protocols[i],
                    &Scalar::default(),
                    &witness[i],
                    &transcript
                        .challenge
                        .expect("Challenge should be present"),
                        &mut self.provers[i].get_rng(),
                );
                SchnorrTranscript {
                    commitment: transcript.commitment,
                    challenge: transcript.challenge,
                    proof: Some(proof),
                }
            }
        }).collect();

        // Return vector of challenges and vector of proofs or a vector of tuples of them
        self.transcripts
            .iter()
            .map(|t| {
                (
                    t.challenge
                        .expect("Challenge should be present"),
                    t.proof
                        .expect("Proof should be present"),
                )
            })
            .collect_vec()
    }

    pub fn init(
        d: usize,
        n: usize,
        protocols: &Vec<Sigma>,
        provers: &Vec<SchnorrProver>,
        verifiers: &Vec<SchnorrVerifier>,
    ) -> Self {
        Self {
            threshold: n - d + 1,
            n,
            transcripts: vec![SchnorrTranscript::new(); n],
            protocols: protocols.to_owned(),
            provers: provers.to_owned(),
            verifiers: verifiers.to_owned(),
        }
    }
}

pub struct CDS94Prover {
    /// Needs to have index of active clauses
    /// Needs to have list of witnesses for each active clause
    active_clauses: Vec<bool>,
    witnesses: Vec<Scalar>,
    prover_rng: ChaCha20Rng,
    transcripts: Vec<SchnorrTranscript>,
}

impl SigmaProver<SW, SA, SC, SZ, ChaCha20Rng> for CDS94Prover {
    // type Transcript = CDS94Transcript;
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
            transcripts: Vec::with_capacity(n),
        }
    }

    pub fn borrow_witnesses(&self) -> &Vec<Scalar> {
        &self.witnesses
    }
}

pub struct CDS94Verifier {
    verifier_rng: ChaCha20Rng,
}

impl SigmaVerifier<SW, SA, SC, SZ, ChaCha20Rng> for CDS94Verifier {
    // type Transcript = CDS94Transcript;
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

#[cfg(test)]
mod tests {

    use super::*;
    use schnorr::{Schnorr, SchnorrProver};

    type CDS94Test = (
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

    fn test_init<const N: usize, const D: usize>() -> CDS94Test {
        // INIT //
        assert!(D <= N);
        // closure to generate random witnesses
        let m = |_| Scalar::random(&mut ChaCha20Rng::from_entropy());
        // generate witnesses
        let actual_witnesses: Vec<Scalar> = (0..N).map(m).collect();
        // generate the prover's witnesses - for inactive clauses the prover generates a random witness
        let provers_witnesses: Vec<Scalar> = actual_witnesses
            .to_owned().iter().enumerate().map(|(i, s)| {
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
            .to_owned().iter()
            .map(|w| Box::new(Schnorr::init(*w)))
            .collect_vec();
            // generate the prover for each clause
        let provers = provers_witnesses
            .to_owned().iter()
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
            mut protocol,
            _cdsprover,
            _cdsverifier,
            _protocols,
            _provers,
            _verifiers,
            actual_witnesses,
            _provers_witnesses,
            active_clauses,
        ) = test_init::<N, D>();

        dbg!(&active_clauses);

        let commitments = protocol.first_message(&active_clauses);
        assert!(commitments.len() == N);
        let (_, testc) = Schnorr::a(
            &protocol.protocols[0],
            &actual_witnesses[0],
            &mut protocol.provers[0].get_rng(),
        );
        assert!(testc == commitments[0]);
        dbg!(
            commitments[0],
            protocol.transcripts[0]
                .commitment
                .unwrap()
        );
        assert!(
            commitments[0]
                == protocol.transcripts[0]
                    .commitment
                    .unwrap()
        );
        dbg!(
            commitments[1],
            protocol.transcripts[1]
                .commitment
                .unwrap()
        );
        assert!(
            commitments[1]
                == protocol.transcripts[1]
                    .commitment
                    .unwrap()
        );
    }

    #[test]
    fn second_message_works() {
        const N: usize = 2;
        const D: usize = 1;
        let (
            mut protocol,
            cdsprover,
            cdsverifier,
            _protocols,
            _provers,
            _verifiers,
            actual_witnesses,
            _provers_witnesses,
            active_clauses,
        ) = test_init::<N, D>();

        let commitments = protocol.first_message(&active_clauses);
        let challenge = CDS94::challenge(&mut cdsverifier.get_rng());
        // Third message
        let proof = protocol.second_message(
            &actual_witnesses,
            challenge,
            &active_clauses,
            &mut cdsprover.get_rng(),
        );
        assert!(CDS94::verify(&protocol, &commitments, &challenge, &proof));
    }

    #[test]
    fn cds_works() {
        // INIT //
        // number of clauses
        const N: usize = 10;
        const D: usize = 3;
        let (
            mut protocol,
            prover,
            verifier,
            _protocols,
            _provers,
            _verifiers,
            _actual_witnesses,
            _provers_witnesses,
            active_clauses,
        ) = test_init::<N, D>();

        // First message
        let commitment = protocol.first_message(&active_clauses);
        // Second message
        let challenge = CDS94::challenge(&mut verifier.get_rng());
        // Third message
        let proof = protocol.second_message(
            prover.borrow_witnesses(),
            challenge,
            &active_clauses,
            &mut prover.get_rng(),
        );
        assert!(CDS94::verify(&protocol, &commitment, &challenge, &proof));
    }
}
