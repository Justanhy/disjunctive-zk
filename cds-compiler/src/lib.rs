pub extern crate curve25519_dalek_ml as curve25519_dalek;
extern crate itertools;
extern crate rand_chacha;
extern crate rand_core;
pub extern crate schnorr;
pub extern crate shamir_ss;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use itertools::{izip, Itertools};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use schnorr::{
    error::{Error as SchnorrError} , Schnorr, SchnorrProver, SchnorrTranscript,
    SchnorrVerifier, sigma::{SigmaProtocol, SigmaProver, SigmaVerifier, SigmaTranscript}
};
use shamir_ss::{
    vsss_rs::curve25519::WrappedScalar, Shamir, Share, WithShares,
};
use std::{fmt, any::Any};

type SW = Vec<Scalar>;
type SA = Result<Vec<RistrettoPoint>, SchnorrError>;
type SC = Result<Scalar, SchnorrError>;
type SZ = Result<Vec<Scalar>, SchnorrError>;
// TODO: Implement generic sigma type
// type Sigma = Box<dyn SigmaProtocol<
//     Statement = dyn Any, 
//     Witness = dyn Any, 
//     State = dyn Any, 
//     A = dyn Any, 
//     C = dyn Any, 
//     Z = dyn Any,
//     ProverContext =  dyn Any
// >>;
type Sigma = Box<Schnorr>;

#[derive(Clone, Debug)]
pub struct CDS94 {
    pub threshold: usize,
    pub n: usize,
    protocols: Vec<Sigma>,
    provers: Vec<SchnorrProver>,
    verifiers: Vec<SchnorrVerifier>,
}

impl fmt::Display for CDS94 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let n = self.n;
        let t = self.threshold;
        write!(f, "Clauses: {}, Active Clauses: {}, Threshold: {}",
        n,
        n - t + 1,
        t)
    }
}

impl SigmaProtocol for CDS94 {
    type Statement = CDS94;
    type Witness = Vec<Scalar>;
    type State = Vec<Box<SchnorrTranscript>>; // dyn SigmaTranscript<A = RistrettoPoint, C = Scalar, Z = Scalar>

    type A = Vec<RistrettoPoint>;
    type C = Scalar;
    type Z = Vec<(Scalar, Scalar)>;

    type ProverContext = Vec<bool>;

    fn simulate(
        statement: &Self::Statement,
        challenge: &Self::C,
        z: &Self::Z,
    ) -> Self::A {
        unimplemented!()
    }

    fn first<R: CryptoRngCore>(
        statement: &CDS94,
        _witness: &Self::Witness,
        _prover_rng: &mut R,
        active_clauses: &Vec<bool>
    ) -> (Self::State, Self::A) {
        assert!(active_clauses.len() == statement.n);
        

        let transcripts: Self::State = active_clauses.iter().enumerate().map(
            |(i, &is_active)| {
                if is_active {
                    let (_state, commitment) = Schnorr::first(
                        &statement.protocols[i],
                        &Scalar::default(),
                        &mut statement.provers[i].get_rng(),
                        &()
                    );
                    Box::new(SchnorrTranscript {
                        commitment: Some(commitment),
                        challenge: None,
                        proof: None,
                    })
                } else {
                    Box::new(statement.protocols[i].simulator())
                }
        }
    ).collect();
        // let mut _error: Option<Error> = None; // For error propagation

        let commitment: Self::A = transcripts
        .iter()
        .map(|t| {
            t.commitment
                .expect("Commitment should be present")
        })
        .collect();
        (transcripts, commitment)
    }

    fn second<R: CryptoRngCore>(verifier_rng: &mut R) -> Self::C {
        Scalar::random(verifier_rng)
    }

    fn third<R: CryptoRngCore>(
        statement: &Self::Statement,
        state: &Vec<Box<SchnorrTranscript>>,
        witness: &Self::Witness,
        challenge: &Self::C,
        prover_rng: &mut R,
        active_clauses: &Vec<bool>
    ) -> Self::Z {
        let shares = CDS94::fill_missing_shares(&state, *challenge, active_clauses);

        let mut transcripts: Vec<Box<SchnorrTranscript>> = state.clone();
        
        for share in shares.iter() {
            let i = share.identifier() as usize - 1;

            match state[i].challenge {
                Some(_) => continue, // Consider: doing extra work to mitigate timing attacks
                None => {
                    let mut c = [0u8; 32];
                    c.copy_from_slice(share.value());
                    
                    transcripts[i] = Box::new(SchnorrTranscript {
                        commitment: state[i].commitment, 
                        challenge: Some(Scalar::from_bytes_mod_order(c)),
                        proof: None,
                    })
                }
            }
        }

        let transcripts: Vec<Box<SchnorrTranscript>> = transcripts.iter().enumerate().map(|(i, transcript)| {
            if !transcript.is_challenged() {
                panic!("Transcript should have a challenge and commitment");
            } 
            if transcript.is_proven() {
                if active_clauses[i] {
                    panic!("Transcript should not be proven yet as it is an active clause");
                }
                transcript.clone()
            } else {
                let proof = Schnorr::third(
                    &statement.protocols[i],
                    &Scalar::default(),
                    &witness[i],
                    &transcript
                        .challenge
                        .expect("Challenge should be present"),
                        &mut statement.provers[i].get_rng(),
                        &()
                );
                Box::new(SchnorrTranscript {
                    commitment: transcript.commitment,
                    challenge: transcript.challenge,
                    proof: Some(proof),
                })
            }
        }).collect();

        // Return vector of challenges and vector of proofs or a vector of tuples of them
        transcripts
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

        combined_secret.0 == *secret
    }
}

impl CDS94 {
    fn fill_missing_shares(
        transcripts: &Vec<Box<SchnorrTranscript>>,
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

        for (i, t) in transcripts
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
            protocols: protocols.to_owned(),
            provers: provers.to_owned(),
            verifiers: verifiers.to_owned(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CDS94Prover {
    /// Needs to have index of active clauses
    /// Needs to have list of witnesses for each active clause
    active_clauses: Vec<bool>,
    witnesses: Vec<Scalar>,
    prover_rng: ChaCha20Rng,
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
        }
    }

    pub fn borrow_witnesses(&self) -> &Vec<Scalar> {
        &self.witnesses
    }
}


#[derive(Clone, Debug)]
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

pub type CDS94Test = (
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

#[cfg(test)]
pub mod tests {

    use super::*;
    use schnorr::{Schnorr, SchnorrProver};


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
            protocol,
            cdsprover,
            _cdsverifier,
            _protocols,
            _provers,
            _verifiers,
            actual_witnesses,
            provers_witnesses,
            active_clauses,
        ) = test_init::<N, D>();

        let (transcripts, commitments) = CDS94::first(&protocol,  &provers_witnesses, &mut cdsprover.get_rng(), &active_clauses);
        assert!(commitments.len() == N);
        let (_, testc) = Schnorr::first(
            &protocol.protocols[0],
            &actual_witnesses[0],
            &mut protocol.provers[0].get_rng(),
            &()
        );
        assert!(testc == commitments[0]);
        assert!(
            commitments[0]
                == transcripts[0]
                    .commitment
                    .unwrap()
        );
        assert!(
            commitments[1]
                == transcripts[1]
                    .commitment
                    .unwrap()
        );
    }

    #[test]
    fn second_message_works() {
        const N: usize = 2;
        const D: usize = 1;
        let (
            protocol,
            cdsprover,
            cdsverifier,
            _protocols,
            _provers,
            _verifiers,
            _actual_witnesses,
            provers_witnesses,
            active_clauses,
        ) = test_init::<N, D>();

        let (transcripts, commitments) = CDS94::first(
            &protocol,  
            &provers_witnesses, 
            &mut cdsprover.get_rng(), 
            &active_clauses
        );
        let challenge = CDS94::second(&mut cdsverifier.get_rng());
        // Third message
        let proof = CDS94::third(
            &protocol, 
            &transcripts, 
            cdsprover.borrow_witnesses(), 
            &challenge, 
            &mut cdsprover.get_rng(), 
            &active_clauses
        );
        
        assert!(CDS94::verify(&protocol, &commitments, &challenge, &proof));
    }

    #[test]
    fn cds_works() {
        // INIT //
        // number of clauses
        const N: usize = 255;
        const D: usize = 200;
        let (
            protocol,
            cdsprover,
            cdsverifier,
            _protocols,
            _provers,
            _verifiers,
            _actual_witnesses,
            provers_witnesses,
            active_clauses,
        ) = test_init::<N, D>();

        // First message
        let (transcripts, commitments) = CDS94::first(
            &protocol,  
            &provers_witnesses, 
            &mut cdsprover.get_rng(), 
            &active_clauses
        );
        // Second message
        let challenge = CDS94::second(&mut cdsverifier.get_rng());
        // Third message
        let proof = CDS94::third(&protocol, &transcripts, cdsprover.borrow_witnesses(), &challenge, &mut cdsprover.get_rng(), &active_clauses);
        assert!(CDS94::verify(&protocol, &commitments, &challenge, &proof));
    }
}
