use crate::*;
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
    pub protocols: Vec<Sigma>,
    pub provers: Vec<SchnorrProver>,
    verifiers: Vec<SchnorrVerifier>,
}

impl fmt::Display for CDS94 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let n = self.n;
        let t = self.threshold;
        write!(
            f,
            "Clauses: {}, Active Clauses: {}, Threshold: {}",
            n,
            n - t + 1,
            t
        )
    }
}

type SigTrans =
    Box<dyn SigmaTranscript<A = RistrettoPoint, C = Scalar, Z = Scalar>>;

impl SigmaProtocol for CDS94 {
    type Statement = CDS94;
    type Witness = Vec<Scalar>;
    // type State = Vec<Box<SchnorrTranscript>>; // dyn SigmaTranscript<A = RistrettoPoint, C = Scalar, Z = Scalar>
    type State = Vec<SigTrans>;

    type A = Vec<RistrettoPoint>;
    type C = Scalar;
    type Z = Vec<(Scalar, Scalar)>;

    type ProverContext = Vec<bool>;

    fn first<R: CryptoRngCore>(
        statement: &CDS94,
        _witness: &Self::Witness,
        _prover_rng: &mut R,
        active_clauses: &Vec<bool>,
    ) -> (Self::State, Self::A) {
        assert!(active_clauses.len() == statement.n);

        let transcripts: Self::State = active_clauses
            .iter()
            .enumerate()
            .map(|(i, &is_active)| {
                let ret: SigTrans = if is_active {
                    let (_state, commitment) = Schnorr::first(
                        &statement.protocols[i],
                        &Scalar::default(),
                        &mut statement.provers[i].get_rng(),
                        &(),
                    );
                    Box::new(SchnorrTranscript {
                        commitment: Some(commitment),
                        challenge: None,
                        proof: None,
                    })
                } else {
                    Box::new(statement.protocols[i].simulator())
                };
                ret
            })
            .collect();
        // let mut _error: Option<Error> = None; // For error propagation

        let commitment: Self::A = transcripts
            .iter()
            .map(|t| {
                t.get_commitment()
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
        state: &Self::State,
        witness: &Self::Witness,
        challenge: &Self::C,
        prover_rng: &mut R,
        active_clauses: &Vec<bool>,
    ) -> Self::Z {
        let shares =
            CDS94::fill_missing_shares(&state, *challenge, active_clauses);

        let mut transcripts: Vec<SigTrans> = shares
            .iter()
            .map(|share| {
                let i = share.identifier() as usize - 1;

                match state[i].get_challenge() {
                    Some(s) => Box::new(SchnorrTranscript {
                        commitment: state[i].get_commitment(),
                        challenge: state[i].get_challenge(),
                        proof: state[i].get_proof(),
                    }) as SigTrans,
                    None => {
                        let mut c = [0u8; 32];
                        c.copy_from_slice(share.value());

                        Box::new(SchnorrTranscript {
                            commitment: state[i].get_commitment(),
                            challenge: Some(Scalar::from_bytes_mod_order(c)),
                            proof: None,
                        }) as SigTrans
                    }
                }
            })
            .collect();

        for (i, transcript) in transcripts
            .iter_mut()
            .enumerate()
        {
            if !transcript.is_challenged() {
                panic!("Transcript should have a challenge and commitment");
            }
            if transcript.is_proven() {
                if active_clauses[i] {
                    panic!("Transcript should not be proven yet as it is an active clause");
                }
                continue;
            } else {
                let proof = Schnorr::third(
                    &statement.protocols[i],
                    &Scalar::default(),
                    &witness[i],
                    &transcript
                        .get_challenge()
                        .expect("Challenge should be present"),
                    &mut statement.provers[i].get_rng(),
                    &(),
                );
                *transcript = Box::new(SchnorrTranscript {
                    commitment: transcript.get_commitment(),
                    challenge: transcript.get_challenge(),
                    proof: Some(proof),
                }) as SigTrans;
            }
        }

        // Return vector of challenges and vector of proofs or a vector of tuples of them
        transcripts
            .iter()
            .map(|t| {
                (
                    t.get_challenge()
                        .expect("Challenge should be present"),
                    t.get_proof()
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
        transcripts: &Vec<SigTrans>,
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
                    t.get_challenge()
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
        shares.sort_by_key(|k| k.identifier());

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
