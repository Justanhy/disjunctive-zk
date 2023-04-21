use std::collections::HashSet;

use curve25519_dalek::ristretto::CompressedRistretto;

use crate::*;
// TODO: Implement generic sigma type
// type Sigma = Box<dyn SigmaProtocol<
//     Statement = dyn Any,
//     Witness = dyn Any,
//     State = dyn Any,
//     MessageA = dyn Any,
//     Challenge = dyn Any,
//     MessageZ = dyn Any,
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

type SigTrans = Box<
    dyn SigmaTranscript<
        MessageA = CompressedRistretto,
        Challenge = Scalar,
        MessageZ = Scalar,
    >,
>;

pub struct CompiledWitness {
    witnesses: Vec<Scalar>,
    active_clauses: Vec<bool>,
}

impl CompiledWitness {
    pub fn new(witnesses: Vec<Scalar>, active_clauses: Vec<bool>) -> Self {
        Self {
            witnesses,
            active_clauses,
        }
    }

    pub fn witnesses(&self) -> &Vec<Scalar> {
        &self.witnesses
    }

    pub fn active_clauses(&self) -> &Vec<bool> {
        &self.active_clauses
    }

    pub fn pattern_match(&self) -> (&Vec<Scalar>, &Vec<bool>) {
        (&self.witnesses, &self.active_clauses)
    }
}

impl SigmaProtocol for CDS94 {
    type Statement = CDS94;
    type Witness = CompiledWitness;
    // type State = Vec<Box<SchnorrTranscript>>; // dyn
    // SigmaTranscript<MessageA = RistrettoPoint, Challenge =
    // Scalar, MessageZ = Scalar>
    type State = Vec<SigTrans>;

    type MessageA = Vec<CompressedRistretto>;
    type Challenge = Scalar;
    type MessageZ = Vec<(usize, Scalar, Scalar)>;

    fn first<R: CryptoRngCore>(
        statement: &CDS94,
        witness: &Self::Witness,
        _prover_rng: &mut R,
    ) -> (Self::State, Self::MessageA) {
        let active_clauses = witness.active_clauses();
        assert!(active_clauses.len() == statement.n);

        let mut commitment: Self::MessageA = Vec::with_capacity(statement.n);

        let transcripts: Self::State = active_clauses
            .iter()
            .enumerate()
            .map(|(i, &is_active)| {
                let ret: SigTrans = if is_active {
                    let (_state, commitment) = Schnorr::first(
                        &statement.protocols[i],
                        &Scalar::default(),
                        &mut statement.provers[i].get_rng(),
                    );
                    Box::new(SchnorrTranscript {
                        commitment: Some(commitment),
                        challenge: None,
                        proof: None,
                    })
                } else {
                    Box::new(statement.protocols[i].simulator())
                };
                commitment.push(
                    ret.get_commitment()
                        .unwrap(),
                );
                ret
            })
            .collect();

        (transcripts, commitment)
    }

    fn second<R: CryptoRngCore>(verifier_rng: &mut R) -> Self::Challenge {
        Scalar::random(verifier_rng)
    }

    fn third<R: CryptoRngCore>(
        statement: &Self::Statement,
        state: Self::State,
        witness: &Self::Witness,
        challenge: &Self::Challenge,
        prover_rng: &mut R,
    ) -> Self::MessageZ {
        let (witnesses, active_clauses) = witness.pattern_match();
        let shares =
            CDS94::fill_missing_shares(&state, *challenge, active_clauses);

        // Loop through transcripts and fill in the challenge
        shares
            .iter()
            .map(|share| {
                let i = usize::from_le_bytes(
                    share
                        .x
                        .to_bytes()[..8]
                        .try_into()
                        .unwrap(),
                ) - 1;

                match state[i].get_challenge() {
                    // Inactive clauses
                    Some(s) => (
                        i,
                        s,
                        state[i]
                            .get_proof()
                            .expect("Proof should be present"),
                    ),
                    // Active clauses
                    None => {
                        let challenge = share.y.0;
                        let proof = Schnorr::third(
                            &statement.protocols[i],
                            Scalar::default(),
                            &witnesses[i],
                            &challenge,
                            &mut statement.provers[i].get_rng(),
                        );

                        (i, challenge, proof)
                    }
                }
            })
            .collect_vec()
    }

    fn verify(
        statement: &Self::Statement,
        a: &Self::MessageA,
        secret: &Self::Challenge,
        z: &Self::MessageZ,
    ) -> bool {
        let valid = a.len() == z.len();

        let mut shares: Vec<Share<WrappedScalar>> =
            Vec::with_capacity(statement.n);

        for (i, c, m2) in z {
            let m1 = a[*i];
            if !Schnorr::verify(&statement.protocols[*i], &m1, &c, &m2) {
                return false;
            }

            let share = Share {
                x: WrappedScalar::from((i + 1) as u64),
                y: WrappedScalar::from(*c),
            };
            shares.push(share);
        }

        let shamir = ShamirSecretSharing {
            threshold: statement.threshold,
            shares: statement.n,
        };

        let res = shamir.reconstruct_secret(&shares);

        let combined_secret = res.unwrap_or(WrappedScalar::default());

        combined_secret.0 == *secret && valid
    }
}

impl CDS94 {
    fn fill_missing_shares(
        transcripts: &Vec<SigTrans>,
        challenge: Scalar,
        active_clauses: &Vec<bool>,
    ) -> Vec<Share<WrappedScalar>> {
        let mut inactive_count: usize = 0;
        let mut active_count: usize = 0;

        for b in active_clauses {
            if *b {
                active_count += 1;
            } else {
                inactive_count += 1;
            }
        }

        let threshold: usize = inactive_count + 1;
        let n: usize = inactive_count + active_count;

        let shamir = ShamirSecretSharing {
            threshold,
            shares: n,
        };

        let mut shares = Vec::with_capacity(threshold);
        let mut xs_to_fill = Vec::with_capacity(active_count);

        for (i, t) in transcripts
            .iter()
            .enumerate()
        {
            if active_clauses[i] {
                xs_to_fill.push(WrappedScalar::from((i + 1) as u64));
            } else {
                let share = Share {
                    x: WrappedScalar::from((i + 1) as u64),
                    y: WrappedScalar::from(
                        t.get_challenge()
                            .expect("Challenge should be present"),
                    ),
                };
                shares.push(share);
            }
        }

        let mut missing_shares = shamir
            .complete_shares::<WrappedScalar>(
                &challenge.into(),
                &shares,
                &xs_to_fill,
            )
            .unwrap();

        shares.append(&mut missing_shares);

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
