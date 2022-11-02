extern crate curve25519_dalek as curve;
extern crate rand;

use curve::constants::RISTRETTO_BASEPOINT_POINT;
use curve::ristretto::{CompressedRistretto, RistrettoPoint};
use curve::scalar::Scalar;
use rand::rngs::StdRng;

pub struct Verifier {
    
}

pub struct Prover {
    witness: Scalar,
}

impl Prover {

}

pub struct Schnorr {
    
}


