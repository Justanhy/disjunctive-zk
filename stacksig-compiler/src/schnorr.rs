use rand_core::{CryptoRng, RngCore};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

#[derive(Debug)]
pub struct Schnorr();

use std::io::Write;

use crate::stack::*;

impl Message for CompressedRistretto {
    fn write<W: Write>(&self, writer: &mut W) {
        writer.write_all(self.as_bytes()).unwrap();
    }
}

impl Message for Scalar {
    fn write<W: Write>(&self, writer: &mut W) {
        writer.write_all(self.as_bytes()).unwrap();
    }
}

impl Challenge for Scalar {
    fn new(bytes: &[u8; 64]) -> Self {
        Scalar::from_bytes_mod_order_wide(bytes)
    }
}

impl Stackable for Schnorr {
    type Witness = Scalar;
    type State = Scalar;
    type Statement = RistrettoPoint;
    type MessageA = CompressedRistretto;
    type MessageZ = Scalar;
    type Challenge = Scalar;
    type Precompute = (RistrettoPoint, Scalar);

    fn sigma_a<R: RngCore + CryptoRng>(
        rng: &mut R,
        _witness: &Self::Witness,
    ) -> (Self::State, Self::MessageA) {
        let state = Scalar::random(rng);
        let message = &state * &RISTRETTO_BASEPOINT_TABLE;
        (state, message.compress())
    }

    fn sigma_z(
        _statement: &Self::Statement,
        witness: &Self::Witness,
        state: &Self::State,
        challenge: &Self::Challenge,
    ) -> (Self::Precompute, Self::MessageZ) {
        let z = challenge * witness + state;
        let p = &z * &RISTRETTO_BASEPOINT_TABLE;
        let cinv = -challenge;
        ((p, cinv), z)
    }

    fn ehvzk(
        precomp: &Self::Precompute,
        statement: &Self::Statement,
        _challenge: &Self::Challenge,
        _z: &Self::MessageZ,
    ) -> Self::MessageA {
        // g^z st^-c = a
        (precomp.0 + precomp.1 * statement).compress()
        // (z * &RISTRETTO_BASEPOINT_TABLE + -challenge * statement).compress()
    }
}
