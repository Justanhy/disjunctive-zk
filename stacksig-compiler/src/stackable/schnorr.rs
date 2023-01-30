use std::io::Write;

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use sigmazk::{Schnorr, SigmaProtocol, SigmaTranscript};

use super::stackable::{Challenge, Message, Stackable};

impl Message for CompressedRistretto {
    fn write<W: Write>(&self, writer: &mut W) {
        writer
            .write_all(self.as_bytes())
            .unwrap();
    }
}

impl Message for Scalar {
    fn write<W: Write>(&self, writer: &mut W) {
        writer
            .write_all(self.as_bytes())
            .unwrap();
    }
}

impl Challenge for Scalar {
    fn new(bytes: &[u8; 64]) -> Self {
        Scalar::from_bytes_mod_order_wide(bytes)
    }
}

impl Stackable for Schnorr {
    type A = CompressedRistretto;
    type C = Scalar;
    type Z = Scalar;
}
