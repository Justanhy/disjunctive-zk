use std::io::Write;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::Scalar;
use sigmazk::Schnorr;

use super::{Message, Stackable};

impl Stackable for Schnorr {}

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

#[test]
fn test_write_scalar() {
    let mut buf = Vec::new();
    let scalar = Scalar::from(1u64);
    scalar.write(&mut buf);
    assert_eq!(scalar.size(), 32);
    let mut expected = vec![0u8; 32];
    expected[0] = 1;
    assert_eq!(buf, expected);
}
