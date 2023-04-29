use std::fmt::Debug;
use std::io::Write;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::Scalar;

pub trait Message: Debug + Default + Clone {
    fn write<W: Write>(&self, writer: &mut W)
    where
        Self: Sized;

    fn size(&self) -> usize {
        let mut v: Vec<u8> = Vec::new();
        self.write(&mut v);
        v.len()
    }
}

impl Message for usize {
    fn write<W: Write>(&self, writer: &mut W) {
        writer
            .write_all(&self.to_le_bytes())
            .unwrap();
    }
}

impl Message for &[u8] {
    fn write<W: Write>(&self, writer: &mut W) {
        writer
            .write_all(self)
            .unwrap();
    }
}

#[test]
fn test_write_array() {
    let mut buf = Vec::new();
    let array = [1u8; 32].as_slice();
    array.write(&mut buf);
    assert_eq!(array.size(), 32);
    let expected = vec![1u8; 32];
    assert_eq!(buf, expected);
}

impl Message for CompressedRistretto {
    fn write<W: Write>(&self, writer: &mut W) {
        writer
            .write_all(self.as_bytes())
            .unwrap();
    }
}

#[test]
fn test_write_compressedristretto() {
    let mut buf = Vec::new();
    let compressedristretto =
        CompressedRistretto::from_slice(&[1u8; 32])
            .unwrap();
    compressedristretto.write(&mut buf);
    assert_eq!(compressedristretto.size(), 32);
    let expected = vec![1u8; 32];
    assert_eq!(buf, expected);
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

impl<M: Message> Message for Vec<M> {
    fn write<W: Write>(&self, writer: &mut W) {
        for m in self {
            m.write(writer);
        }
    }
}

#[test]
fn test_write_vecmsg() {
    let mut buf = Vec::new();
    let vecmsg = vec![
        CompressedRistretto::from_slice(&[1u8; 32])
            .unwrap(),
        CompressedRistretto::from_slice(&[2u8; 32])
            .unwrap(),
        CompressedRistretto::from_slice(&[3u8; 32])
            .unwrap(),
    ];
    vecmsg.write(&mut buf);
    assert_eq!(vecmsg.size(), 96);
    let mut expected = vec![0u8; 96];
    expected[0..32].copy_from_slice(&[1u8; 32]);
    expected[32..64].copy_from_slice(&[2u8; 32]);
    expected[64..96].copy_from_slice(&[3u8; 32]);
    assert_eq!(buf, expected);
}
