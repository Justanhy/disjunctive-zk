use rand_core::CryptoRngCore;
use sigmazk::{EHVzk, SigmaProtocol};

use std::fmt::Debug;
use std::io::Write;

pub trait Message: Debug + Default {
    fn write<W: Write>(&self, writer: &mut W);

    fn size(&self) -> usize {
        let mut v: Vec<u8> = Vec::new();
        self.write(&mut v);
        v.len()
    }
}

impl Message for &[u8] {
    fn write<W: Write>(&self, writer: &mut W) {
        writer
            .write_all(self)
            .unwrap();
    }
}

pub trait Challenge {
    fn new(bytes: &[u8; 64]) -> Self;
}

pub trait Randomizable {
    fn randomize<R: CryptoRngCore>(&mut self, rng: &mut R);
}

pub trait Stackable:
    SigmaProtocol<
        Statement: Randomizable,
        MessageA: Message,
        MessageZ: Message,
        Challenge: Challenge,
    > + EHVzk
{
    const CLAUSES: usize = 1;
}
