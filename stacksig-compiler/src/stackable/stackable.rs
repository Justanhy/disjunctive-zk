use rand_core::{CryptoRng, RngCore};
use sigmazk::{EHVzk, SigmaProtocol};

use std::{fmt::Debug, io::Write};

// Trait for messages exchanged in a Stacakble protocol
pub trait Message: Debug {
    fn write<W: Write>(&self, writer: &mut W);

    fn size(&self) -> usize {
        let mut v: Vec<u8> = Vec::new();
        self.write(&mut v);
        v.len()
    }
}

// Implementation of Message for [u8]
impl Message for [u8] {
    fn write<W: Write>(&self, writer: &mut W) {
        writer
            .write_all(self)
            .unwrap();
    }
}

pub trait Challenge {
    fn new(bytes: &[u8; 64]) -> Self;
}

pub trait Stackable: SigmaProtocol + EHVzk {
    type A: Message;
    type C: Challenge;
    type Z: Message;

    const CLAUSES: usize = 1;
}
