use rand_core::{CryptoRng, RngCore};

use std::io::Write;

pub trait Message {
    fn write<W: Write>(&self, writer: &mut W);

    fn size(&self) -> usize {
        let mut v: Vec<u8> = Vec::new();
        self.write(&mut v);
        v.len()
    }
}

impl Message for [u8] {
    fn write<W: Write>(&self, writer: &mut W) {
        writer.write_all(self).unwrap();
    }
}

pub trait Challenge {
    fn new(bytes: &[u8; 64]) -> Self;
}

pub trait Stackable {
    type State;
    type Witness;
    type Statement;

    type MessageA: Message;
    type MessageZ: Message;
    type Challenge: Challenge;

    type Precompute;

    const CLAUSES: usize = 1;

    // produce a first round message
    fn sigma_a<R: RngCore + CryptoRng>(
        rng: &mut R,
        witness: &Self::Witness,
    ) -> (Self::State, Self::MessageA);

    // produce a third round message
    fn sigma_z(
        statement: &Self::Statement,
        witness: &Self::Witness,
        state: &Self::State,
        challenge: &Self::Challenge,
    ) -> (Self::Precompute, Self::MessageZ);

    // simulator
    fn ehvzk(
        precom: &Self::Precompute,
        statement: &Self::Statement,
        challenge: &Self::Challenge,
        z: &Self::MessageZ,
    ) -> Self::MessageA;
}
