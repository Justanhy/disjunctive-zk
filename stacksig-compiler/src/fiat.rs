use sha2::{Digest, Sha512};

use std::io::Write;
use std::marker::PhantomData;

use rand_core::{CryptoRng, RngCore};

use crate::stack::{Challenge, Message, Stackable};

pub struct SignatureScheme<S: Stackable>(PhantomData<S>);

#[derive(Debug)]
pub struct Signature<S: Stackable> {
    a: S::MessageA,
    z: S::MessageZ,
}

impl<S: Stackable> Message for Signature<S> {
    fn write<W: Write>(&self, writer: &mut W) {
        self.a.write(writer);
        self.z.write(writer);
    }
}

impl<S: Stackable> SignatureScheme<S> {
    pub fn sign<R: RngCore + CryptoRng>(
        rng: &mut R,
        sk: &S::Witness,
        pk: &S::Statement,
        msg: &[u8],
    ) -> Signature<S> {
        // create first message
        let (st, a) = S::sigma_a(rng, sk);

        // Fiat-Shamir
        let challenge = {
            // hash first round and message
            let mut h = Sha512::new();
            a.write(&mut h);
            h.write(msg).unwrap();

            // convert to challenge
            let mut c: [u8; 64] = [0u8; 64];
            c.copy_from_slice(&h.finalize());
            S::Challenge::new(&c)
        };

        // finish last message
        let (_, z) = S::sigma_z(pk, sk, &st, &challenge);
        Signature { a, z }
    }
}
