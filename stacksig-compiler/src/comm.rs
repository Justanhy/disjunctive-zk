use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoBasepointTable};
use curve25519_dalek::scalar::Scalar;

use rand_core::{CryptoRng, RngCore};
use std::convert::TryInto;

use sha2::{Digest, Sha512};

use crate::stack::Message;
use crate::Side;

use std::fmt;
use std::io::Write;

use std::rc::Rc;

impl Message for CommitKey {
    fn write<W: Write>(&self, writer: &mut W) {
        let cp = self.0.basepoint().compress();
        writer.write_all(cp.as_bytes()).unwrap();
    }
}

pub type Randomness = Scalar;

#[derive(Eq, PartialEq, Debug)]
pub struct Commitment([u8; 32]);

impl Message for Commitment {
    fn write<W: Write>(&self, writer: &mut W) {
        writer.write_all(&self.0).unwrap();
    }
}

fn feistel_round(l: [u8; 16], mut r: [u8; 16]) -> ([u8; 16], [u8; 16]) {
    let mut hasher = Sha512::new();
    hasher.update(l);
    let pad = hasher.finalize();
    for i in 0..r.len() {
        r[i] ^= pad[i];
    }
    (r, l)
}

// Feistel is indempotent
fn feistel(v: &[u8; 32]) -> [u8; 32] {
    let (l, r) = v.split_at(16);
    let l = l.try_into().unwrap();
    let r = r.try_into().unwrap();

    let (l, r) = feistel_round(l, r);
    let (l, r) = feistel_round(l, r);
    let (l, r) = feistel_round(l, r);
    let (l, r) = feistel_round(l, r);

    let (l, r) = feistel_round(l, r);
    let (l, r) = feistel_round(l, r);
    let (l, r) = feistel_round(l, r);
    let (l, r) = feistel_round(l, r);

    let mut res: [u8; 32] = [0; 32];
    res[16..].copy_from_slice(&l);
    res[..16].copy_from_slice(&r);
    res
}

fn perm(v: &[u8; 32]) -> [u8; 32] {
    feistel(v)
}

fn perm_inv(v: &[u8; 32]) -> [u8; 32] {
    feistel(v)
}

pub struct Trapdoor {
    td: Scalar,
}

impl Trapdoor {
    pub fn equiv<M1: Message, M2: Message>(
        &self,
        random: &Scalar,
        old: (Option<&M1>, Option<&M2>),
        new: (Option<&M1>, Option<&M2>),
    ) -> Scalar {
        let old = (hash_option(old.0), hash_option(old.1));
        let new = (hash_option(new.0), hash_option(new.1));
        let delta = (old.0 - new.0) + (old.1 - new.1);
        random + self.td * delta
    }
}

#[derive(Clone)]
pub struct CommitKey(Rc<RistrettoBasepointTable>, Rc<RistrettoBasepointTable>);

impl fmt::Debug for CommitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitKey")
            .field("left", &self.0.basepoint())
            .field("right", &self.0.basepoint())
            .finish()
    }
}

fn hash<M: Message>(v: &M) -> Scalar {
    let mut hash = Sha512::new();
    v.write(&mut hash);
    Scalar::from_hash(hash)
}

fn hash_option<M: Message>(v: Option<&M>) -> Scalar {
    v.map(hash).unwrap_or(Scalar::zero())
}

impl CommitKey {
    pub fn gen<R: RngCore + CryptoRng>(
        rng: &mut R, // random tape
        side: Side,  // binding side
    ) -> (Self, Trapdoor) {
        let (td, l, r) = loop {
            let td = Scalar::random(rng);
            match side {
                Side::Left => {
                    let r = &td * &constants::RISTRETTO_BASEPOINT_TABLE;
                    let li = perm_inv(r.compress().as_bytes());
                    if let Some(l) = CompressedRistretto::from_slice(&li).decompress() {
                        break (td, l, r);
                    }
                }
                Side::Right => {
                    let l = &td * &constants::RISTRETTO_BASEPOINT_TABLE;
                    let ri = perm(l.compress().as_bytes());
                    if let Some(r) = CompressedRistretto::from_slice(&ri).decompress() {
                        break (td, l, r);
                    }
                }
            }
        };
        (
            CommitKey(
                Rc::new(RistrettoBasepointTable::create(&l)),
                Rc::new(RistrettoBasepointTable::create(&r)),
            ),
            Trapdoor { td },
        )
    }

    pub fn commit<M1: Message, M2: Message>(
        &self,
        random: &Randomness,
        values: (Option<&M1>, Option<&M2>),
    ) -> Commitment {
        // add randomness
        let comm = random * &constants::RISTRETTO_BASEPOINT_TABLE;

        // add first element
        let comm = values.0.map(|v| comm + &hash(v) * &*self.0).unwrap_or(comm);

        // add second element
        let comm = values.1.map(|v| comm + &hash(v) * &*self.1).unwrap_or(comm);

        Commitment(*comm.compress().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perm_inv() {
        let v: [u8; 32] = [
            0x42, 0x64, 0x32, 0x11, 0x42, 0x64, 0x32, 0x11, 0x42, 0x64, 0x32, 0x11, 0x42, 0x64,
            0x32, 0x11, 0x42, 0x64, 0x32, 0x11, 0x42, 0x64, 0x32, 0x11, 0x42, 0x64, 0x32, 0x11,
            0x42, 0x64, 0x32, 0x11,
        ];
        let pv = perm(&v);
        assert_eq!(v, perm_inv(&pv));
    }
}
