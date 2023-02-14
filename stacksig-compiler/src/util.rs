use curve25519_dalek::scalar::Scalar;
use digest::Digest;
use sha2::Sha512;

use crate::stackable::Message;

pub(crate) fn hash<M: Message + ?Sized>(v: &M) -> Scalar {
    let mut hash = Sha512::new();
    v.write(&mut hash);
    Scalar::from_hash(hash)
}
