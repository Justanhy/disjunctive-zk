pub mod inner_outer;
pub mod qbinding;
use std::io::Write;

use inner_outer::*;
pub use qbinding::*;
use rand_core::CryptoRngCore;

use crate::commitment_scheme::halfbinding::{self, Side};
use crate::stackable::Message;

pub const MIN_Q: usize = 2;
/// Defines the binding index for a 1-of-2^q
/// partially-binding commitment scheme
#[derive(Copy, Clone, Debug, PartialEq, Hash)]
pub struct BindingIndex {
    q: usize,
    length: usize,
    index: usize, // 0-indexed
}

impl BindingIndex {
    pub fn new(q: usize, index: usize) -> Self {
        assert!(q >= MIN_Q);
        let length = 1 << q; // 2^q
        assert!(index < length);
        Self { q, length, index }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn length(&self) -> usize {
        self.length
    }

    pub fn is_base(&self) -> bool {
        self.q == MIN_Q
    }

    fn get_inner_raw(&self) -> usize {
        // index * (length / 2)
        self.index % (self.length >> 1)
    }

    pub fn get_inner(&self) -> Self {
        let raw = self.get_inner_raw();
        BindingIndex::new(self.q - 1, raw)
    }

    pub fn base_inner(&self) -> Option<Side> {
        if self.is_base() {
            match self.get_inner_raw() {
                0 => Some(Side::One),
                1 => Some(Side::Two),
                _ => None,
            }
        } else {
            None
        }
    }

    pub fn get_outer(&self) -> Side {
        // if self.index < (self.length / 2)
        if self.index < (self.length >> 1) {
            Side::One
        } else {
            Side::Two
        }
    }

    pub fn get_inner_outer(&self) -> (BindingIndex, Side) {
        let ia = self.get_inner();
        let ib = self.get_outer();
        (ia, ib)
    }

    pub fn base_inner_outer(&self) -> (Side, Side) {
        let ia = self
            .base_inner()
            .unwrap();
        let ib = self.get_outer();
        (ia, ib)
    }
}

#[derive(Clone, Debug)]
pub struct PublicParams {
    inner: Inner<halfbinding::PublicParams>,
    outer: halfbinding::PublicParams,
}

impl InnerOuter<halfbinding::PublicParams> for PublicParams {
    type Fields = ();

    fn init(
        inner: &Inner<halfbinding::PublicParams>,
        outer: &halfbinding::PublicParams,
        _: &Self::Fields,
    ) -> Self {
        Self {
            inner: inner.clone(),
            outer: outer.clone(),
        }
    }

    fn get_inner(&self) -> &Inner<halfbinding::PublicParams> {
        &self.inner
    }

    fn get_outer(&self) -> &halfbinding::PublicParams {
        &self.outer
    }
}

impl PublicParams {
    // pub fn gen_inner_pp(&self) -> Option<Self> {
    //     let (inner, outer) = self
    //         .inner
    //         .gen_inner_t()
    //         .unwrap();

    //     Some(Self { inner, outer })
    // }
}

#[derive(Clone, Debug, PartialEq, Hash, Default)]
pub struct CommitKey {
    pub inner_ck: Inner<halfbinding::CommitKey>,
    pub outer_ck: halfbinding::CommitKey,
}

impl CommitKey {
    pub fn gen_inner_ck(&self) -> Option<Self> {
        let (inner_ck, outer_ck) = self
            .inner_ck
            .gen_inner_t()
            .unwrap();

        Some(Self { inner_ck, outer_ck })
    }
}

impl InnerOuter<halfbinding::CommitKey> for CommitKey {
    type Fields = ();

    fn init(
        inner: &Inner<halfbinding::CommitKey>,
        outer: &halfbinding::CommitKey,
        _: &Self::Fields,
    ) -> Self {
        Self {
            inner_ck: inner.clone(),
            outer_ck: outer.clone(),
        }
    }

    fn get_inner(&self) -> &Inner<halfbinding::CommitKey> {
        &self.inner_ck
    }

    fn get_outer(&self) -> &halfbinding::CommitKey {
        &self.outer_ck
    }
}

impl Message for Inner<halfbinding::CommitKey> {
    fn write<W: Write>(&self, writer: &mut W) {
        for ck in &self.0 {
            ck.write(writer);
        }
    }
}

impl Message for CommitKey {
    fn write<W: Write>(&self, writer: &mut W) {
        self.inner_ck
            .write(writer);
        self.outer_ck
            .write(writer);
    }
}

#[derive(Clone, Debug, PartialEq, Hash)]
pub struct Randomness {
    pub inner: Inner<halfbinding::Randomness>,
    pub outer: halfbinding::Randomness,
}

impl InnerOuter<halfbinding::Randomness> for Randomness {
    type Fields = ();

    fn init(
        inner: &Inner<halfbinding::Randomness>,
        outer: &halfbinding::Randomness,
        _: &Self::Fields,
    ) -> Self {
        Self {
            inner: inner.clone(),
            outer: outer.clone(),
        }
    }

    fn get_inner(&self) -> &Inner<halfbinding::Randomness> {
        &self.inner
    }

    fn get_outer(&self) -> &halfbinding::Randomness {
        &self.outer
    }
}

impl Inner<halfbinding::Randomness> {
    pub fn random<R: CryptoRngCore>(rng: &mut R, q: usize) -> Self {
        Self(vec![halfbinding::Randomness::random(rng); q])
    }
}

impl Randomness {
    pub fn random<R: CryptoRngCore>(rng: &mut R, q: usize) -> Self {
        Randomness {
            inner: Inner::<halfbinding::Randomness>::random(rng, q),
            outer: halfbinding::Randomness::random(rng),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Hash)]
pub struct EquivKey {
    inner_ek: Inner<halfbinding::EquivKey>,
    outer_ek: halfbinding::EquivKey,
    ck: CommitKey,
    binding_index: BindingIndex,
}

impl EquivKey {
    pub fn binding_index(&self) -> &BindingIndex {
        &self.binding_index
    }

    pub fn ck(&self) -> &CommitKey {
        &self.ck
    }

    pub fn unroll(&self) -> Self
    where
        Self: Sized,
    {
        let initial = (
            self.ck
                .unroll(()),
            self.binding_index
                .get_inner(),
        );

        <Self as InnerOuter<halfbinding::EquivKey>>::unroll(&self, initial)
    }
}

impl InnerOuter<halfbinding::EquivKey> for EquivKey {
    type Fields = (CommitKey, BindingIndex);

    fn init(
        inner: &Inner<halfbinding::EquivKey>,
        outer: &halfbinding::EquivKey,
        fields: &Self::Fields,
    ) -> Self {
        Self {
            inner_ek: inner.clone(),
            ck: fields
                .0
                .clone(),
            outer_ek: outer.clone(),
            binding_index: fields
                .1
                .clone(),
        }
    }

    fn get_inner(&self) -> &Inner<halfbinding::EquivKey> {
        &self.inner_ek
    }

    fn get_outer(&self) -> &halfbinding::EquivKey {
        &self.outer_ek
    }
}
