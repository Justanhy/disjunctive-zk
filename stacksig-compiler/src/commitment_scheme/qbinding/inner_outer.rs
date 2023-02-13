use std::fmt::Debug;

#[derive(Clone, Debug, PartialEq, Hash, Default)]
pub struct Inner<T: Clone>(pub Vec<T>);

impl<T: Clone> Inner<T> {
    pub fn new(first: T) -> Self {
        Self(vec![first])
    }

    pub fn init(inner: Vec<T>) -> Self {
        Self(inner)
    }

    pub fn push(&mut self, t: T) {
        self.0
            .push(t);
    }

    pub fn first(&self) -> Option<&T> {
        self.0
            .first()
    }

    pub fn last(&self) -> Option<&T> {
        self.0
            .last()
    }

    /// Get copies of the vector of first N - 1 elements and
    /// the last element
    /// TODO: Replace Option with Result
    pub fn gen_inner_t(&self) -> Option<(Self, T)> {
        if self
            .0
            .len()
            < 2
        {
            return None;
        }

        let mut copy = self
            .0
            .clone();
        let outer = copy
            .pop()
            .unwrap();

        Some((Inner::init(copy), outer))
    }
}

pub trait InnerOuter<T: Clone + Debug> {
    type Fields;

    fn init(inner: &Inner<T>, outer: &T, rest: &Self::Fields) -> Self;
    fn get_inner(&self) -> &Inner<T>;
    fn get_outer(&self) -> &T;
    /// Composes the inner and outer components into
    /// a single Inner component by pushing outer
    /// into the inner vector
    fn compose(&self) -> Inner<T> {
        let mut inner = self
            .get_inner()
            .0
            .clone();
        inner.push(
            self.get_outer()
                .clone(),
        );
        Inner::init(inner)
    }
    /// Unrolls the inner vector into a new InnerOuter
    /// instance with a outer component that is normally
    /// the last element of the inner vector
    fn unroll(&self, initial: Self::Fields) -> Self
    where
        Self: Sized,
    {
        let (inner, outer) = self
            .get_inner()
            .gen_inner_t()
            .unwrap();
        Self::init(&inner, &outer, &initial)
    }
    /// Get the first element of the inner vector which is
    /// usually the innermost T
    fn base_inner(&self) -> &T {
        self.get_inner()
            .first()
            .unwrap()
    }
}
