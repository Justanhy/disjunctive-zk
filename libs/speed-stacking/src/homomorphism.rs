use std::fmt::Debug;

use group::ff::PrimeField;
use group::Group;

/// In this work we consider group homomorphisms $f: Z_q^n
/// -> G_T$ where $G_T$ is an abelian group.
///
/// In this trait $X \in Z_q$ and $Y \in G_T$. The trait
/// requires the implementation of the homomorphism $f$ that
/// takes a vector of $X$ ($n$ is the length of the vector)
/// and outputs $Y$
pub trait Hom<X: PrimeField, Y: Group>: Clone + Copy + Debug {
    fn f(&self, x: &Vec<X>) -> Y {
        let n = x.len() / 2;
        self.fleft(&x[..n]) + self.fright(&x[n..])
    }

    fn fleft(&self, x: &[X]) -> Y;

    fn fright(&self, x: &[X]) -> Y;
}
