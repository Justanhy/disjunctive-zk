use group::{Group, ScalarMul, ScalarMulOwned};

pub mod ristretto;
pub mod scalar;

pub trait CommonField<G: Group>:
    Group + ScalarMul<G::Scalar> + ScalarMulOwned<G::Scalar>
{
}
