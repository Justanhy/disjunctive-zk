use thiserror::Error;

#[derive(Error, Debug)]
pub enum ShamirError {
    #[error(
        "Unqualified set should have size t - 1 (1 less \
         than the threshold)"
    )]
    InvalidUnqualifiedSet,
    #[error(
        "Lagrange polynomial could not be initialised: x \
         and y coordinates must have the same size"
    )]
    InvalidCoordinateSizes,
    #[error(
        "Share has x-coordinate of 0 implying that it is \
         the secret which is not allowed"
    )]
    InvalidShare,
    #[error("Not enough shares to reconstruct the secret")]
    NotEnoughShares,
}
