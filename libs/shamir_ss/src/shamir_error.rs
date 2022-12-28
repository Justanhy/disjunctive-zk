use vsss_rs::Error;

#[derive(Debug)]
pub enum ShamirError {
    InvalidUnqualifiedSet,
    Error(Error),
}
