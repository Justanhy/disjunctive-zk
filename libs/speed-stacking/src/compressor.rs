#[derive(Clone, Debug)]
pub struct Compressor {
    clauses: usize,
}

impl Compressor {
    pub fn new(clauses: usize) -> Self {
        Self { clauses }
    }
}
