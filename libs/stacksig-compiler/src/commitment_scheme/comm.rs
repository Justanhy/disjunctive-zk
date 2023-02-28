use rand_core::CryptoRngCore;

use crate::stackable::Message;

pub trait PartialBindingCommScheme {
    type PublicParams;
    type BindingIndex: Copy;
    type CommitKey;
    type EquivKey;
    type Commitment;
    type Randomness;
    type Msg<'a, M: Message + 'a>;

    fn setup<R: CryptoRngCore>(&self, rng: &mut R) -> Self::PublicParams;

    fn gen<R: CryptoRngCore>(
        &self,
        pp: &Self::PublicParams,
        binding_index: Self::BindingIndex,
        rng: &mut R,
    ) -> (Self::CommitKey, Self::EquivKey);

    fn bind<'a, M: Message + ?Sized>(
        &self,
        pp: &Self::PublicParams,
        ck: &Self::CommitKey,
        msg: &Self::Msg<'a, M>,
        randomness: &Self::Randomness,
    ) -> Self::Commitment;

    fn equiv<'a, M: Message + ?Sized>(
        &self,
        pp: &Self::PublicParams,
        ek: &Self::EquivKey,
        old_msg: &Self::Msg<'a, M>,
        new_msg: &Self::Msg<'a, M>,
        old_randomness: &Self::Randomness,
    ) -> Self::Randomness;

    fn equivcom<'a, M: Message + ?Sized>(
        &self,
        pp: &Self::PublicParams,
        ek: &Self::EquivKey,
        msg: &Self::Msg<'a, M>,
        randomness: Option<Self::Randomness>,
    ) -> (Self::Commitment, Self::Randomness);
}
