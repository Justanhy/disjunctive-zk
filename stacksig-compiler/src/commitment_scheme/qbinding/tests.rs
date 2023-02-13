use super::*;

#[cfg(test)]
mod test_binding_index {
    use super::*;

    #[test]
    fn test_new_binding_index() {
        let q: usize = 4;
        let index: usize = 5;
        let bi = BindingIndex::new(q, index);
        assert_eq!(bi.q(), q);
        assert_eq!(bi.length(), 16);
        assert_eq!(bi.index(), index);
        assert_eq!(bi.get_inner_raw(), index);
        let inner_3 = bi.get_inner();
        assert_eq!(inner_3.q(), 3);
        assert_eq!(inner_3.length(), 8);
        assert_eq!(inner_3.index(), index);
        assert_eq!(inner_3.is_base(), false);
        assert_eq!(inner_3.base_inner(), None);
        assert_eq!(bi.get_outer(), Side::One);
        assert_eq!(inner_3.get_outer(), Side::Two);
        let inner_base = inner_3.get_inner();
        assert_eq!(inner_base.q(), 2);
        assert_eq!(inner_base.length(), 4);
        assert_eq!(inner_base.index(), 1);
        assert_eq!(inner_base.is_base(), true);
        assert_eq!(inner_base.base_inner(), Some(Side::Two));
        assert_eq!(inner_base.get_outer(), Side::One);
    }
}

#[cfg(test)]
mod test_inner_outer {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    use crate::commitment_scheme::halfbinding::CommitKey;
    use crate::commitment_scheme::qbinding::CommitKey as QCommitKey;

    use super::*;

    #[test]
    fn test_inner_outer() {
        let two: Scalar = Scalar::ONE + Scalar::ONE;
        let inner_vec = vec![
            Scalar::ONE,
            two,
            Scalar::ONE + two,
            two + two,
            two + two + Scalar::ONE,
            two + two + two,
            two + two + two + Scalar::ONE,
            two + two + two + two,
        ];
        let inner_vec: Vec<CommitKey> = inner_vec
            .iter()
            .map(|s| CommitKey((s * RISTRETTO_BASEPOINT_TABLE).compress()))
            .collect();
        let inner_ck = Inner::init(inner_vec);
        let outer_ck = CommitKey(
            (&Scalar::from_bits([9u8; 32]) * RISTRETTO_BASEPOINT_TABLE)
                .compress(),
        );
        let ck = QCommitKey { inner_ck, outer_ck };
        let ck_up = QCommitKey {
            inner_ck: ck.compose(),
            outer_ck,
        };
        let ck_down = ck_up.extract(());
        assert!(ck == ck_down);
        let ck = ck
            .extract(())
            .extract(())
            .extract(())
            .extract(())
            .extract(())
            .extract(())
            .extract(()); // 7
        let base_inner = ck.base_inner();
        assert!(
            base_inner.0
                == (&Scalar::ONE * RISTRETTO_BASEPOINT_TABLE).compress()
        );

        assert!(
            ck.get_outer()
                .0
                == (&two * RISTRETTO_BASEPOINT_TABLE).compress()
        )
    }
}
