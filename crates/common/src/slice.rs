use bytes::{BufMut, Bytes, BytesMut};
use num_bigint::BigUint;
use num_traits::Zero;
use std::cmp::max;

pub fn bigints_to_bytes(src_list: &[BigUint]) -> Vec<Bytes> {
    src_list
        .iter()
        .map(|v| {
            if v.is_zero() {
                Bytes::new()
            } else {
                v.to_bytes_be().into()
            }
        })
        .collect()
}

pub fn multibytes_to_bigints(src_list: &[Bytes]) -> Vec<BigUint> {
    src_list
        .iter()
        .map(|v| BigUint::from_bytes_be(v.as_ref()))
        .collect()
}

pub fn pad_left(src: Bytes, len: usize) -> Bytes {
    let mut buf = BytesMut::with_capacity(max(len, src.len()));
    let left_len = if len > src.len() { len - src.len() } else { 0 };
    buf.resize(left_len, 0);
    buf.put(src);
    buf.freeze()
}

pub fn is_non_empty_all(src_list: &[Bytes]) -> bool {
    !src_list.is_empty() && src_list.iter().all(|v| !v.is_empty())
}

pub fn is_non_empty_with_length(src_list: &[Bytes], expected_len: usize) -> bool {
    !src_list.is_empty() && src_list.len() == expected_len && src_list.iter().all(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bigints_to_bytes_test() {
        let check = |src: &[u32], expected: &[&[u8]]| {
            let src: Vec<_> = src.iter().map(|v| BigUint::from(*v)).collect();
            let actual = bigints_to_bytes(src.as_slice());
            assert_eq!(actual.len(), expected.len());
            for (a, e) in actual.iter().zip(expected.iter()) {
                assert_eq!(a.as_ref(), *e);
            }
        };

        check(&[], &[]);
        check(&[0], &[&[]]);
        check(&[1], &[&[1]]);
        check(&[1, 2, 3], &[&[1], &[2], &[3]]);
        check(&[1, 2, 0, 731], &[&[1], &[2], &[], &[2, 219]]);
    }

    #[test]
    fn multibytes_to_bigints_test() {
        let check = |src: &[&[u8]], expected: &[u32]| {
            let src: Vec<_> = src.iter().map(|v| Vec::from(*v).into()).collect();
            let actual = multibytes_to_bigints(src.as_slice());
            assert_eq!(actual.len(), expected.len());
            for (a, e) in actual.iter().zip(expected.iter()) {
                assert_eq!(*a, BigUint::from(*e));
            }
        };

        check(&[], &[]);
        check(&[&[]], &[0]);
        check(&[&[1]], &[1]);
        check(&[&[1], &[2], &[3]], &[1, 2, 3]);
        check(&[&[1], &[2], &[], &[2, 219]], &[1, 2, 0, 731]);
    }

    #[test]
    fn pad_left_test() {
        let check = |src: &[u8], len: usize, expected: &[u8]| {
            let actual = pad_left(Vec::from(src).into(), len);
            assert_eq!(actual.as_ref(), expected);
        };

        check(&[], 0, &[]);
        check(&[], 1, &[0]);
        check(&[1], 1, &[1]);
        check(&[1], 2, &[0, 1]);
        check(&[1, 2, 3], 5, &[0, 0, 1, 2, 3]);
        check(&[1, 2, 3], 3, &[1, 2, 3]);
        check(&[1, 2, 3], 2, &[1, 2, 3]);
        check(&[1, 2, 3], 1, &[1, 2, 3]);
        check(&[1, 2, 3], 0, &[1, 2, 3]);
    }

    #[test]
    fn is_non_empty_all_test() {
        let check = |src: &[&[u8]], expected: bool| {
            let src: Vec<_> = src.iter().map(|v| Vec::from(*v).into()).collect();
            let actual = is_non_empty_all(src.as_slice());
            assert_eq!(actual, expected);
        };

        check(&[], false);
        check(&[&[]], false);
        check(&[&[1]], true);
        check(&[&[1], &[2], &[3]], true);
        check(&[&[1], &[2], &[], &[2, 219]], false);
    }

    #[test]
    fn is_non_empty_with_length_test() {
        let check = |src: &[&[u8]], with_len: usize, expected: bool| {
            let src: Vec<_> = src.iter().map(|v| Vec::from(*v).into()).collect();
            let actual = is_non_empty_with_length(src.as_slice(), with_len);
            assert_eq!(actual, expected);
        };

        check(&[], 0, false);
        check(&[], 1, false);
        check(&[&[]], 0, false);
        check(&[&[]], 1, false);
        check(&[&[1]], 0, false);
        check(&[&[1]], 1, true);
        check(&[&[1], &[2], &[3]], 3, true);
        check(&[&[1], &[2], &[], &[2, 219]], 4, false);
    }
}
