use std::ops::RangeInclusive;

#[derive(Debug, PartialEq)]
pub struct CommonError(String);

impl CommonError {
    pub fn wrong_length_bytes() -> CommonError {
        CommonError("Wrong length bytes".to_owned())
    }

    pub fn division_by_zero() -> CommonError {
        CommonError("Division by zero".to_owned())
    }

    pub fn invalid_random_bits_length<N>(value: N, range: RangeInclusive<N>) -> CommonError
    where
        N: std::fmt::Display + std::fmt::Debug,
    {
        let msg = format!("Invalid random bits length: given {value} not in {range:?}",);
        CommonError(msg)
    }
}
