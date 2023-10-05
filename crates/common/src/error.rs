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

    pub fn out_of_range<N>(value: N, range: RangeInclusive<N>) -> CommonError
    where
        N: std::fmt::Display + std::fmt::Debug,
    {
        let msg = format!("Out of range: given {value} not in {range:?}",);
        CommonError(msg)
    }

    pub fn invalid_argument<A>(value: A, msg: &str) -> CommonError
    where
        A: std::fmt::Display + std::fmt::Debug,
    {
        let msg = format!("Invalid argument: {value}: {msg}",);
        CommonError(msg)
    }
}
