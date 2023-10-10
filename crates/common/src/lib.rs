pub mod error;
pub mod fixed_bytes;
pub mod hash;
pub mod hash_utils;
pub mod miller_rabin;
pub mod mod_int;
pub mod random;
pub mod safe_prime;
pub mod slice;
pub mod time;

pub use error::CommonError;

type Result<T> = std::result::Result<T, CommonError>;
