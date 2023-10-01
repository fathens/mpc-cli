pub mod error;
pub mod fixed_bytes;
pub mod hash;
pub mod hash_utils;
pub mod mod_int;
pub mod slice;

pub use error::CommonError;

type Result<T> = std::result::Result<T, CommonError>;
