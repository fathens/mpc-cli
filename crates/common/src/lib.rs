pub mod error;
pub mod fixed_bytes;
pub mod hash;
pub mod hash_utils;
mod mod_int;

pub use error::CommonError;

type Result<T> = std::result::Result<T, CommonError>;
