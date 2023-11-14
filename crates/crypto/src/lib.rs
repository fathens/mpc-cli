pub mod base58;
pub mod commitment;
pub mod error;
pub mod extend_key;
mod fixed_bytes;
pub mod hash;
pub mod hdpath;
pub mod paillier;
pub mod proof;
pub mod utils;

pub use error::CryptoError;
type Result<T> = std::result::Result<T, CryptoError>;
