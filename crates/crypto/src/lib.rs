pub mod base58;
pub mod commitment;
pub mod error;
pub mod extend_key;
pub mod facproof;
mod fixed_bytes;
pub mod hash;
pub mod hdpath;
pub mod proof;

pub use error::CryptoError;
type Result<T> = std::result::Result<T, CryptoError>;
