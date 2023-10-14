pub mod error;
pub mod mod_int;
pub mod prime;
pub mod random;
pub mod slice;
pub mod time;

pub use error::CommonError;

type Result<T> = std::result::Result<T, CommonError>;
