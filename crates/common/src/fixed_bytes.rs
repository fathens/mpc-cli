pub trait FixedBytes {
    fn copy_bytes(&self) -> bytes::Bytes;
}

macro_rules! fixed_bytes {
    ($t:ident) => {
        impl TryFrom<&[u8]> for $t {
            type Error = crate::CommonError;

            fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
                Ok(Self(
                    src.try_into()
                        .map_err(|_| crate::CommonError::wrong_length_bytes())?,
                ))
            }
        }

        impl TryFrom<bytes::Bytes> for $t {
            type Error = crate::CommonError;

            fn try_from(src: bytes::Bytes) -> Result<Self, Self::Error> {
                src.as_ref().try_into()
            }
        }

        impl FixedBytes for $t {
            fn copy_bytes(&self) -> bytes::Bytes {
                bytes::Bytes::copy_from_slice(self.as_ref())
            }
        }

        impl AsRef<[u8]> for $t {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}
pub(crate) use fixed_bytes;
