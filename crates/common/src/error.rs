#[derive(Debug)]
pub struct CommonError(String);

impl CommonError {
    pub fn wrong_length_bytes() -> CommonError {
        CommonError("Wrong length bytes".to_owned())
    }
}
