use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("1Password CLI is unavailable: {0}")]
    OpUnavailable(String),
    #[error("1Password CLI failed: {0}")]
    OpFailed(String),
    #[error("item not found")]
    NotFound,
    #[error("not permitted: {0}")]
    NotPermitted(String),
    #[error("not supported: {0}")]
    NotSupported(String),
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for zbus::fdo::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::NotSupported(message) => zbus::fdo::Error::NotSupported(message),
            Error::Invalid(message) => zbus::fdo::Error::InvalidArgs(message),
            other => zbus::fdo::Error::Failed(other.to_string()),
        }
    }
}
