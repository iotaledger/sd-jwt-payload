/// Alias for a `Result` with the error type [`Error`].
pub type Result<T> = ::core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
  #[error("invalid input {0}")]
  InvalidDisclosure(String),

  #[error("no hashing algorithm can be specified for the provided input")]
  HashingAlgorithmError,

  #[error("data type is not expected: {0}")]
  DataTypeMismatch(String),

  #[error("claim {0} of disclosure already exists")]
  ClaimCollisionError(String),

  #[error("digest {0} appears multiple times")]
  DuplicateDigestError(String),

  #[error("array disclosure object contains keys other than `...`")]
  InvalidArrayDisclosureObject,

  #[error("invalid path: {0}")]
  InvalidPath(String),

  #[error("invalid input")]
  DeserializationError(String),

  #[error("index out of bounds for the array was provided")]
  IndexOutofBounds,

  #[error("{0}")]
  Unspecified(String),
}
