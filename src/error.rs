// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Alias for a `Result` with the error type [`Error`].
pub type Result<T> = ::core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
  #[error("invalid input: {0}")]
  InvalidDisclosure(String),

  #[error("no hasher can be specified for the hashing algorithm {0}")]
  MissingHasher(String),

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

  #[error("index {0} is out of bounds for the provided array")]
  IndexOutofBounds(usize),

  #[error("{0}")]
  Unspecified(String),

  #[error("salt size must be greater or equal 16")]
  InvalidSaltSize,
}
