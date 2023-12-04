// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::hashes::sha::SHA256;
use crypto::hashes::sha::SHA256_LEN;

/// Used to implement hash functions to be used for encoding/decoding.
///
/// ## Note
///
/// Implementations of this trait are expected only for algorithms listed in
/// the IANA "Named Information Hash Algorithm" registry.
/// See [Hash Function Claim](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-06.html#name-hash-function-claim)
pub trait Hasher: Sync + Send {
  /// Digests input to produce unique fixed-size hash value in bytes.
  fn digest(&self, input: &[u8]) -> Vec<u8>;

  /// Returns the name of hash function used.
  ///
  /// ## Note
  ///
  /// The hash algorithm identifier MUST be a hash algorithm value from the
  /// "Hash Name String" column in the IANA "Named Information Hash Algorithm"  
  fn alg_name(&self) -> &'static str;
}

/// An implementation of [`Hasher`] that uses the `sha-256` hash function.
#[derive(Default)]
pub struct Sha256Hasher;

impl Sha256Hasher {
  pub const ALG_NAME: &'static str = "sha-256";
  /// Creates a new [`ShaHasher`]
  pub fn new() -> Self {
    Sha256Hasher {}
  }
}

impl Hasher for Sha256Hasher {
  fn digest(&self, input: &[u8]) -> Vec<u8> {
    let mut digest: [u8; SHA256_LEN] = Default::default();
    SHA256(input, &mut digest);
    digest.to_vec()
  }

  fn alg_name(&self) -> &'static str {
    Sha256Hasher::ALG_NAME
  }
}
