use crypto::hashes::sha::{SHA256, SHA256_LEN};

/// Used to implement hash functions to be used for encoding/decoding.
pub trait Hasher: Sync + Send {
  /// Digests input to produce unique fixed-size hash value in bytes.
  fn digest(&self, input: &[u8]) -> Vec<u8>;
  /// Returns the name of hash function used.
  fn alg_name(&self) -> &'static str;
}

/// An implementation of [`Hasher`] that uses the `sha-256` hash function.
pub struct ShaHasher;

impl ShaHasher {
  pub const ALG_NAME: &str = "sha-256";
  /// Creates a new [`ShaHasher`]
  pub fn new() -> Self {
    ShaHasher {}
  }
}

impl Hasher for ShaHasher {
  fn digest(&self, input: &[u8]) -> Vec<u8> {
    let mut digest: [u8; SHA256_LEN] = Default::default();
    SHA256(input, &mut digest);
    digest.to_vec()
  }

  fn alg_name(&self) -> &'static str {
    ShaHasher::ALG_NAME
  }
}
