use crate::Hasher;

pub(crate) struct Utils {}

impl Utils {
  pub(crate) fn digest_b64_url_only_ascii(hasher: &dyn Hasher, input: &str) -> String {
    // "The digest MUST be taken over the US-ASCII bytes of the base64url-encoded Disclosure".
    let ascii_bytes: Vec<u8> = input.as_bytes().iter().cloned().filter(|&byte| byte <= 127).collect();
    let hash = hasher.digest(&ascii_bytes);
    // "The bytes of the digest MUST then be base64url-encoded".
    multibase::Base::from(multibase::Base::Base64Url).encode(hash)
  }
}

// Some test values taken from https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-hashing-disclosures
#[cfg(test)]
mod test {
  use crate::ShaHasher;

  use super::Utils;

  #[test]
  fn test1() {
    let disclosure = "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
    let hasher = ShaHasher::new();
    let hash = Utils::digest_b64_url_only_ascii(&hasher, disclosure);
    assert_eq!("uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY", hash);
  }

  #[test]
  fn test2() {
    let disclosure =
      "WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImVtYWlsIiwgIlwidW51c3VhbCBlbWFpbCBhZGRyZXNzXCJAZXhhbXBsZS5qcCJd";
    let hasher = ShaHasher::new();
    let hash = Utils::digest_b64_url_only_ascii(&hasher, disclosure);
    assert_eq!("Kuet1yAa0HIQvYnOVd59hcViO9Ug6J2kSfqYRBeowvE", hash);
  }

  #[test]
  fn test3() {
    let disclosure = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0";
    let hasher = ShaHasher::new();
    let hash = Utils::digest_b64_url_only_ascii(&hasher, disclosure);
    assert_eq!("w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs", hash);
  }
}
