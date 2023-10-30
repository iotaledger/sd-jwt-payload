use std::fmt::Display;

use crate::Error;
use crate::Result;
use itertools::Itertools;

/// Representation of an SD-JWT of the format
/// `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~<optional KB-JWT>`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SdJwt {
  /// The JWT part.
  pub jwt: String,
  /// The disclosures part.
  pub disclosures: Vec<String>,
  /// The optional key binding JWT.
  pub key_binding_jwt: Option<String>,
}

impl SdJwt {
  /// Creates a new [`SdJwt`] from its components.
  pub fn new(jwt: String, disclosures: Vec<String>, key_binding_jwt: Option<String>) -> Self {
    Self {
      jwt,
      disclosures,
      key_binding_jwt,
    }
  }

  /// Serializes the components into the final SD-JWT.
  ///
  /// ## Error
  /// Returns [`Error::DeserializationError`] if parsing fails.
  pub fn presentation(&self) -> String {
    let disclosures = self.disclosures.iter().cloned().join("~");
    let key_bindings: String = if let Some(key_bindings) = &self.key_binding_jwt {
      key_bindings.clone()
    } else {
      "".to_owned()
    };
    format!("{}~{}~{}", self.jwt, disclosures, key_bindings)
  }

  /// Serializes the components into the final SD-JWT.
  ///
  /// ## Error
  /// Returns [`Error::DeserializationError`] if parsing fails.
  pub fn into_presentation(self) -> String {
    let disclosures = self.disclosures.into_iter().join("~");
    let key_bindings: String = if let Some(key_bindings) = self.key_binding_jwt {
      key_bindings
    } else {
      "".to_owned()
    };
    format!("{}~{}~{}", self.jwt, disclosures, key_bindings)
  }

  /// Parses an SD-JWT into its components as [`SdJwt`].
  pub fn parse(sd_jwt: &str) -> Result<Self> {
    let sd_segments: Vec<&str> = sd_jwt.split('~').collect();
    let num_of_segments = sd_segments.len();
    if num_of_segments < 2 {
      return Err(Error::DeserializationError(
        "SD-JWT format is invalid, less than 2 segments".to_string(),
      ));
    }

    let includes_key_binding = sd_jwt.chars().next_back().map(|char| char != '~').unwrap_or(false);
    if includes_key_binding && num_of_segments < 3 {
      return Err(Error::DeserializationError(
        "SD-JWT format is invalid, less than 3 segments with key binding jwt".to_string(),
      ));
    }

    let jwt = sd_segments.first().unwrap().to_string();
    let disclosures: Vec<String> = sd_segments[1..num_of_segments - 1]
      .iter()
      .map(|disclosure| disclosure.to_string())
      .collect();

    let key_binding = includes_key_binding.then(|| sd_segments[num_of_segments - 1].to_string());

    Ok(Self {
      jwt,
      disclosures,
      key_binding_jwt: key_binding,
    })
  }
}

impl Display for SdJwt {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&(self.presentation()))
  }
}

#[cfg(test)]
mod test {
  use crate::SdJwt;
  #[test]
  fn parse() {
    let sd_jwt_str = "eyJhbGciOiAiRVMyNTYifQ.eyJAY29udGV4dCI6IFsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCAiaHR0cHM6Ly93M2lkLm9yZy92YWNjaW5hdGlvbi92MSJdLCAidHlwZSI6IFsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCAiVmFjY2luYXRpb25DZXJ0aWZpY2F0ZSJdLCAiaXNzdWVyIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlzc3VhbmNlRGF0ZSI6ICIyMDIzLTAyLTA5VDExOjAxOjU5WiIsICJleHBpcmF0aW9uRGF0ZSI6ICIyMDI4LTAyLTA4VDExOjAxOjU5WiIsICJuYW1lIjogIkNPVklELTE5IFZhY2NpbmF0aW9uIENlcnRpZmljYXRlIiwgImRlc2NyaXB0aW9uIjogIkNPVklELTE5IFZhY2NpbmF0aW9uIENlcnRpZmljYXRlIiwgImNyZWRlbnRpYWxTdWJqZWN0IjogeyJfc2QiOiBbIjFWX0stOGxEUThpRlhCRlhiWlk5ZWhxUjRIYWJXQ2k1VDB5Ykl6WlBld3ciLCAiSnpqTGd0UDI5ZFAtQjN0ZDEyUDY3NGdGbUsyenk4MUhNdEJnZjZDSk5XZyIsICJSMmZHYmZBMDdaX1lsa3FtTlp5bWExeHl5eDFYc3RJaVM2QjFZYmwySlo0IiwgIlRDbXpybDdLMmdldl9kdTdwY01JeXpSTEhwLVllZy1GbF9jeHRyVXZQeGciLCAiVjdrSkJMSzc4VG1WRE9tcmZKN1p1VVBIdUtfMmNjN3laUmE0cVYxdHh3TSIsICJiMGVVc3ZHUC1PRERkRm9ZNE5semxYYzN0RHNsV0p0Q0pGNzVOdzhPal9nIiwgInpKS19lU01YandNOGRYbU1aTG5JOEZHTTA4ekozX3ViR2VFTUotNVRCeTAiXSwgInZhY2NpbmUiOiB7Il9zZCI6IFsiMWNGNWhMd2toTU5JYXFmV0pyWEk3Tk1XZWRMLTlmNlkyUEE1MnlQalNaSSIsICJIaXk2V1d1ZUxENWJuMTYyOTh0UHY3R1hobWxkTURPVG5CaS1DWmJwaE5vIiwgIkxiMDI3cTY5MWpYWGwtakM3M3ZpOGViT2o5c214M0MtX29nN2dBNFRCUUUiXSwgInR5cGUiOiAiVmFjY2luZSJ9LCAicmVjaXBpZW50IjogeyJfc2QiOiBbIjFsU1FCTlkyNHEwVGg2T0d6dGhxLTctNGw2Y0FheHJZWE9HWnBlV19sbkEiLCAiM256THE4MU0yb04wNndkdjFzaEh2T0VKVnhaNUtMbWREa0hFREpBQldFSSIsICJQbjFzV2kwNkc0TEpybm4tX1JUMFJiTV9IVGR4blBKUXVYMmZ6V3ZfSk9VIiwgImxGOXV6ZHN3N0hwbEdMYzcxNFRyNFdPN01HSnphN3R0N1FGbGVDWDRJdHciXSwgInR5cGUiOiAiVmFjY2luZVJlY2lwaWVudCJ9LCAidHlwZSI6ICJWYWNjaW5hdGlvbkV2ZW50In0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.l7byWDsTtDOjFbWS4lko-3mkeeZwzUYw6ZicrJurES_gzs6EK_svPiVwj5g6evb_nmLWpK2_cXQ_J0cjH0XnGw~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgIm9yZGVyIiwgIjMvMyJd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImRhdGVPZlZhY2NpbmF0aW9uIiwgIjIwMjEtMDYtMjNUMTM6NDA6MTJaIl0~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImF0Y0NvZGUiLCAiSjA3QlgwMyJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgIm1lZGljaW5hbFByb2R1Y3ROYW1lIiwgIkNPVklELTE5IFZhY2NpbmUgTW9kZXJuYSJd~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE2OTgwNzc3OTAsICJfc2RfaGFzaCI6ICJ1MXpzTkxGUXhlVkVGcFRmT1Z1NFRjSTNaYjdDX1UzYTFFNGVzQVlRLXpZIn0.LLaMyLVXmAC5YVj29d8T-QbyJaxORbMCuWtxnw8VLZHjz9kyyMMTFaOfGb3CZmytVWfwXIYXevyBfsR4Ir5EQA";

    let sd_jwt = SdJwt::parse(sd_jwt_str).unwrap();
    assert_eq!(sd_jwt.disclosures.len(), 4);
    assert_eq!(sd_jwt.key_binding_jwt.unwrap(), "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE2OTgwNzc3OTAsICJfc2RfaGFzaCI6ICJ1MXpzTkxGUXhlVkVGcFRmT1Z1NFRjSTNaYjdDX1UzYTFFNGVzQVlRLXpZIn0.LLaMyLVXmAC5YVj29d8T-QbyJaxORbMCuWtxnw8VLZHjz9kyyMMTFaOfGb3CZmytVWfwXIYXevyBfsR4Ir5EQA");
  }
}
