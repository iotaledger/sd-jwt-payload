use crate::{Error, Result};
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
  pub fn to_string(self) -> String {
    let disclosures = self.disclosures.into_iter().join("~");
    let key_bindings: String = if let Some(key_bindings) = self.key_binding_jwt {
      key_bindings
    } else {
      "".to_owned()
    };
    format!("{}~{}~{}", self.jwt, disclosures, key_bindings)
  }

  /// Parses an SD-JWT into its components as [`SdJwt`].
  pub fn parse(sd_jwt: String) -> Result<Self> {
    let sd_segments: Vec<&str> = sd_jwt.split('~').collect();
    let num_of_segments = sd_segments.len();
    if num_of_segments < 2 {
      return Err(Error::DeserializationError(
        "SD-JWT format is invalid, less than 2 segments".to_string(),
      ));
    }

    let includes_key_binding = sd_jwt.chars().rev().next().map(|char| char != '~').unwrap_or(false);
    if includes_key_binding && num_of_segments < 3 {
      return Err(Error::DeserializationError(
        "SD-JWT format is invalid, less than 3 segments with key binding jwt".to_string(),
      ));
    }

    let jwt = sd_segments.get(0).unwrap().to_string();
    let disclosures: Vec<String> = sd_segments[1..num_of_segments - 1]
      .into_iter()
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
