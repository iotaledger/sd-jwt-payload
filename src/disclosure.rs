// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::Error;
use serde_json::Value;
use std::fmt::Display;

/// A disclosable value.
/// Both object properties and array elements disclosures are supported.
///
/// See: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#name-disclosures
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
  /// The salt value.
  pub salt: String,
  /// The claim name, optional for array elements.
  pub claim_name: Option<String>,
  /// The claim Value which can be of any type.
  pub claim_value: Value,
}

impl Disclosure {
  /// Creates a new instance of [`Disclosure`].
  ///
  /// Use `.to_string()` to get the actual disclosure.
  pub fn new(salt: String, claim_name: Option<String>, claim_value: Value) -> Self {
    Self {
      salt,
      claim_name,
      claim_value,
    }
  }

  /// Parses a Base64 encoded disclosure into a [`Disclosure`].
  ///
  /// ## Error
  ///
  /// Returns an [`Error::InvalidDisclosure`] if input is not a valid disclosure.
  pub fn parse(disclosure: &str) -> Result<Self, Error> {
    let decoded: Vec<Value> = multibase::Base::Base64Url
      .decode(&disclosure)
      .map_err(|_e| {
        Error::InvalidDisclosure(format!(
          "Base64 decoding of the disclosure was not possible {}",
          disclosure
        ))
      })
      .and_then(|data| {
        serde_json::from_slice(&data).map_err(|_e| {
          Error::InvalidDisclosure(format!(
            "decoded disclosure could not be serialized as an array {}",
            disclosure
          ))
        })
      })?;

    if decoded.len() == 2 {
      Ok(Self {
        salt: decoded
          .first()
          .ok_or(Error::InvalidDisclosure("invalid salt".to_string()))?
          .as_str()
          .ok_or(Error::InvalidDisclosure(
            "salt could not be parsed as a string".to_string(),
          ))?
          .to_owned(),
        claim_name: None,
        claim_value: decoded
          .get(1)
          .ok_or(Error::InvalidDisclosure("invalid claim name".to_string()))?
          .clone(),
      })
    } else if decoded.len() == 3 {
      Ok(Self {
        salt: decoded
          .first()
          .ok_or(Error::InvalidDisclosure("invalid salt".to_string()))?
          .as_str()
          .ok_or(Error::InvalidDisclosure(
            "salt could not be parsed as a string".to_string(),
          ))?
          .to_owned(),
        claim_name: Some(
          decoded
            .get(1)
            .ok_or(Error::InvalidDisclosure("invalid claim name".to_string()))?
            .as_str()
            .ok_or(Error::InvalidDisclosure(
              "claim name could not be parsed as a string".to_string(),
            ))?
            .to_owned(),
        ),
        claim_value: decoded
          .get(2)
          .ok_or(Error::InvalidDisclosure("invalid claim name".to_string()))?
          .clone(),
      })
    } else {
      Err(Error::InvalidDisclosure(format!(
        "deserialized array has an invalid length of {}",
        decoded.len()
      )))
    }
  }
}

impl Display for Disclosure {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let input = if let Some(name) = self.claim_name.as_deref() {
      format!("[\"{}\", \"{}\", {}]", self.salt, &name, self.claim_value.to_string())
    } else {
      format!("[\"{}\", {}]", self.salt, self.claim_value.to_string())
    };

    let encoded = multibase::Base::Base64Url.encode(input);
    f.write_str(&encoded)
  }
}

#[cfg(test)]
mod test {
  use super::Disclosure;

  // Test values from:
  // https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#appendix-A.2-7
  #[test]
  fn test_parsing() {
    let disclosure = Disclosure::new(
      "2GLC42sKQveCfGfryNRN9w".to_string(),
      Some("time".to_owned()),
      "2012-04-23T18:25Z".to_owned().into(),
    );

    let parsed =
      Disclosure::parse("WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInRpbWUiLCAiMjAxMi0wNC0yM1QxODoyNVoiXQ");
    assert_eq!(parsed.unwrap(), disclosure);
  }

  // Test values from:
  // https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-5.5-25
  #[test]
  fn test_creating() {
    let disclosure = Disclosure::new("lklxF5jMYlGTPUovMNIvCA".to_owned(), None, "US".to_owned().into());
    assert_eq!(
      "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0".to_owned(),
      disclosure.to_string()
    );
  }
}
