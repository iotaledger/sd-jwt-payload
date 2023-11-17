use std::fmt::Display;

use crate::Error;
use serde_json::Value;

/// Represents an elements constructing a disclosure.
/// Object properties and array elements disclosures are supported.
///
/// See: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-06.html#name-disclosures
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
  /// The salt value.
  pub salt: String,
  /// The claim name, optional for array elements.
  pub claim_name: Option<String>,
  /// The claim Value which can be of any type.
  pub claim_value: Value,
  /// The base64url-encoded string.
  pub disclosure: String,
}

impl Disclosure {
  /// Creates a new instance of [`Disclosure`].
  ///
  /// Use `.to_string()` to get the actual disclosure.
  pub fn new(salt: String, claim_name: Option<String>, claim_value: Value) -> Self {
    let input = if let Some(name) = &claim_name {
      format!("[\"{}\", \"{}\", {}]", &salt, &name, &claim_value.to_string())
    } else {
      format!("[\"{}\", {}]", &salt, &claim_value.to_string())
    };

    let encoded = multibase::Base::Base64.encode(input);
    Self {
      salt,
      claim_name,
      claim_value,
      disclosure: encoded,
    }
  }

  /// Parses a Base64 encoded disclosure into a [`Disclosure`].
  ///
  /// ## Error
  ///
  /// Returns an [`Error::InvalidDisclosure`] if input is not a valid disclosure.
  pub fn parse(disclosure: String) -> Result<Self, Error> {
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
          .get(0)
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

        disclosure,
      })
    } else if decoded.len() == 3 {
      Ok(Self {
        salt: decoded
          .get(0)
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
        disclosure,
      })
    } else {
      Err(Error::InvalidDisclosure(format!(
        "deserialized array has an invalid length of {}",
        decoded.len()
      )))
    }
  }

  /// Reference the actual disclosure.
  pub fn as_str(&self) -> &str {
    &self.disclosure
  }

  /// Convert this object into the actual disclosure.
  pub fn into_string(self) -> String {
    self.disclosure
  }
}

impl Display for Disclosure {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.disclosure)
  }
}

#[cfg(test)]
mod test {
  use super::Disclosure;

  // Test values from:
  // https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#appendix-A.2-7
  #[test]
  fn test_parsing() {
    let disclosure = Disclosure::new(
      "2GLC42sKQveCfGfryNRN9w".to_string(),
      Some("time".to_owned()),
      "2012-04-23T18:25Z".to_owned().into(),
    );

    let parsed =
      Disclosure::parse("WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInRpbWUiLCAiMjAxMi0wNC0yM1QxODoyNVoiXQ".to_owned());
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
