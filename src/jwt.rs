use std::fmt::Display;
use std::str::FromStr;

use anyhow::Context;
use multibase::Base;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::Error;
use crate::JsonObject;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwt<T> {
  pub header: JsonObject,
  pub claims: T,
  pub signature: String,
}

impl<T> Display for Jwt<T>
where
  T: Serialize,
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let header = Base::Base64Url.encode(serde_json::to_vec(&self.header).unwrap());
    let payload = Base::Base64Url.encode(serde_json::to_vec(&self.claims).unwrap());
    write!(f, "{header}.{payload}.{}", &self.signature)
  }
}

impl<T> FromStr for Jwt<T>
where
  T: DeserializeOwned,
{
  type Err = Error;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let mut segments = s.split('.');
    let header = segments
      .next()
      .context("missing header segment")
      .and_then(|b64| Base::Base64Url.decode(b64).context("not Base64Url-encoded"))
      .and_then(|json_bytes| serde_json::from_slice::<JsonObject>(&json_bytes).context("invalid JWT header properties"))
      .map_err(|e| Error::DeserializationError(format!("invalid JWT: {e}")))?;
    let claims = segments
      .next()
      .context("missing payload")
      .and_then(|b64| Base::Base64Url.decode(b64).context("not Base64Url-encoded"))
      .and_then(|json_bytes| {
        serde_json::from_slice::<T>(&json_bytes).map_err(|e| anyhow::anyhow!("invalid JWT claims: {e}"))
      })
      .map_err(|e| Error::DeserializationError(format!("invalid JWT: {e}")))?;
    let signature = segments
      .next()
      .context("missing signature")
      .map(String::from)
      .map_err(|e| Error::DeserializationError(format!("invalid JWT: {e}")))?;
    if segments.next().is_some() {
      return Err(Error::DeserializationError(
        "invalid JWT: more than 3 segments".to_string(),
      ));
    }

    Ok(Self {
      header,
      claims,
      signature,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::Jwt;
  use serde::Deserialize;
  use serde::Serialize;

  const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

  #[derive(Debug, Serialize, Deserialize)]
  struct TestClaims {
    sub: String,
    name: String,
    iat: i64,
  }

  #[test]
  fn round_trip() {
    let jwt = JWT.parse::<Jwt<TestClaims>>().unwrap();
    assert_eq!(&jwt.to_string(), JWT);
  }
}
