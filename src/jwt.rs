use std::{fmt::Display, str::FromStr};

use anyhow::Context;
use multibase::{encode, Base};
use serde::{de::DeserializeOwned, Serialize};

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
    let header = encode(Base::Base64Url, serde_json::to_vec(&self.header).unwrap());
    let payload = encode(Base::Base64Url, serde_json::to_vec(&self.claims).unwrap());
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
      .and_then(|json_bytes| serde_json::from_slice::<JsonObject>(&json_bytes).context("not a JSON object"))
      .map_err(|e| Error::DeserializationError(format!("invalid JWT: {e}")))?;
    let claims = segments
      .next()
      .context("missing payload")
      .and_then(|b64| Base::Base64Url.decode(b64).context("not Base64Url-encoded"))
      .and_then(|json_bytes| serde_json::from_slice::<T>(&json_bytes).context("not a JSON object"))
      .map_err(|e| Error::DeserializationError(format!("invalid JWT: {e}")))?;
    let signature = segments
      .next()
      .context("missing signature")
      .map(String::from)
      .map_err(|e| Error::DeserializationError(format!("invalid JWT: {e}")))?;

    Ok(Self {
      header,
      claims,
      signature,
    })
  }
}
