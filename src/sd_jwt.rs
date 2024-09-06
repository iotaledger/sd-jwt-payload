// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Display;
use std::ops::Deref;
use std::str::FromStr;

use crate::jwt::Jwt;
use crate::Disclosure;
use crate::Error;
use crate::JsonObject;
use crate::KeyBindingJwt;
use crate::RequiredKeyBinding;
use crate::Result;
use crate::SdObjectDecoder;
use crate::ARRAY_DIGEST_KEY;
use crate::DIGESTS_KEY;
use itertools::Itertools;
use json_pointer::JsonPointer;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SdJwtClaims {
  #[serde(skip_serializing_if = "Vec::is_empty", default)]
  pub _sd: Vec<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub _sd_alg: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub cnf: Option<RequiredKeyBinding>,
  #[serde(flatten)]
  properties: JsonObject,
}

impl Deref for SdJwtClaims {
  type Target = JsonObject;
  fn deref(&self) -> &Self::Target {
    &self.properties
  }
}

/// Representation of an SD-JWT of the format
/// `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~<optional KB-JWT>`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SdJwt {
  /// The JWT part.
  jwt: Jwt<SdJwtClaims>,
  /// The disclosures part.
  disclosures: HashMap<String, Disclosure>,
  /// The optional key binding JWT.
  key_binding_jwt: Option<KeyBindingJwt>,
}

impl SdJwt {
  /// Creates a new [`SdJwt`] from its components.
  pub(crate) fn new(
    jwt: Jwt<SdJwtClaims>,
    disclosures: HashMap<String, Disclosure>,
    key_binding_jwt: Option<KeyBindingJwt>,
  ) -> Self {
    Self {
      jwt,
      disclosures,
      key_binding_jwt,
    }
  }

  pub fn header(&self) -> &JsonObject {
    &self.jwt.header
  }

  pub fn claims(&self) -> &SdJwtClaims {
    &self.jwt.claims
  }

  pub fn disclosures(&self) -> &HashMap<String, Disclosure> {
    &self.disclosures
  }

  pub fn required_key_bind(&self) -> Option<&RequiredKeyBinding> {
    self.claims().cnf.as_ref()
  }

  pub fn key_binding_jwt(&self) -> Option<&KeyBindingJwt> {
    self.key_binding_jwt.as_ref()
  }

  /// Removes the disclosure for the property at `path`, conceiling it.
  /// Might return `None` if the disclosure of the element at given `path` has already been removed.
  pub fn conceal(&mut self, path: &str) -> Result<Option<Disclosure>> {
    let object = {
      let sd = std::mem::take(&mut self.jwt.claims._sd)
        .into_iter()
        .map(Value::String)
        .collect();
      let mut object = Value::Object(std::mem::take(&mut self.jwt.claims.properties));
      object
        .as_object_mut()
        .unwrap()
        .insert(DIGESTS_KEY.to_string(), Value::Array(sd));

      object
    };
    let mut element_pointer = path
      .parse::<JsonPointer<_, _>>()
      .map_err(|e| Error::InvalidPath(format!("{e:?}")))?;
    // always return `object` in its place before returning.
    let result = (|| {
      if let Ok(Value::Object(element)) = element_pointer.get(&object) {
        // The given path points to an element that exists. There are two possible cases:
        //   * disclosable array entry
        //   * undisclosable entry
        // Let's make sure it's the former, or return an error.
        let Some(Value::String(disclosure_digest)) = element.get(ARRAY_DIGEST_KEY) else {
          return Err(Error::DataTypeMismatch("non-concealable data".to_string()));
        };
        // Remove and return the disclosure.
        Ok(self.disclosures.remove(disclosure_digest))
      } else {
        // the element at `path` doesn't exists, check if it's a concealable element
        // by checking if it exists among its parent's `_sd` values.
        let element_key = element_pointer
          .pop()
          .ok_or_else(|| Error::InvalidPath("root path cannot be conceiled".to_string()))?;
        element_pointer.push(DIGESTS_KEY.to_string());
        let Ok(Value::Array(sd)) = element_pointer.get(&object) else {
          return Err(Error::InvalidPath(
            "the given path doesn't point to a disclosable element".to_string(),
          ));
        };
        for digest in sd {
          let digest = digest
            .as_str()
            .ok_or_else(|| Error::InvalidDisclosure(format!("{digest} is not a valid disclosure digest")))?;
          if self
            .disclosures
            .get(digest)
            .is_some_and(|disclosure| disclosure.claim_name.as_ref() == Some(&element_key))
          {
            return Ok(self.disclosures.remove(digest));
          }
        }

        return Err(Error::InvalidPath(
          "no disclosable element at specified path".to_string(),
        ));
      }
    })();

    let Value::Object(mut obj) = object else {
      unreachable!();
    };
    let Value::Array(sd) = obj.remove(DIGESTS_KEY).unwrap() else {
      unreachable!()
    };
    self.jwt.claims._sd = sd
      .into_iter()
      .map(|value| {
        if let Value::String(s) = value {
          s
        } else {
          unreachable!()
        }
      })
      .collect();
    self.jwt.claims.properties = obj;

    result
  }

  pub fn attach_key_binding_jwt(&mut self, kb_jwt: KeyBindingJwt) {
    self.key_binding_jwt = Some(kb_jwt);
  }

  /// Serializes the components into the final SD-JWT.
  ///
  /// ## Error
  /// Returns [`Error::DeserializationError`] if parsing fails.
  pub fn presentation(&self) -> String {
    let disclosures = self.disclosures.keys().join("~");
    let key_bindings = self
      .key_binding_jwt
      .as_ref()
      .map(ToString::to_string)
      .unwrap_or_default();
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

    let includes_key_binding = sd_jwt.chars().next_back().is_some_and(|char| char != '~');
    if includes_key_binding && num_of_segments < 3 {
      return Err(Error::DeserializationError(
        "SD-JWT format is invalid, less than 3 segments with key binding jwt".to_string(),
      ));
    }

    let jwt = sd_segments.first().unwrap().parse()?;
    let disclosures = sd_segments[1..num_of_segments - 1]
      .iter()
      .map(|s| Disclosure::parse(s).map(|d| (s.to_string(), d)))
      .try_collect()?;

    let key_binding_jwt = includes_key_binding
      .then(|| sd_segments[num_of_segments - 1].parse())
      .transpose()?;

    Ok(Self {
      jwt,
      disclosures,
      key_binding_jwt,
    })
  }

  /// Returns the JWT payload with all un-conceiled values visible.
  pub fn decode(&self) -> Result<JsonObject> {
    let decoder = SdObjectDecoder;
    let object = serde_json::to_value(self.claims()).unwrap();

    decoder.decode(object.as_object().unwrap(), self.disclosures())
  }
}

impl Display for SdJwt {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&(self.presentation()))
  }
}

impl FromStr for SdJwt {
  type Err = Error;
  fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
    Self::parse(s)
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
    assert_eq!(sd_jwt.key_binding_jwt.unwrap().to_string().as_str(), "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE2OTgwNzc3OTAsICJfc2RfaGFzaCI6ICJ1MXpzTkxGUXhlVkVGcFRmT1Z1NFRjSTNaYjdDX1UzYTFFNGVzQVlRLXpZIn0.LLaMyLVXmAC5YVj29d8T-QbyJaxORbMCuWtxnw8VLZHjz9kyyMMTFaOfGb3CZmytVWfwXIYXevyBfsR4Ir5EQA");
  }
}
