// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Display;
use std::iter::Peekable;
use std::ops::Deref;
use std::str::FromStr;

use crate::jwt::Jwt;
use crate::Disclosure;
use crate::Error;
use crate::Hasher;
use crate::JsonObject;
use crate::KeyBindingJwt;
use crate::RequiredKeyBinding;
use crate::Result;
use crate::SdObjectDecoder;
use crate::ARRAY_DIGEST_KEY;
use crate::DIGESTS_KEY;
use crate::SHA_ALG_NAME;
use itertools::Itertools;
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
  disclosures: Vec<Disclosure>,
  /// The optional key binding JWT.
  key_binding_jwt: Option<KeyBindingJwt>,
}

impl SdJwt {
  /// Creates a new [`SdJwt`] from its components.
  pub(crate) fn new(
    jwt: Jwt<SdJwtClaims>,
    disclosures: Vec<Disclosure>,
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

  pub fn disclosures(&self) -> &[Disclosure] {
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
  pub fn conceal(&mut self, path: &str, hasher: &dyn Hasher) -> Result<Vec<Disclosure>> {
    // Check `hasher` matches the hasher used for creating this sd-jwt.
    let required_hasher = self.claims()._sd_alg.as_deref().unwrap_or(SHA_ALG_NAME);
    let provided_hasher_alg = hasher.alg_name();
    if required_hasher != provided_hasher_alg {
      return Err(Error::MissingHasher(format!(
        "the provided hasher uses algorithm \"{provided_hasher_alg}\", but algorithm \"{required_hasher}\" is required"
      )));
    }
    // create the map <disclosure's digest> -> <disclosure>.
    let mut disclosures = self
      .disclosures
      .drain(..)
      .map(|disclosure| (hasher.encoded_digest(disclosure.as_str()), disclosure))
      .collect();

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
    // always return `object` in its place before returning.
    let result = (|| {
      let path_segments = path.trim_start_matches('/').split('/').peekable();
      let digests_to_remove = conceal(&object, path_segments, &disclosures)?
        .into_iter()
        // needed as some strings are borrowed for the lifetime of the borrow of `self.disclosures`.
        .map(ToOwned::to_owned)
        .collect_vec();

      let removed_disclosures = digests_to_remove
        .into_iter()
        .flat_map(|digest| disclosures.remove(&digest))
        .collect();
      Ok(removed_disclosures)
    })();

    // Put everything back in its place.
    self.disclosures = disclosures.into_values().collect();

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
    let disclosures = self.disclosures.iter().map(ToString::to_string).join("~");
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
      .map(|s| Disclosure::parse(s))
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

  /// Returns the JSON object obtained by replacing all disclosures into their
  /// corresponding JWT concealable claims.
  pub fn into_disclosed_object(self, hasher: &dyn Hasher) -> Result<JsonObject> {
    let decoder = SdObjectDecoder;
    let object = serde_json::to_value(self.claims()).unwrap();

    let disclosure_map = self
      .disclosures
      .into_iter()
      .map(|disclosure| (hasher.encoded_digest(disclosure.as_str()), disclosure))
      .collect();

    decoder.decode(object.as_object().unwrap(), &disclosure_map)
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

fn conceal<'p, 'o, 'd, I>(
  object: &'o Value,
  mut path: Peekable<I>,
  disclosures: &'d HashMap<String, Disclosure>,
) -> Result<Vec<&'o str>>
where
  I: Iterator<Item = &'p str>,
  'd: 'o,
{
  let element_key = path
    .next()
    .ok_or_else(|| Error::InvalidPath("element at path doens't exist or is not disclosable".to_string()))?;
  let has_next = path.peek().is_some();
  match object {
    // We are just traversing to a deeper part of the object.
    Value::Object(object) if has_next => {
      let next_object = object
        .get(element_key)
        .or_else(|| {
          find_disclosure(object, element_key, disclosures)
            .and_then(|digest| disclosures.get(digest))
            .map(|disclosure| &disclosure.claim_value)
        })
        .ok_or_else(|| Error::InvalidPath("the referenced element doesn't exist or is not concealable".to_string()))?;

      conceal(next_object, path, disclosures)
    }
    // We reached the parent of the value we want to conceal.
    // Make sure its concealable by finding its disclosure.
    Value::Object(object) => {
      let digest = find_disclosure(object, element_key, disclosures)
        .ok_or_else(|| Error::InvalidPath("the referenced element doesn't exist or is not concealable".to_string()))?;
      let disclosure = disclosures.get(digest).unwrap();
      let mut sub_disclosures: Vec<&str> = get_all_sub_disclosures(&disclosure.claim_value, disclosures).collect();
      sub_disclosures.push(digest);
      Ok(sub_disclosures)
    }
    // Traversing an array
    Value::Array(arr) if has_next => {
      let index = element_key
        .parse::<usize>()
        .ok()
        .filter(|idx| arr.len() > *idx)
        .ok_or_else(|| Error::InvalidPath(String::default()))?;
      let next_object = arr
        .get(index)
        .ok_or_else(|| Error::InvalidPath("the referenced element doesn't exist or is not concealable".to_string()))?;

      conceal(next_object, path, disclosures)
    }
    // Concealing an array's entry.
    Value::Array(arr) => {
      let index = element_key
        .parse::<usize>()
        .ok()
        .filter(|idx| arr.len() > *idx)
        .ok_or_else(|| Error::InvalidPath(String::default()))?;
      let digest = arr
        .get(index)
        .unwrap()
        .as_object()
        .and_then(|entry| find_disclosure(entry, "", disclosures))
        .ok_or_else(|| Error::InvalidPath("the referenced element doesn't exist or is not concealable".to_string()))?;
      let disclosure = disclosures.get(digest).unwrap();
      let mut sub_disclosures: Vec<&str> = get_all_sub_disclosures(&disclosure.claim_value, disclosures).collect();
      sub_disclosures.push(digest);
      Ok(sub_disclosures)
    }
    _ => Err(Error::InvalidPath(String::default())),
  }
}

fn find_disclosure<'o>(
  object: &'o JsonObject,
  key: &str,
  disclosures: &HashMap<String, Disclosure>,
) -> Option<&'o str> {
  let maybe_disclosable_array_entry = || {
    object
      .get(ARRAY_DIGEST_KEY)
      .and_then(|value| value.as_str())
      .filter(|_| object.len() == 1)
  };
  // Try to find the digest for disclosable property `key` in
  // the `_sd` field of `object`.
  object
    .get(DIGESTS_KEY)
    .and_then(|value| value.as_array())
    .iter()
    .flat_map(|values| values.iter())
    .flat_map(|value| value.as_str())
    .find(|digest| {
      disclosures
        .get(*digest)
        .and_then(|disclosure| disclosure.claim_name.as_deref())
        .is_some_and(|name| name == key)
    })
    // If no result is found try checking `object` as a disclosable array entry.
    .or_else(maybe_disclosable_array_entry)
}

fn get_all_sub_disclosures<'v, 'd>(
  start: &'v Value,
  disclosures: &'d HashMap<String, Disclosure>,
) -> Box<dyn Iterator<Item = &'v str> + 'v>
where
  'd: 'v,
{
  match start {
    // `start` is a JSON object, check if it has a "_sd" array + recursively
    // check all its properties
    Value::Object(object) => {
      let direct_sds = object
        .get(DIGESTS_KEY)
        .and_then(|sd| sd.as_array())
        .map(|sd| sd.iter())
        .unwrap_or_default()
        .flat_map(|value| value.as_str())
        .filter(|digest| disclosures.contains_key(*digest));
      let sub_sds = object
        .values()
        .flat_map(|value| get_all_sub_disclosures(value, disclosures));
      Box::new(itertools::chain!(direct_sds, sub_sds))
    }
    // `start` is a JSON array, check for disclosable values `{"...", <digest>}` +
    // recursively check all its values.
    Value::Array(arr) => {
      let mut digests = vec![];
      for value in arr {
        if let Some(Value::String(digest)) = value.get(ARRAY_DIGEST_KEY) {
          if disclosures.contains_key(digest) {
            digests.push(digest.as_str());
          }
        } else {
          get_all_sub_disclosures(value, disclosures).for_each(|digest| digests.push(digest));
        }
      }
      Box::new(digests.into_iter())
    }
    _ => Box::new(std::iter::empty()),
  }
}

#[cfg(test)]
mod test {
  use crate::SdJwt;
  const SD_JWT: &str = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBbIkM5aW5wNllvUmFFWFI0Mjd6WUpQN1FyazFXSF84YmR3T0FfWVVyVW5HUVUiLCAiS3VldDF5QWEwSElRdlluT1ZkNTloY1ZpTzlVZzZKMmtTZnFZUkJlb3d2RSIsICJNTWxkT0ZGekIyZDB1bWxtcFRJYUdlcmhXZFVfUHBZZkx2S2hoX2ZfOWFZIiwgIlg2WkFZT0lJMnZQTjQwVjd4RXhad1Z3ejd5Um1MTmNWd3Q1REw4Ukx2NGciLCAiWTM0em1JbzBRTExPdGRNcFhHd2pCZ0x2cjE3eUVoaFlUMEZHb2ZSLWFJRSIsICJmeUdwMFdUd3dQdjJKRFFsbjFsU2lhZW9iWnNNV0ExMGJRNTk4OS05RFRzIiwgIm9tbUZBaWNWVDhMR0hDQjB1eXd4N2ZZdW8zTUhZS08xNWN6LVJaRVlNNVEiLCAiczBCS1lzTFd4UVFlVTh0VmxsdE03TUtzSVJUckVJYTFQa0ptcXhCQmY1VSJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAiYWRkcmVzcyI6IHsiX3NkIjogWyI2YVVoelloWjdTSjFrVm1hZ1FBTzN1MkVUTjJDQzFhSGhlWnBLbmFGMF9FIiwgIkF6TGxGb2JrSjJ4aWF1cFJFUHlvSnotOS1OU2xkQjZDZ2pyN2ZVeW9IemciLCAiUHp6Y1Z1MHFiTXVCR1NqdWxmZXd6a2VzRDl6dXRPRXhuNUVXTndrclEtayIsICJiMkRrdzBqY0lGOXJHZzhfUEY4WmN2bmNXN3p3Wmo1cnlCV3ZYZnJwemVrIiwgImNQWUpISVo4VnUtZjlDQ3lWdWIyVWZnRWs4anZ2WGV6d0sxcF9KbmVlWFEiLCAiZ2xUM2hyU1U3ZlNXZ3dGNVVEWm1Xd0JUdzMyZ25VbGRJaGk4aEdWQ2FWNCIsICJydkpkNmlxNlQ1ZWptc0JNb0d3dU5YaDlxQUFGQVRBY2k0MG9pZEVlVnNBIiwgInVOSG9XWWhYc1poVkpDTkUyRHF5LXpxdDd0NjlnSkt5NVFhRnY3R3JNWDQiXX0sICJfc2RfYWxnIjogInNoYS0yNTYifQ.gR6rSL7urX79CNEvTQnP1MH5xthG11ucIV44SqKFZ4Pvlu_u16RfvXQd4k4CAIBZNKn2aTI18TfvFwV97gJFoA~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInJlZ2lvbiIsICJcdTZlMmZcdTUzM2EiXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImNvdW50cnkiLCAiSlAiXQ~";

  #[test]
  fn parse() {
    let sd_jwt = SdJwt::parse(SD_JWT).unwrap();
    assert_eq!(sd_jwt.disclosures.len(), 2);
    assert!(sd_jwt.key_binding_jwt.is_none());
  }

  #[test]
  fn round_trip_ser_des() {
    let sd_jwt = SdJwt::parse(SD_JWT).unwrap();
    assert_eq!(&sd_jwt.to_string(), SD_JWT);
  }
}
