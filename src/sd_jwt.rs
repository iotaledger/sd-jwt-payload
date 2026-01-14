// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::fmt::Display;
use std::ops::Deref;
use std::ops::DerefMut;
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
use indexmap::IndexMap;
use itertools::Either;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
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

impl DerefMut for SdJwtClaims {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.properties
  }
}

/// Representation of an SD-JWT of the format
/// `<Issuer-signed JWT>~<D.1>~<D.2>~...~<D.N>~<optional KB-JWT>`.
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

  pub fn headers(&self) -> &JsonObject {
    &self.jwt.header
  }

  pub fn claims(&self) -> &SdJwtClaims {
    &self.jwt.claims
  }

  /// Returns a mutable reference to this SD-JWT's claims.
  /// ## Warning
  /// Modifying the claims might invalidate the signature.
  /// Use this method carefully.
  pub fn claims_mut(&mut self) -> &mut SdJwtClaims {
    &mut self.jwt.claims
  }

  /// Returns the disclosures of this SD-JWT.
  pub fn disclosures(&self) -> &[Disclosure] {
    &self.disclosures
  }

  /// Returns the required key binding of this SD-JWT, if any.
  pub fn required_key_bind(&self) -> Option<&RequiredKeyBinding> {
    self.claims().cnf.as_ref()
  }

  /// Returns the key binding JWT of this SD-JWT, if any.
  pub fn key_binding_jwt(&self) -> Option<&KeyBindingJwt> {
    self.key_binding_jwt.as_ref()
  }

  /// Attaches a [KeyBindingJwt] to this SD-JWT.
  /// ## Notes
  /// This method overwrites any existing [KeyBindingJwt] and does **not**
  /// perform any sort of validation of the passed KB-JWT.
  pub fn attach_key_binding_jwt(&mut self, kb_jwt: KeyBindingJwt) {
    self.key_binding_jwt = Some(kb_jwt);
  }

  /// Serializes the components into the final SD-JWT.
  pub fn presentation(&self) -> String {
    let disclosures = self.disclosures.iter().map(ToString::to_string).join("~");
    let key_bindings = self
      .key_binding_jwt
      .as_ref()
      .map(ToString::to_string)
      .unwrap_or_default();
    if disclosures.is_empty() {
      format!("{}~{}", self.jwt, key_bindings)
    } else {
      format!("{}~{}~{}", self.jwt, disclosures, key_bindings)
    }
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

    let jwt = sd_segments.first().unwrap().parse()?;

    let disclosures = sd_segments[1..num_of_segments - 1]
      .iter()
      .map(|s| Disclosure::parse(s))
      .try_collect()?;

    let key_binding_jwt = sd_segments
      .last()
      .filter(|segment| !segment.is_empty())
      .map(|segment| segment.parse())
      .transpose()?;

    Ok(Self {
      jwt,
      disclosures,
      key_binding_jwt,
    })
  }

  /// Prepares this [`SdJwt`] for a presentation, returning an [`SdJwtPresentationBuilder`].
  /// ## Errors
  /// - [`Error::InvalidHasher`] is returned if the provided `hasher`'s algorithm doesn't match the algorithm specified
  ///   by SD-JWT's `_sd_alg` claim. "sha-256" is used if the claim is missing.
  pub fn into_presentation(self, hasher: &dyn Hasher) -> Result<SdJwtPresentationBuilder> {
    SdJwtPresentationBuilder::new(self, hasher)
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

#[derive(Debug, Clone)]
pub struct SdJwtPresentationBuilder {
  sd_jwt: SdJwt,
  disclosures: IndexMap<String, Disclosure>,
  disclosures_to_omit: HashSet<usize>,
  object: Value,
}

impl Deref for SdJwtPresentationBuilder {
  type Target = SdJwt;
  fn deref(&self) -> &Self::Target {
    &self.sd_jwt
  }
}

impl SdJwtPresentationBuilder {
  pub fn new(mut sd_jwt: SdJwt, hasher: &dyn Hasher) -> Result<Self> {
    let required_hasher = sd_jwt.claims()._sd_alg.as_deref().unwrap_or(SHA_ALG_NAME);
    if required_hasher != hasher.alg_name() {
      return Err(Error::InvalidHasher(format!(
        "hasher \"{}\" was provided, but \"{required_hasher} is required\"",
        hasher.alg_name()
      )));
    }
    let disclosures = std::mem::take(&mut sd_jwt.disclosures)
      .into_iter()
      .map(|disclosure| (hasher.encoded_digest(disclosure.as_str()), disclosure))
      .collect();
    let object = {
      let sd = std::mem::take(&mut sd_jwt.jwt.claims._sd)
        .into_iter()
        .map(Value::String)
        .collect();
      let mut object = Value::Object(std::mem::take(&mut sd_jwt.jwt.claims.properties));
      object
        .as_object_mut()
        .unwrap()
        .insert(DIGESTS_KEY.to_string(), Value::Array(sd));

      object
    };
    Ok(Self {
      sd_jwt,
      disclosures,
      disclosures_to_omit: HashSet::default(),
      object,
    })
  }

  /// Removes the disclosure for the property at `path`, concealing it.
  ///
  /// ## Notes
  /// - When concealing a claim more than one disclosure may be removed: the disclosure for the claim itself and the
  ///   disclosures for any concealable sub-claim.
  pub fn conceal(mut self, path: &str) -> Result<Self> {
    self
      .disclosures_to_omit
      .extend(find_disclosure_and_sub_disclosures_for_value_at_path(
        &self.object,
        path,
        &self.disclosures,
      )?);
    Ok(self)
  }

  /// Removes all disclosures from this SD-JWT, resulting in a token that,
  /// when presented, will have *all* selectively-disclosable properties
  /// omitted.
  pub fn conceal_all(mut self) -> Self {
    self.disclosures_to_omit.extend(0..self.disclosures.len());
    self
  }

  /// Discloses a value that was previously concealed.
  /// # Notes
  /// - This method may disclose multiple values, if the given path references a disclosable value stored within another
  ///   disclosable value. That is, [disclose](Self::disclose) will unconceal the selectively disclosable value at
  ///   `path` together with *all* its parents that are disclosable values themselves.
  /// - By default *all* disclosable claims are disclosed, therefore this method can only be used to *undo* any
  ///   concealment operations previously performed by either [Self::conceal] or [Self::conceal_all].
  pub fn disclose(mut self, path: &str) -> Result<Self> {
    let disclosing = find_disclosure_and_parent_disclosures_for_value_at_path(&self.object, path, &self.disclosures)?;
    for idx in disclosing {
      self.disclosures_to_omit.remove(&idx);
    }
    Ok(self)
  }

  /// Returns the resulting [`SdJwt`] together with all removed disclosures.
  pub fn finish(self) -> (SdJwt, Vec<Disclosure>) {
    // Put everything back in its place.
    let SdJwtPresentationBuilder {
      mut sd_jwt,
      disclosures,
      disclosures_to_omit,
      object,
      ..
    } = self;

    let (disclosures_to_keep, omitted_disclosures) =
      disclosures
        .into_values()
        .enumerate()
        .partition_map(|(idx, disclosure)| {
          if disclosures_to_omit.contains(&idx) {
            Either::Right(disclosure)
          } else {
            Either::Left(disclosure)
          }
        });

    let Value::Object(mut obj) = object else {
      unreachable!();
    };
    let Value::Array(sd) = obj.remove(DIGESTS_KEY).unwrap_or(Value::Array(vec![])) else {
      unreachable!()
    };
    sd_jwt.jwt.claims._sd = sd
      .into_iter()
      .map(|value| {
        if let Value::String(s) = value {
          s
        } else {
          unreachable!()
        }
      })
      .collect();
    sd_jwt.jwt.claims.properties = obj;
    sd_jwt.disclosures = disclosures_to_keep;

    (sd_jwt, omitted_disclosures)
  }
}

fn find_disclosure_and_sub_disclosures_for_value_at_path<'a>(
  value: &'a Value,
  path: &str,
  disclosures: &'a IndexMap<String, Disclosure>,
) -> Result<Vec<usize>> {
  let path_segments = path.trim_start_matches('/').split('/').collect_vec();
  let (value, mut visited_disclosures) = traverse_disclosable_object(value, &path_segments, disclosures)
    .ok_or_else(|| Error::InvalidPath("the referenced element doesn't exist or is not concealable".to_owned()))?;
  let path_referenced_disclosure = visited_disclosures
    .pop()
    .ok_or_else(|| Error::InvalidPath("the referenced element doesn't exist or is not concealable".to_owned()))?;

  let mut disclosures_to_omit = get_all_sub_disclosures(value, disclosures);
  disclosures_to_omit.push(path_referenced_disclosure);

  Ok(disclosures_to_omit)
}

fn find_disclosure_and_parent_disclosures_for_value_at_path<'a>(
  value: &'a Value,
  path: &str,
  disclosures: &'a IndexMap<String, Disclosure>,
) -> Result<Vec<usize>> {
  let path_segments = path.trim_start_matches('/').split('/').collect_vec();
  traverse_disclosable_object(value, &path_segments, disclosures)
    .map(|(_, disclosures)| disclosures)
    .ok_or_else(|| Error::InvalidPath("the referenced element doesn't exist or is not concealable".to_owned()))
}

fn find_disclosure(object: &JsonObject, key: &str, disclosures: &IndexMap<String, Disclosure>) -> Option<usize> {
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
    .and_then(|digest| disclosures.get_index_of(digest))
}

fn traverse_disclosable_object<'a>(
  mut value: &'a Value,
  path: &[&str],
  disclosures: &'a IndexMap<String, Disclosure>,
) -> Option<(&'a Value, Vec<usize>)> {
  let mut visited_disclosures = vec![];
  for path_segment in path {
    let step = traverse_disclosable_object_step(value, path_segment, disclosures)?;
    value = step.value;
    if let Some(disclosure) = step.disclosure {
      visited_disclosures.push(disclosure)
    }
  }

  Some((value, visited_disclosures))
}

fn traverse_disclosable_object_step<'a>(
  value: &'a Value,
  path_fragment: &str,
  disclosures: &'a IndexMap<String, Disclosure>,
) -> Option<TraversalResult<'a>> {
  match value {
    // Object has an entry for the element we are searching.
    Value::Object(object) if object.contains_key(path_fragment) => {
      Some(TraversalResult::new_value(object.get(path_fragment).unwrap()))
    }
    // No entry for path fragment, searching object's disclosures.
    Value::Object(object) => {
      let idx = find_disclosure(object, path_fragment, disclosures)?;
      let (_, disclosure) = disclosures.get_index(idx).unwrap();
      Some(TraversalResult::new_from_disclosure(idx, disclosure))
    }
    Value::Array(array) => {
      let arr_idx = path_fragment.parse::<usize>().ok()?;
      let value = array.get(arr_idx)?;

      // Check if the value is a disclosable value.
      if let Some(digest) = value.get(ARRAY_DIGEST_KEY).and_then(|value| value.as_str()) {
        disclosures
          .get_full(digest)
          .map(|(idx, _, disclosure)| TraversalResult::new_from_disclosure(idx, disclosure))
      } else {
        Some(TraversalResult::new_value(value))
      }
    }
    _ => None,
  }
}

/// The result of a step in the traversal of a disclosable value.
#[derive(Debug)]
struct TraversalResult<'a> {
  /// The reached value.
  value: &'a Value,
  /// The index of the disclosure we had to walk through to reach `value`.
  disclosure: Option<usize>,
}

impl<'a> TraversalResult<'a> {
  fn new_value(value: &'a Value) -> Self {
    Self {
      value,
      disclosure: None,
    }
  }

  fn new_from_disclosure(idx: usize, disclosure: &'a Disclosure) -> Self {
    Self {
      value: &disclosure.claim_value,
      disclosure: Some(idx),
    }
  }
}

fn get_all_sub_disclosures<'a>(value: &'a Value, disclosures: &'a IndexMap<String, Disclosure>) -> Vec<usize> {
  let mut sub_disclosures = vec![];
  match value {
    Value::Object(object) => {
      // Check object's "_sd" entry.
      object
        .get(DIGESTS_KEY)
        .and_then(|sd| sd.as_array())
        .map(|sd| sd.iter())
        .unwrap_or_default()
        .flat_map(|value| value.as_str())
        .filter_map(|digest| disclosures.get_index_of(digest))
        .for_each(|idx| sub_disclosures.push(idx));
      // Recursively check all object's property.
      object.values().for_each(|value| {
        let found_sub_disclosures = get_all_sub_disclosures(value, disclosures);
        sub_disclosures.extend(found_sub_disclosures);
      });
    }
    Value::Array(arr) => {
      for value in arr.iter().filter(|value| value.is_object()) {
        if let Some(idx) = value
          .get(ARRAY_DIGEST_KEY)
          .and_then(|value| value.as_str())
          .and_then(|digest| disclosures.get_index_of(digest))
        {
          sub_disclosures.push(idx);
        } else {
          sub_disclosures.extend(get_all_sub_disclosures(value, disclosures));
        }
      }
    }
    _ => (),
  }

  sub_disclosures
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
