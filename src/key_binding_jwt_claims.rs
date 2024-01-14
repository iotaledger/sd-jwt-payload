// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::Hasher;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// Claims set for key binding JWT.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct KeyBindingJwtClaims {
  pub iat: i64,
  pub aud: String,
  pub nonce: String,
  pub sd_hash: String,
  #[serde(flatten)]
  pub properties: BTreeMap<String, Value>,
}

impl KeyBindingJwtClaims {
  pub const KB_JWT_HEADER_TYP: &'static str = " kb+jwt";

  /// Creates a new [`KeyBindingJwtClaims`].
  pub fn new(hasher: &dyn Hasher, jwt: String, disclosures: Vec<String>, nonce: String, aud: String, iat: i64) -> Self {
    let disclosures = disclosures.iter().join("~");
    let sd_jwt = format!("{}~{}~", jwt, disclosures);
    let hash = hasher.encoded_digest(&sd_jwt);
    Self {
      iat,
      aud,
      nonce,
      sd_hash: hash,
      properties: BTreeMap::new(),
    }
  }
}
