use std::collections::BTreeMap;

use itertools::Itertools;
use serde_json::Value;

use crate::{utils::Utils, Hasher, SdJwt};
use serde::Deserialize;
use serde::Serialize;

///
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct KeyBindingJwtClaims {
  pub iat: i64,
  pub aud: String,
  pub nonce: String,
  #[serde(rename = "_sd_hash")]
  pub sd_hash: String,
  #[serde(flatten)]
  pub properties: BTreeMap<String, Value>,
}

impl KeyBindingJwtClaims {
  pub fn new(sd_jwt: SdJwt, iat: i64, aud: String, nonce: String, hasher: &dyn Hasher) -> Self {
    let disclosures = sd_jwt.disclosures.iter().join("~");
    let sd_jwt = format!("{}~{}~", sd_jwt.jwt, disclosures);
    let hash = Utils::digest_b64_url_only_ascii(hasher, &sd_jwt);
    Self {
      iat,
      aud,
      nonce,
      sd_hash: hash,
      properties: BTreeMap::new(),
    }
  }
}
