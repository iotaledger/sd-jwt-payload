use std::collections::BTreeMap;
use std::time::SystemTime;

use itertools::Itertools;
use serde_json::Value;

use crate::utils::Utils;
use crate::Hasher;
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
  /// Creates a new [`KeyBindingJwtClaims`].
  /// When `issued_at` is left as None, it will automatically default to the current time
  ///
  /// # Panic
  /// When `issued_at` is set to `None` and the system returns time earlier than `SystemTime::UNIX_EPOCH`.
  pub fn new(
    hasher: &dyn Hasher,
    jwt: String,
    disclosures: Vec<String>,
    nonce: String,
    aud: String,
    issued_at: Option<i64>,
  ) -> Self {
    let disclosures = disclosures.iter().join("~");
    let sd_jwt = format!("{}~{}~", jwt, disclosures);
    let hash = Utils::digest_b64_url_only_ascii(hasher, &sd_jwt);
    let iat = issued_at.unwrap_or(
      SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time error")
        .as_secs() as i64,
    );
    Self {
      iat,
      aud,
      nonce,
      sd_hash: hash,
      properties: BTreeMap::new(),
    }
  }
}
