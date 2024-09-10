// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::jwt::Jwt;
use crate::Error;
use crate::Hasher;
use crate::JsonObject;
use crate::JwsSigner;
use crate::SdJwt;
use crate::SHA_ALG_NAME;
use multibase::Base;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::fmt::Display;
use std::ops::Deref;
use std::str::FromStr;

pub const KB_JWT_HEADER_TYP: &str = "kb+jwt";

/// Representation of a [KB-JWT](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-12.html#name-key-binding-jwt).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBindingJwt(Jwt<KeyBindingJwtClaims>);

impl Display for KeyBindingJwt {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", &self.0)
  }
}

impl FromStr for KeyBindingJwt {
  type Err = Error;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let jwt = Jwt::<KeyBindingJwtClaims>::from_str(s)?;
    let valid_jwt_type = jwt.header.get("typ").is_some_and(|typ| typ == KB_JWT_HEADER_TYP);
    if !valid_jwt_type {
      return Err(Error::DeserializationError(format!(
        "invalid KB-JWT: typ must be \"{KB_JWT_HEADER_TYP}\""
      )));
    }
    let valid_alg = jwt.header.get("alg").is_some_and(|alg| alg != "none");
    if !valid_alg {
      return Err(Error::DeserializationError(
        "invalid KB-JWT: alg must be set and cannot be \"none\"".to_string(),
      ));
    }

    Ok(Self(jwt))
  }
}

impl KeyBindingJwt {
  pub fn builder() -> KeyBindingJwtBuilder {
    KeyBindingJwtBuilder::default()
  }
  pub fn claims(&self) -> &KeyBindingJwtClaims {
    &self.0.claims
  }
}

#[derive(Debug, Default, Clone)]
pub struct KeyBindingJwtBuilder(JsonObject);

impl KeyBindingJwtBuilder {
  pub fn new() -> Self {
    Self::default()
  }
  pub fn from_object(object: JsonObject) -> Self {
    Self(object)
  }
  pub fn iat(mut self, iat: i64) -> Self {
    self.0.insert("iat".to_string(), iat.into());
    self
  }
  pub fn aud(mut self, aud: impl ToOwned<Owned = String>) -> Self {
    self.0.insert("aud".to_string(), aud.to_owned().into());
    self
  }
  pub fn nonce(mut self, nonce: impl ToOwned<Owned = String>) -> Self {
    self.0.insert("nonce".to_string(), nonce.to_owned().into());
    self
  }
  pub async fn finish<S>(
    self,
    sd_jwt: &SdJwt,
    hasher: &dyn Hasher,
    alg: &str,
    signer: &S,
  ) -> Result<KeyBindingJwt, Error>
  where
    S: JwsSigner,
  {
    let mut claims = self.0;
    if alg == "none" {
      return Err(Error::DataTypeMismatch(
        "A KeyBindingJwt cannot use algorithm \"none\"".to_string(),
      ));
    }
    if sd_jwt.key_binding_jwt().is_some() {
      return Err(Error::DataTypeMismatch(
        "the provided SD-JWT already has a KB-JWT attached".to_string(),
      ));
    }
    if sd_jwt.claims()._sd_alg.as_deref().unwrap_or(SHA_ALG_NAME) != hasher.alg_name() {
      return Err(Error::MissingHasher(format!(
        "invalid hashing algorithm \"{}\"",
        hasher.alg_name()
      )));
    }
    let sd_hash = hasher.encoded_digest(&sd_jwt.to_string());
    claims.insert("sd_hash".to_string(), sd_hash.into());

    let Value::Object(header) = serde_json::json!({
      "alg": alg,
      "typ": KB_JWT_HEADER_TYP,
    }) else {
      unreachable!();
    };

    // Validate claims
    let parsed_claims = serde_json::from_value::<KeyBindingJwtClaims>(claims.clone().into())
      .map_err(|e| Error::DeserializationError(format!("invalid KB-JWT claims: {e}")))?;
    let signature = signer
      .sign(&header, &claims)
      .await
      .map_err(|e| Error::JwsSignerFailure(e.to_string()))
      .map(|raw_sig| Base::Base64Url.encode(raw_sig))?;

    Ok(KeyBindingJwt(Jwt {
      header,
      claims: parsed_claims,
      signature,
    }))
  }
}

/// Claims set for key binding JWT.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct KeyBindingJwtClaims {
  pub iat: i64,
  pub aud: String,
  pub nonce: String,
  pub sd_hash: String,
  #[serde(flatten)]
  properties: JsonObject,
}

impl Deref for KeyBindingJwtClaims {
  type Target = JsonObject;
  fn deref(&self) -> &Self::Target {
    &self.properties
  }
}

/// Proof of possession of a given key. See [RFC7800](https://www.rfc-editor.org/rfc/rfc7800.html#section-3) for more details.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum RequiredKeyBinding {
  /// Json Web Key (JWK).
  Jwk(JsonObject),
  /// Encoded JWK in its compact serialization form.
  Jwe(String),
  /// Key ID.
  Kid(String),
  /// JWK from a JWK set identified by `kid`.
  Jwu {
    /// URL of the JWK Set.
    jwu: String,
    /// kid of the referenced JWK.
    kid: String,
  },
  /// Non standard key-bind.
  #[serde(untagged)]
  Custom(Value),
}
