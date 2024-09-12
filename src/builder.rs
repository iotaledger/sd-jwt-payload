use anyhow::Context as _;
use serde::Serialize;
use serde_json::Value;

use crate::jwt::Jwt;
use crate::Disclosure;
use crate::Error;
use crate::Hasher;
use crate::JwsSigner;
use crate::RequiredKeyBinding;
use crate::Result;
use crate::SdJwt;
use crate::SdJwtClaims;
use crate::SdObjectEncoder;
use crate::Sha256Hasher;
use crate::DEFAULT_SALT_SIZE;
use crate::HEADER_TYP;

/// Builder structure to create an issuable SD-JWT.
#[derive(Debug)]
pub struct SdJwtBuilder<H> {
  encoder: SdObjectEncoder<H>,
  disclosures: Vec<Disclosure>,
  key_bind: Option<RequiredKeyBinding>,
}

#[cfg(feature = "sha")]
impl SdJwtBuilder<Sha256Hasher> {
  /// Creates a new [`SdJwtBuilder`] with `sha-256` hash function.
  ///
  /// ## Error
  /// Returns [`Error::DataTypeMismatch`] if `object` is not a valid JSON object.
  pub fn new<T: Serialize>(object: T) -> Result<Self> {
    Self::new_with_hasher(object, Sha256Hasher::new())
  }
}

impl<H: Hasher> SdJwtBuilder<H> {
  /// Creates a new [`SdJwtBuilder`] with custom hash function to create digests.
  pub fn new_with_hasher<T: Serialize>(object: T, hasher: H) -> Result<Self> {
    Self::new_with_hasher_and_salt_size(object, hasher, DEFAULT_SALT_SIZE)
  }

  /// Creates a new [`SdJwtBuilder`] with custom hash function to create digests, and custom salt size.
  pub fn new_with_hasher_and_salt_size<T: Serialize>(object: T, hasher: H, salt_size: usize) -> Result<Self> {
    let object = serde_json::to_value(object).map_err(|e| Error::Unspecified(e.to_string()))?;
    let encoder = SdObjectEncoder::with_custom_hasher_and_salt_size(object, hasher, salt_size)?;
    Ok(Self {
      encoder,
      disclosures: vec![],
      key_bind: None,
    })
  }

  /// Substitutes a value with the digest of its disclosure.
  ///
  /// ## Notes
  /// - `path` indicates the pointer to the value that will be concealed using the syntax of [JSON pointer](https://datatracker.ietf.org/doc/html/rfc6901).
  ///
  ///
  /// ## Example
  ///  ```rust
  ///  use sd_jwt_payload::SdJwtBuilder;
  ///  use sd_jwt_payload::json;
  ///
  ///  let obj = json!({
  ///   "id": "did:value",
  ///   "claim1": {
  ///      "abc": true
  ///   },
  ///   "claim2": ["val_1", "val_2"]
  /// });
  /// let builder = SdJwtBuilder::new(obj)
  ///   .unwrap()
  ///   .make_concealable("/id").unwrap() //conceals "id": "did:value"
  ///   .make_concealable("/claim1/abc").unwrap() //"abc": true
  ///   .make_concealable("/claim2/0").unwrap(); //conceals "val_1"
  /// ```
  /// 
  /// ## Error
  /// * [`Error::InvalidPath`] if pointer is invalid.
  /// * [`Error::DataTypeMismatch`] if existing SD format is invalid.
  pub fn make_concealable(mut self, path: &str) -> Result<Self> {
    let disclosure = self.encoder.conceal(path)?;
    self.disclosures.push(disclosure);

    Ok(self)
  }

  /// Adds a decoy digest to the specified path.
  ///
  /// `path` indicates the pointer to the value that will be concealed using the syntax of
  /// [JSON pointer](https://datatracker.ietf.org/doc/html/rfc6901).
  ///
  /// Use `path` = "" to add decoys to the top level.
  pub fn add_decoys(mut self, path: &str, number_of_decoys: usize) -> Result<Self> {
    self.encoder.add_decoys(path, number_of_decoys)?;

    Ok(self)
  }

  /// Require a proof of possession of a given key from the holder.
  ///
  /// This operation adds a JWT confirmation (`cnf`) claim as specified in
  /// [RFC8300](https://www.rfc-editor.org/rfc/rfc7800.html#section-3).
  pub fn require_key_binding(mut self, key_bind: RequiredKeyBinding) -> Self {
    self.key_bind = Some(key_bind);
    self
  }

  /// Creates an SD-JWT with the provided data.
  pub async fn finish<S>(self, signer: &S, alg: &str) -> Result<SdJwt>
  where
    S: JwsSigner,
  {
    let SdJwtBuilder {
      mut encoder,
      disclosures,
      key_bind,
    } = self;
    encoder.add_sd_alg_property();
    let mut object = encoder.object;
    // Add key binding requirement as `cnf`.
    if let Some(key_bind) = key_bind {
      let key_bind = serde_json::to_value(key_bind).map_err(|e| Error::DeserializationError(e.to_string()))?;
      object.as_object_mut().unwrap().insert("cnf".to_string(), key_bind);
    }

    let Value::Object(header) = serde_json::json!({
      "typ": HEADER_TYP,
      "alg": alg,
    }) else {
      unreachable!();
    };

    let jws = signer
      .sign(&header, object.as_object().unwrap())
      .await
      .map_err(|e| anyhow::anyhow!("jws failed: {e}"))
      .and_then(|jws_bytes| String::from_utf8(jws_bytes).context("invalid JWS"))
      .map_err(|e| Error::JwsSignerFailure(e.to_string()))?;

    let claims = serde_json::from_value::<SdJwtClaims>(object)
      .map_err(|e| Error::DeserializationError(format!("invalid SD-JWT claims: {e}")))?;
    let jwt = Jwt { header, claims, jws };

    Ok(SdJwt::new(jwt, disclosures, None))
  }
}
