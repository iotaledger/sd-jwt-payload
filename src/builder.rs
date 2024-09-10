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
use multibase::Base;

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
  pub fn new(object: Value) -> Result<Self> {
    Self::new_with_hasher(Sha256Hasher::new(), object)
  }
}

impl<H: Hasher> SdJwtBuilder<H> {
  /// Creates a new [`SdJwtBuilder`] with custom hash function to create digests.
  pub fn new_with_hasher(hasher: H, object: Value) -> Result<Self> {
    Self::new_with_hasher_and_salt_size(object, hasher, DEFAULT_SALT_SIZE)
  }

  /// Creates a new [`SdJwtBuilder`] with custom hash function to create digests, and custom salt size.
  pub fn new_with_hasher_and_salt_size(object: Value, hasher: H, salt_size: usize) -> Result<Self> {
    let encoder = SdObjectEncoder::with_custom_hasher_and_salt_size(object, hasher, salt_size)?;
    Ok(Self {
      encoder,
      disclosures: vec![],
      key_bind: None,
    })
  }

  /// Makes a property or value of the object concealable. See [`SdObjectEncoder::conceal`] for more details.
  ///
  /// ## Notes
  /// `path` indicates the pointer to the value that will be concealed using the syntax of
  /// [JSON pointer](https://datatracker.ietf.org/doc/html/rfc6901).
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
  pub fn require_key_binding(mut self, key_bind: RequiredKeyBinding) -> Self {
    self.key_bind = Some(key_bind);
    self
  }

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
    let signature = {
      let raw_signature = signer
        .sign(&header, object.as_object().unwrap())
        .await
        .map_err(|e| Error::JwsSignerFailure(e.to_string()))?;
      Base::Base64Url.encode(raw_signature)
    };

    let claims = serde_json::from_value::<SdJwtClaims>(object)
      .map_err(|e| Error::DeserializationError(format!("invalid SD-JWT claims: {e}")))?;
    let jwt = Jwt {
      header,
      claims,
      signature,
    };

    Ok(SdJwt::new(jwt, disclosures, None))
  }
}
