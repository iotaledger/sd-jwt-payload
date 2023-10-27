use crate::{Utils, DIGESTS_KEY};

use super::{Disclosure, Hasher, ShaHasher};
use crate::Error;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Substitutes digests in an SD-JWT object by their corresponding plaintext values provided by disclosures.
pub struct SdObjectDecoder {
  hashers: BTreeMap<String, Box<dyn Hasher>>,
}

impl SdObjectDecoder {
  /// Creates a new [`SdObjectDecoder`] without any hashers.
  /// If `sha-256` decoder is needed, consider using `new_with_sha256_hasher()` instead.
  pub fn new() -> Self {
    let hashers: BTreeMap<String, Box<dyn Hasher>> = BTreeMap::new();
    Self { hashers }
  }

  /// Creates a new [`SdObjectDecoder`] with `sha-256` hasher.
  pub fn new_with_sha256_hasher() -> Self {
    let mut hasher = Self::new();
    hasher.add_hasher(Box::new(ShaHasher::new()));
    hasher
  }

  /// Adds a hasher.
  ///
  /// If a hasher for the same algorithm [`Hasher::alg_name`] already exists, it will be replaced and
  /// the existing hasher will be returned, otherwise `None`.
  pub fn add_hasher(&mut self, hasher: Box<dyn Hasher>) -> Option<Box<dyn Hasher>> {
    let alg_name = hasher.as_ref().alg_name().to_string();
    let existing_hasher = self.hashers.insert(alg_name.clone(), hasher);
    existing_hasher
  }

  /// Removes a hasher.
  ///
  /// If the hasher for that algorithm exists, it will be removed and returned, otherwise `None`.
  pub fn remove_hasher(&mut self, hash_alg: String) -> Option<Box<dyn Hasher>> {
    self.hashers.remove(&hash_alg)
  }

  /// Decodes an SD-JWT `object` containing by Substituting the digests with their corresponding
  /// plaintext values provided by `disclosures`.
  pub fn decode(
    &self,
    object: &Map<String, Value>,
    disclosures: &Vec<String>,
  ) -> Result<Map<String, Value>, crate::Error> {
    // Determine hasher.
    let hasher = self.determin_hasher(object)?;

    // Create a map of (disclosure digest) → (disclosure).
    let mut disclosures_map: BTreeMap<String, Disclosure> = BTreeMap::new();
    for disclosure in disclosures {
      let parsed_disclosure = Disclosure::parse(disclosure.to_string())?;
      let digest = Utils::digest_b64_url_only_ascii(&**hasher, disclosure.as_str());
      disclosures_map.insert(digest, parsed_disclosure);
    }

    // `processed_digests` are kept track of in case on digests appears more than once which
    // renders the SD-JWT invalid.
    let mut processed_digests: Vec<String> = vec![];

    // Decode the object recursively.
    let (mut decoded, mut changed) = self.decode_object(object, &disclosures_map, &mut processed_digests)?;
    while changed {
      (decoded, changed) = self.decode_object(&decoded, &disclosures_map, &mut processed_digests)?;
    }

    // Remove `_sd_alg` in case it exists.
    decoded.remove("_sd_alg");
    Ok(decoded)
  }

  fn determin_hasher(&self, object: &Map<String, Value>) -> Result<&Box<dyn Hasher>, Error> {
    //If the _sd_alg claim is not present at the top level, a default value of sha-256 MUST be used.
    let alg: &str = if let Some(alg) = object.get("_sd_alg") {
      alg
        .as_str()
        .ok_or(Error::DataTypeMismatch("`_sd_alg` is not a string".to_string()))?
    } else {
      ShaHasher::ALG_NAME
    };
    self.hashers.get(alg).ok_or(Error::HashingAlgorithmError)
  }

  fn decode_object(
    &self,
    object: &Map<String, Value>,
    disclosures: &BTreeMap<String, Disclosure>,
    processed_digests: &mut Vec<String>,
  ) -> Result<(Map<String, Value>, bool), Error> {
    let mut output: Map<String, Value> = object.clone();
    let mut changed = false;
    for (key, value) in object.iter() {
      if key == DIGESTS_KEY {
        let sd_array: &Vec<Value> = value
          .as_array()
          .ok_or(Error::DataTypeMismatch(format!("{} is not an array", DIGESTS_KEY)))?;
        for digest in sd_array {
          let digest_str = digest
            .as_str()
            .ok_or(Error::DataTypeMismatch(format!("{} is not a string", digest)))?
            .to_string();

          // Reject if any digests were found more than once.
          if processed_digests.contains(&digest_str) {
            return Err(Error::DuplicateDigestError(digest_str));
          }

          // Check if a disclosure of this digest is available
          // and insert its claim name and value in the object.
          if let Some(disclosure) = disclosures.get(&digest_str) {
            let claim_name = disclosure.claim_name.clone().ok_or(Error::DataTypeMismatch(format!(
              "disclosure type error: {}",
              disclosure.to_string()
            )))?;

            if output.contains_key(&claim_name) {
              return Err(Error::ClaimCollisionError(claim_name));
            }

            output.insert(claim_name, disclosure.claim_value.clone());
            changed = true;
          }
        }
        output.remove(DIGESTS_KEY);
        continue;
      }

      match value {
        Value::Object(object) => {
          let (mut decoded_object, mut changed) = self.decode_object(object, disclosures, processed_digests)?;
          while changed {
            (decoded_object, changed) = self.decode_object(&decoded_object, disclosures, processed_digests)?;
          }
          if !decoded_object.is_empty() {
            output.insert(key.to_string(), Value::Object(decoded_object));
          }
        }
        Value::Array(array) => {
          let (mut decoded_array, mut changed) = self.decode_array(array, disclosures, processed_digests)?;
          while changed {
            (decoded_array, changed) = self.decode_array(&decoded_array, disclosures, processed_digests)?;
          }
          if !decoded_array.is_empty() {
            output.insert(key.to_string(), Value::Array(decoded_array));
          }
        }
        _ => {}
      }
    }
    Ok((output, changed))
  }

  fn decode_array(
    &self,
    array: &Vec<Value>,
    disclosures: &BTreeMap<String, Disclosure>,
    processed_digests: &mut Vec<String>,
  ) -> Result<(Vec<Value>, bool), Error> {
    let mut output: Vec<Value> = vec![];
    let mut changed = false;

    for value in array.iter() {
      if let Some(object) = value.as_object() {
        for (key, value) in object.iter() {
          if key == "..." {
            if object.keys().len() != 1 {
              return Err(Error::InvalidArrayDisclosureObject);
            }

            let digest_in_array = value
              .as_str()
              .ok_or(Error::DataTypeMismatch(format!("{} is not a string", key)))?
              .to_string();

            // Reject if any digests were found more than once.
            if processed_digests.contains(&digest_in_array) {
              return Err(Error::DuplicateDigestError(digest_in_array));
            }

            if let Some(disclosure) = disclosures.get(&digest_in_array) {
              if disclosure.claim_name.is_some() {
                panic!("array length must be 2");
              }
              output.push(disclosure.claim_value.clone());
              changed = true;
            }
          } else {
            let (mut decoded_object, mut changed) = self.decode_object(object, disclosures, processed_digests)?;
            while changed {
              (decoded_object, changed) = self.decode_object(&decoded_object, disclosures, processed_digests)?;
            }
            output.push(Value::Object(decoded_object));
          }
        }
      } else {
        output.push(value.clone());
        //to do: arrays in arrays can have disclosuers?
      }
    }

    Ok((output, changed))
  }
}
