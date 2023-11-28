use crate::Utils;
use crate::ARRAY_DIGEST_KEY;
use crate::DIGESTS_KEY;

use super::Disclosure;
use super::Hasher;
use super::Sha256Hasher;
use crate::Error;
use serde_json::Map;
use serde_json::Value;
use std::collections::BTreeMap;

/// Substitutes digests in an SD-JWT object by their corresponding plaintext values provided by disclosures.
pub struct SdObjectDecoder {
  hashers: BTreeMap<String, Box<dyn Hasher>>,
}

impl SdObjectDecoder {
  /// Creates a new [`SdObjectDecoder`] with `sha-256` hasher.
  pub fn new() -> Self {
    let hashers: BTreeMap<String, Box<dyn Hasher>> = BTreeMap::new();
    let mut hasher = Self { hashers };
    hasher.add_hasher(Box::new(Sha256Hasher::new()));
    hasher
  }

  /// Adds a hasher.
  ///
  /// If a hasher for the same algorithm [`Hasher::alg_name`] already exists, it will be replaced and
  /// the existing hasher will be returned, otherwise `None`.
  pub fn add_hasher(&mut self, hasher: Box<dyn Hasher>) -> Option<Box<dyn Hasher>> {
    let alg_name = hasher.as_ref().alg_name().to_string();

    self.hashers.insert(alg_name.clone(), hasher)
  }

  /// Removes a hasher.
  ///
  /// If the hasher for that algorithm exists, it will be removed and returned, otherwise `None`.
  pub fn remove_hasher(&mut self, hash_alg: String) -> Option<Box<dyn Hasher>> {
    self.hashers.remove(&hash_alg)
  }

  /// Decodes an SD-JWT `object` containing by Substituting the digests with their corresponding
  /// plaintext values provided by `disclosures`.
  ///
  /// ## Notes
  /// * The hasher is determined by the `_sd_alg` property. If none is set, the sha-256 hasher will
  /// be used, if present.
  /// * Claims like `exp` or `iat` are not validated in the process of decoding.
  /// * `_sd_alg` property will be removed if present.
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
      let digest = Utils::digest_b64_url_only_ascii(hasher, disclosure.as_str());
      disclosures_map.insert(digest, parsed_disclosure);
    }

    // `processed_digests` are kept track of in case on digests appears more than once which
    // renders the SD-JWT invalid.
    let mut processed_digests: Vec<String> = vec![];

    // Decode the object recursively.
    let mut decoded = self.decode_object(object, &disclosures_map, &mut processed_digests)?;

    // Remove `_sd_alg` in case it exists.
    decoded.remove("_sd_alg");
    Ok(decoded)
  }

  pub fn determin_hasher(&self, object: &Map<String, Value>) -> Result<&dyn Hasher, Error> {
    //If the _sd_alg claim is not present at the top level, a default value of sha-256 MUST be used.
    let alg: &str = if let Some(alg) = object.get("_sd_alg") {
      alg
        .as_str()
        .ok_or(Error::DataTypeMismatch("`_sd_alg` is not a string".to_string()))?
    } else {
      Sha256Hasher::ALG_NAME
    };
    self
      .hashers
      .get(alg)
      .map(AsRef::as_ref)
      .ok_or(Error::HashingAlgorithmError)
  }

  fn decode_object(
    &self,
    object: &Map<String, Value>,
    disclosures: &BTreeMap<String, Disclosure>,
    processed_digests: &mut Vec<String>,
  ) -> Result<Map<String, Value>, Error> {
    let mut output: Map<String, Value> = object.clone();
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
              disclosure
            )))?;

            if output.contains_key(&claim_name) {
              return Err(Error::ClaimCollisionError(claim_name));
            }

            let recursively_decoded = match disclosure.claim_value {
              Value::Array(ref sub_arr) => Value::Array(self.decode_array(sub_arr, disclosures, processed_digests)?),
              Value::Object(ref sub_obj) => {
                Value::Object(self.decode_object(sub_obj, disclosures, processed_digests)?)
              }
              _ => disclosure.claim_value.clone(),
            };

            output.insert(claim_name, recursively_decoded);
          }
        }
        output.remove(DIGESTS_KEY);
        continue;
      }

      match value {
        Value::Object(object) => {
          let decoded_object = self.decode_object(object, disclosures, processed_digests)?;
          if !decoded_object.is_empty() {
            output.insert(key.to_string(), Value::Object(decoded_object));
          }
        }
        Value::Array(array) => {
          let decoded_array = self.decode_array(array, disclosures, processed_digests)?;
          if !decoded_array.is_empty() {
            output.insert(key.to_string(), Value::Array(decoded_array));
          }
        }
        _ => {}
      }
    }
    Ok(output)
  }

  fn decode_array(
    &self,
    array: &[Value],
    disclosures: &BTreeMap<String, Disclosure>,
    processed_digests: &mut Vec<String>,
  ) -> Result<Vec<Value>, Error> {
    let mut output: Vec<Value> = vec![];
    for value in array.iter() {
      if let Some(object) = value.as_object() {
        for (key, value) in object.iter() {
          if key == ARRAY_DIGEST_KEY {
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
                return Err(Error::InvalidDisclosure("array length must be 2".to_string()));
              }
              // Recursively decoded the disclosed values.
              let recursively_decoded = match disclosure.claim_value {
                Value::Array(ref sub_arr) => {
                  Value::Array(self.decode_array(sub_arr, disclosures, processed_digests)?)
                }
                Value::Object(ref sub_obj) => {
                  Value::Object(self.decode_object(sub_obj, disclosures, processed_digests)?)
                }
                _ => disclosure.claim_value.clone(),
              };

              output.push(recursively_decoded);
            }
          } else {
            let decoded_object = self.decode_object(object, disclosures, processed_digests)?;
            output.push(Value::Object(decoded_object));
          }
        }
      } else if let Some(arr) = value.as_array() {
        // Nested arrays need to be decoded too.
        let decoded = self.decode_array(arr, disclosures, processed_digests)?;
        output.push(Value::Array(decoded));
      } else {
        // Append the rest of the values.
        output.push(value.clone());
      }
    }

    Ok(output)
  }
}

impl Default for SdObjectDecoder {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod test {
  use crate::Error;
  use crate::SdObjectDecoder;
  use crate::SdObjectEncoder;
  use serde_json::json;
  use serde_json::Value;

  #[test]
  fn collision() {
    let object = json!({
      "id": "did:value",
    });
    let mut encoder = SdObjectEncoder::try_from(object).unwrap();
    let dis = encoder.conceal(&["id"], None).unwrap();
    encoder
      .object_mut()
      .insert("id".to_string(), Value::String("id-value".to_string()));
    let decoder = SdObjectDecoder::new();
    let decoded = decoder.decode(encoder.object(), &vec![dis.to_string()]).unwrap_err();
    assert!(matches!(decoded, Error::ClaimCollisionError(_)));
  }

  #[test]
  fn sd_alg() {
    let object = json!({
      "id": "did:value",
      "claim1": [
        "abc"
      ],
    });
    let mut encoder = SdObjectEncoder::try_from(object).unwrap();
    encoder.add_sd_alg_property();
    assert_eq!(encoder.object().get("_sd_alg").unwrap(), "sha-256");
    let decoder = SdObjectDecoder::new();
    let decoded = decoder.decode(encoder.object(), &vec![]).unwrap();
    assert!(decoded.get("_sd_alg").is_none());
  }
}
