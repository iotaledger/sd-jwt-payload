use super::{Disclosure, Hasher, Sha256Hasher};
use crate::Error;
use crate::Result;
use crate::Utils;
use rand::{distributions::DistString, Rng};
use serde_json::{json, Map, Value};

pub(crate) const DIGESTS_KEY: &str = "_sd";
pub(crate) const ARRAY_DIGEST_KEY: &str = "...";

/// Transforms a JSON object into an SD-JWT object by substituting selected values
/// with their corresponding disclosure digests.
pub struct SdObjectEncoder<H: Hasher = Sha256Hasher> {
  /// The object in JSON object format.
  pub object: Map<String, Value>,
  /// Length of the salts that generated for disclosures.
  /// Constant length for readability considerations.
  pub salt_length: usize,
  /// The hash function used to create digests.
  pub hasher: H,
}

impl SdObjectEncoder {
  /// Creates a new [`SdObjectEncoder`] with `sha-256` hash function.
  ///
  /// ## Error
  /// Returns [`Error::DeserializationError`] if `object` is not a valid JSON object.
  pub fn new(object: &str) -> Result<SdObjectEncoder<Sha256Hasher>> {
    Ok(SdObjectEncoder {
      object: serde_json::from_str(object).map_err(|e| Error::DeserializationError(e.to_string()))?,
      salt_length: rand::thread_rng().gen_range(24..34),
      hasher: Sha256Hasher::new(),
    })
  }
}

impl TryFrom<Value> for SdObjectEncoder {
  type Error = crate::Error;

  fn try_from(value: Value) -> std::result::Result<Self, Self::Error> {
    match value {
      Value::Object(object) => Ok(SdObjectEncoder {
        object,
        salt_length: rand::thread_rng().gen_range(24..34),
        hasher: Sha256Hasher::new(),
      }),
      _ => Err(Error::DataTypeMismatch("Expected object".to_owned())),
    }
  }
}

impl<H: Hasher> SdObjectEncoder<H> {
  /// Creates a new [`SdObjectEncoder`] with custom hash function to create digests.
  pub fn with_custom_hasher(json: &str, hasher: H) -> Result<Self> {
    Ok(Self {
      object: serde_json::from_str(json).map_err(|e| Error::DeserializationError(e.to_string()))?,
      salt_length: rand::thread_rng().gen_range(24..34),
      hasher,
    })
  }

  /// Substitutes a value with the digest of its disclosure.
  /// If no salt is provided, the disclosure will be created with random salt value.
  ///
  /// The value of the key specified in `path` will be concealed. E.g. for path
  /// `["claim", "subclaim"]` the value of `claim.subclaim` will be concealed.
  /// The path slice must not be empty.
  ///
  /// Note: use `conceal_array_entry` for values in arrays.
  pub fn conceal(&mut self, path: &[&str], salt: Option<String>) -> Result<Disclosure> {
    // Error if path is not provided.
    if path.len() == 0 {
      return Err(Error::InvalidPath("the provided path length is 0".to_string()));
    }

    // Determine salt.
    let salt = salt.unwrap_or(Self::gen_rand(self.salt_length));

    // Obtain the parent of the property specified by the provided path.
    let (target_key, parent_value) = Self::get_target_property_and_its_parent(&mut self.object, path)?;

    // Remove the value from the parent and create a disclosure for it.
    let disclosure = Disclosure::new(
      salt,
      Some(target_key.to_owned()),
      parent_value
        .remove(target_key)
        .ok_or(Error::InvalidPath(format!("{} does not exist", target_key)))?,
    );

    // Hash the disclosure.
    let hash = Utils::digest_b64_url_only_ascii(&self.hasher, disclosure.as_str());

    // Add the hash to the "_sd" array if exists; otherwise, create the array and insert the hash.
    Self::add_digest_to_object(parent_value, hash)?;
    Ok(disclosure)
  }

  /// Substitutes a value within an array with the digest of its disclosure.
  /// If no salt is provided, the disclosure will be created with random salt value.
  ///
  /// `path` is used to specify the array in the object, while `element_index` specifies
  /// the index of the element to be concealed (index start at 0).
  ///
  /// The path slice must not be empty.
  pub fn conceal_array_entry(
    &mut self,
    path: &[&str],
    element_index: usize,
    salt: Option<String>,
  ) -> Result<Disclosure> {
    // Error if path is not provided.
    if path.len() == 0 {
      return Err(Error::InvalidPath("the provided path length is 0".to_string()));
    }

    // Determine salt.
    let salt = salt.unwrap_or(Self::gen_rand(self.salt_length));

    // Obtain the parent of the property specified by the provided path.
    let (target_key, parent_value) = Self::get_target_property_and_its_parent(&mut self.object, path)?;

    let array = parent_value
      .get_mut(target_key)
      .ok_or(Error::InvalidPath(format!("{} does not exist", target_key)))?
      .as_array_mut()
      .ok_or(Error::InvalidPath(format!("{} is not an array", target_key)))?;

    // Get array element, calculate digest of the disclosure and replace the element with the object
    // of form "{"...": "<digest>"}".
    if let Some(element_value) = array.get_mut(element_index) {
      let disclosure = Disclosure::new(salt, None, element_value.clone());
      let hash = Utils::digest_b64_url_only_ascii(&self.hasher, disclosure.as_str());
      let tripledot = json!({ARRAY_DIGEST_KEY: hash});
      *element_value = tripledot;
      Ok(disclosure)
    } else {
      Err(Error::IndexOutofBounds)
    }
  }

  fn get_target_property_and_its_parent<'a, 'b>(
    json: &'a mut Map<String, Value>,
    path: &'b [&str],
  ) -> Result<(&'b str, &'a mut Map<String, Value>)> {
    let mut parent_value = json;
    let mut target_property = path[0];
    for index in 1..path.len() {
      match parent_value
        .get(target_property)
        .ok_or(Error::InvalidPath(format!("{} does not exist", target_property)))?
      {
        Value::Object(_) => {
          parent_value = parent_value
            .get_mut(path[index - 1])
            .ok_or(Error::InvalidPath(format!("{} does not exist", path[index - 1])))?
            .as_object_mut()
            .ok_or(Error::InvalidPath(format!("{} is not an object", path[index - 1])))?;
          target_property = path[index];
        }
        _ => return Err(Error::InvalidPath(format!("{} is not an object", target_property))),
      }
    }
    Ok((target_property, parent_value))
  }

  /// Adds the `_sd_alg` property to the top level of the object.
  /// The value is taken from the [`crate::Hasher::alg_name`] implementation.
  pub fn add_sd_alg_property(&mut self) -> Option<Value> {
    self
      .object
      .insert("_sd_alg".to_string(), Value::String(self.hasher.alg_name().to_string()))
  }

  /// Returns the modified object as a string.
  pub fn to_string(&self) -> Result<String> {
    Ok(
      serde_json::to_string(&self.object)
        .map_err(|_e| Error::Unspecified("error while serializing internal object".to_string()))?,
    )
  }

  /// Adds a decoy digest to the specified path.
  /// If path is an empty slice, decoys will be added to the top level.
  pub fn add_decoys(&mut self, path: &[&str], number_of_decoys: usize) -> Result<Vec<Disclosure>> {
    let mut disclosures = vec![];
    for _ in 0..number_of_decoys {
      disclosures.push(self.add_decoy(path)?);
    }
    Ok(disclosures)
  }

  fn add_decoy(&mut self, path: &[&str]) -> Result<Disclosure> {
    if path.len() == 0 {
      let (disclosure, hash) = Self::random_digest(&self.hasher, self.salt_length, true);
      Self::add_digest_to_object(&mut self.object, hash)?;
      return Ok(disclosure);
    } else {
      let (target_key, parent_value) = Self::get_target_property_and_its_parent(&mut self.object, path)?;

      let value: &mut Value = parent_value
        .get_mut(target_key)
        .ok_or(Error::InvalidPath(format!("{} does not exist", target_key)))?;

      if let Some(object) = value.as_object_mut() {
        let (disclosure, hash) = Self::random_digest(&self.hasher, self.salt_length, true);
        Self::add_digest_to_object(object, hash)?;
        return Ok(disclosure);
      } else if let Some(array) = value.as_array_mut() {
        let (disclosure, hash) = Self::random_digest(&self.hasher, self.salt_length, true);
        let tripledot = json!({ARRAY_DIGEST_KEY: hash});
        array.push(tripledot);
        return Ok(disclosure);
      } else {
        return Err(Error::InvalidPath(format!(
          "{} is neiter an object nor an array",
          target_key
        )));
      }
    }
  }

  fn add_digest_to_object(object: &mut Map<String, Value>, digest: String) -> Result<()> {
    // Add the hash to the "_sd" array if exists; otherwise, create the array and insert the hash.
    match object.get_mut(DIGESTS_KEY) {
      Some(sd_value) => match sd_value {
        Value::Array(value) => value.push(Value::String(digest)),
        _ => {
          return Err(Error::DataTypeMismatch(
            "invalid object: existing `_sd` type is not an array".to_string(),
          ))
        }
      },
      None => {
        object.insert(DIGESTS_KEY.to_owned(), Value::Array(vec![Value::String(digest)]));
      }
    }
    Ok(())
  }

  fn random_digest(hasher: &dyn Hasher, salt_len: usize, array_entry: bool) -> (Disclosure, String) {
    let mut rng = rand::thread_rng();
    let salt = Self::gen_rand(salt_len);
    let decoy_value_length = rng.gen_range(20..=100);
    let decoy_claim_name = if array_entry {
      None
    } else {
      let decoy_claim_name_length = rng.gen_range(4..=10);
      Some(Self::gen_rand(decoy_claim_name_length))
    };
    let decoy_value = Self::gen_rand(decoy_value_length);
    let disclosure = Disclosure::new(salt, decoy_claim_name, Value::String(decoy_value));
    let hash = Utils::digest_b64_url_only_ascii(hasher, disclosure.as_str());
    (disclosure, hash)
  }

  fn gen_rand(len: usize) -> String {
    // todo: check if random is cryptographically secure.
    rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), len)
  }

  pub fn object(&self) -> &Map<String, Value> {
    &self.object
  }
}

#[cfg(test)]
mod test {
  use super::SdObjectEncoder;
  use crate::Error;
  use crate::Sha256Hasher;
  use serde_json::json;

  #[test]
  fn test() {
    let object = json!({
      "id": "did:value",
      "claim1": {
        "abc": true
      },
      "claim2": ["arr-value1", "arr-value2"]
    });
    let object_string = object.to_string();
    let mut encoder = SdObjectEncoder::<Sha256Hasher>::new(&object_string).unwrap();
    encoder.conceal(&["claim1", "abc"], None).unwrap();
    encoder.conceal(&["id"], None).unwrap();
    encoder.add_decoys(&[], 10).unwrap();
    encoder.add_decoys(&["claim2"], 10).unwrap();
    assert_eq!(encoder.object.get("_sd").unwrap().as_array().unwrap().len(), 11);
    assert_eq!(encoder.object.get("claim2").unwrap().as_array().unwrap().len(), 12);
    println!(
      "encoded object: {}",
      serde_json::to_string_pretty(&encoder.object()).unwrap()
    );
  }

  #[test]
  fn test_wrong_path() {
    let object = json!({
      "id": "did:value",
      "claim1": [
        "abc"
      ],
    });
    let mut encoder = SdObjectEncoder::try_from(object).unwrap();
    assert!(matches!(
      encoder.conceal(&["claim12"], None).unwrap_err(),
      Error::InvalidPath(_)
    ));
    assert!(matches!(
      encoder.conceal_array_entry(&["claim12"], 0, None).unwrap_err(),
      Error::InvalidPath(_)
    ));
  }
}
