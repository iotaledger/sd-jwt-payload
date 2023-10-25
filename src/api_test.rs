use josekit::{
  jws::{JwsHeader, HS256},
  jwt::{self, JwtPayload},
};
use serde_json::{json, Value};

use crate::{Disclosure, SdJwt, SdObjectEncoder};

#[test]
fn api() {
  let json = json!({
    "sub": "user_42",
    "given_name": "John",
    "family_name": "Doe",
    "email": "johndoe@example.com",
    "phone_number": "+1-202-555-0101",
    "phone_number_verified": true,
    "address": {
      "street_address": "123 Main St",
      "locality": "Anytown",
      "region": "Anystate",
      "country": "US"
    },
    "birthdate": "1940-01-01",
    "updated_at": 1570000000,
    "nationalities": [
      "US",
      "DE"
    ]
  });
  let stringi = json.to_string();

  let mut disclosures: Vec<Disclosure> = vec![];
  let mut encoder = SdObjectEncoder::new(&stringi).unwrap();
  let disclosure = encoder.conceal(&["given_name"], Some("2GLC42sKQveCfGfryNRN9w".to_owned()));
  disclosures.push(disclosure.unwrap());
  let disclosure = encoder.conceal(&["family_name"], Some("eluV5Og3gSNII8EYnsxA_A".to_owned()));
  disclosures.push(disclosure.unwrap());
  let disclosure = encoder.conceal(&["email"], Some("6Ij7tM-a5iVPGboS5tmvVA".to_owned()));
  disclosures.push(disclosure.unwrap());
  let disclosure = encoder.conceal(&["phone_number"], Some("eI8ZWm9QnKPpNPeNenHdhQ".to_owned()));
  disclosures.push(disclosure.unwrap());
  let disclosure = encoder.conceal(&["phone_number_verified"], Some("Qg_O64zqAxe412a108iroA".to_owned()));
  disclosures.push(disclosure.unwrap());
  let disclosure = encoder.conceal(&["address"], Some("AJx-095VPrpTtN4QMOqROA".to_owned()));
  disclosures.push(disclosure.unwrap());
  let disclosure = encoder.conceal(&["birthdate"], Some("Pc33JM2LchcU_lHggv_ufQ".to_owned()));
  disclosures.push(disclosure.unwrap());
  let disclosure = encoder.conceal(&["updated_at"], Some("G02NSrQfjFXQ7Io09syajA".to_owned()));
  disclosures.push(disclosure.unwrap());
  let disclosure = encoder.conceal_array_entry(&["nationalities"], 0, Some("lklxF5jMYlGTPUovMNIvCA".to_owned()));
  println!("{}", disclosure.as_ref().unwrap().to_string());
  disclosures.push(disclosure.unwrap());
  let disclosure = encoder.conceal_array_entry(&["nationalities"], 1, Some("nPuoQnkRFq3BIeAm7AnXFA".to_owned()));
  disclosures.push(disclosure.unwrap());

  let encoded = encoder.to_string().unwrap();

  let encoded_json: Value = serde_json::from_str(&encoded).unwrap();

  let mut header = JwsHeader::new();
  header.set_token_type("JWT");

  let payload = JwtPayload::from_map(encoded_json.as_object().unwrap().clone()).unwrap();
  let key = b"0123456789ABCDEF0123456789ABCDEF";
  let signer = HS256.signer_from_bytes(key).unwrap();
  let jwt = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

  let disclosures: Vec<String> = disclosures
    .into_iter()
    .map(|disclosure| disclosure.to_string())
    .collect();

  let sd_jwt = SdJwt::new(jwt, disclosures.clone(), None);

  let decoder = crate::SdObjectDecoder::new_with_sha256_hasher();
  let decoded = decoder.decode(encoded_json.as_object().unwrap(), &disclosures).unwrap();
}
