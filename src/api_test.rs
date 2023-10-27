use josekit::{
  jws::{JwsHeader, HS256},
  jwt::{self, JwtPayload},
};
use serde_json::{json, Value};

use crate::{Disclosure, SdJwt, SdObjectDecoder, SdObjectEncoder};

#[test]
fn api() {
  let object = json!({
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

  let mut disclosures: Vec<Disclosure> = vec![];
  let mut encoder = SdObjectEncoder::try_from(object).unwrap();
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

#[test]
fn test_complex_structure() {
  let object = json!({
    "verified_claims": {
      "verification": {
        "trust_framework": "de_aml",
        "time": "2012-04-23T18:25Z",
        "verification_process": "f24c6f-6d3f-4ec5-973e-b0d8506f3bc7",
        "evidence": [
          {
            "type": "document",
            "method": "pipp",
            "time": "2012-04-22T11:30Z",
            "document": {
              "type": "idcard",
              "issuer": {
                "name": "Stadt Augsburg",
                "country": "DE"
              },
              "number": "53554554",
              "date_of_issuance": "2010-03-23",
              "date_of_expiry": "2020-03-22"
            }
          }
        ]
      },
      "claims": {
        "given_name": "Max",
        "family_name": "Müller",
        "nationalities": [
          "DE"
        ],
        "birthdate": "1956-01-28",
        "place_of_birth": {
          "country": "IS",
          "locality": "Þykkvabæjarklaustur"
        },
        "address": {
          "locality": "Maxstadt",
          "postal_code": "12344",
          "country": "DE",
          "street_address": "Weidenstraße 22"
        }
      }
    },
    "birth_middle_name": "Timotheus",
    "salutation": "Dr.",
    "msisdn": "49123456789"
  });

  let mut disclosures: Vec<Disclosure> = vec![];
  let mut encoder = SdObjectEncoder::try_from(object).unwrap();
  let disclosure = encoder.conceal(&["verified_claims", "verification", "time"], None);
  disclosures.push(disclosure.unwrap());

  let disclosure = encoder.conceal_array_entry(&["verified_claims", "verification", "evidence"], 0, None);
  disclosures.push(disclosure.unwrap());

  // let disclosure = encoder.conceal(&["verified_claims", "verification", "evidence"], None);
  // disclosures.push(disclosure.unwrap());

  let disclosure = encoder.conceal(&["verified_claims", "claims", "place_of_birth", "locality"], None);
  disclosures.push(disclosure.unwrap());

  let disclosure = encoder.conceal(&["verified_claims", "claims"], None);
  disclosures.push(disclosure.unwrap());

  println!(
    "encoded object: {}",
    serde_json::to_string_pretty(&encoder.object()).unwrap()
  );
  // Create the JWT.
  // Creating JWTs is out of the scope of this library, josekit is used here as an example
  let mut header = JwsHeader::new();
  header.set_token_type("SD-JWT");

  // Use the encoded object as a payload for the JWT.
  let payload = JwtPayload::from_map(encoder.object().clone()).unwrap();
  let key = b"0123456789ABCDEF0123456789ABCDEF";
  let signer = HS256.signer_from_bytes(key).unwrap();
  let jwt = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

  // Create an SD_JWT by collecting the disclosures and creating an `SdJwt` instance.
  let disclosures: Vec<String> = disclosures
    .into_iter()
    .map(|disclosure| disclosure.to_string())
    .collect();
  let sd_jwt: SdJwt = SdJwt::new(jwt, disclosures.clone(), None);
  let sd_jwt: String = sd_jwt.to_string();

  // Decoding the SD-JWT
  // Extract the payload from the JWT of the SD-JWT after verifying the signature.
  let sd_jwt: SdJwt = SdJwt::parse(sd_jwt).unwrap();
  let verifier = HS256.verifier_from_bytes(key).unwrap();
  let (payload, _header) = jwt::decode_with_verifier(&sd_jwt.jwt, &verifier).unwrap();

  // Decode the payload by providing the disclosures that were parsed from the SD-JWT.
  let decoder = SdObjectDecoder::new_with_sha256_hasher();
  let decoded = decoder.decode(payload.claims_set(), &sd_jwt.disclosures).unwrap();
  println!("decoded object: {}", serde_json::to_string_pretty(&decoded).unwrap());
}
