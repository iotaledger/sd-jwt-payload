// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use josekit::jws::JwsAlgorithm;
use josekit::jws::JwsHeader;
use josekit::jws::JwsVerifier;
use josekit::jws::HS256;
use josekit::jwt::JwtPayload;
use josekit::jwt::{self};
use serde_json::json;
use serde_json::Map;
use serde_json::Value;

use sd_jwt::Disclosure;
use sd_jwt::SdJwt;
use sd_jwt::SdObjectDecoder;
use sd_jwt::SdObjectEncoder;

#[test]
fn test_complex_structure() {
  // Values taken from https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-06.html#appendix-A.2
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
          },
          "evidence2"
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
  let mut encoder = SdObjectEncoder::try_from(object.clone()).unwrap();
  let disclosure = encoder.conceal(&["verified_claims", "verification", "time"], None);
  disclosures.push(disclosure.unwrap());

  let disclosure = encoder.conceal_array_entry(&["verified_claims", "verification", "evidence"], 0, None);
  disclosures.push(disclosure.unwrap());

  let disclosure = encoder.conceal_array_entry(&["verified_claims", "verification", "evidence"], 1, None);
  disclosures.push(disclosure.unwrap());

  let disclosure = encoder.conceal(&["verified_claims", "verification", "evidence"], None);
  disclosures.push(disclosure.unwrap());

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
  let sd_jwt: String = sd_jwt.presentation();

  // Decoding the SD-JWT
  // Extract the payload from the JWT of the SD-JWT after verifying the signature.
  let sd_jwt: SdJwt = SdJwt::parse(&sd_jwt).unwrap();
  let verifier = HS256.verifier_from_bytes(key).unwrap();
  let (payload, _header) = jwt::decode_with_verifier(&sd_jwt.jwt, &verifier).unwrap();

  // Decode the payload by providing the disclosures that were parsed from the SD-JWT.
  let decoder = SdObjectDecoder::new_with_sha256();
  let decoded = decoder.decode(payload.claims_set(), &sd_jwt.disclosures).unwrap();
  println!("decoded object: {}", serde_json::to_string_pretty(&decoded).unwrap());
  assert_eq!(Value::Object(decoded), object);
}

#[test]
fn concealed_object_in_array() {
  let mut disclosures: Vec<Disclosure> = vec![];
  let nested_object = json!({
    "test1": 123,
  });
  let mut encoder = SdObjectEncoder::try_from(nested_object.clone()).unwrap();
  let disclosure = encoder.conceal(&["test1"], None);
  disclosures.push(disclosure.unwrap());

  let object = json!({
        "test2": [
          "value1",
          encoder.object()
        ]
  });

  let expected = json!({
        "test2": [
          "value1",
          {
           "test1": 123,
          }
        ]
  });
  let mut encoder = SdObjectEncoder::try_from(object.clone()).unwrap();
  let disclosure = encoder.conceal_array_entry(&["test2"], 0, None);
  disclosures.push(disclosure.unwrap());
  let disclosure = encoder.conceal(&["test2"], None);
  disclosures.push(disclosure.unwrap());

  let disclosures: Vec<String> = disclosures
    .into_iter()
    .map(|disclosure| disclosure.to_string())
    .collect();
  let decoder = SdObjectDecoder::new_with_sha256();
  let decoded = decoder.decode(encoder.object(), &disclosures).unwrap();
  assert_eq!(Value::Object(decoded), expected);
}

#[test]
fn decode() {
  // Values taken from https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-06.html#name-example-2-handling-structur
  let sd_jwt = "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkM5aW5wNllvUmFFWFI0Mjd6WUpQN1FyazFXSF84YmR3T0FfWVVyVW5HUVUiLCAiS3VldDF5QWEwSElRdlluT1ZkNTloY1ZpTzlVZzZKMmtTZnFZUkJlb3d2RSIsICJNTWxkT0ZGekIyZDB1bWxtcFRJYUdlcmhXZFVfUHBZZkx2S2hoX2ZfOWFZIiwgIlg2WkFZT0lJMnZQTjQwVjd4RXhad1Z3ejd5Um1MTmNWd3Q1REw4Ukx2NGciLCAiWTM0em1JbzBRTExPdGRNcFhHd2pCZ0x2cjE3eUVoaFlUMEZHb2ZSLWFJRSIsICJmeUdwMFdUd3dQdjJKRFFsbjFsU2lhZW9iWnNNV0ExMGJRNTk4OS05RFRzIiwgIm9tbUZBaWNWVDhMR0hDQjB1eXd4N2ZZdW8zTUhZS08xNWN6LVJaRVlNNVEiLCAiczBCS1lzTFd4UVFlVTh0VmxsdE03TUtzSVJUckVJYTFQa0ptcXhCQmY1VSJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAiYWRkcmVzcyI6IHsiX3NkIjogWyI2YVVoelloWjdTSjFrVm1hZ1FBTzN1MkVUTjJDQzFhSGhlWnBLbmFGMF9FIiwgIkF6TGxGb2JrSjJ4aWF1cFJFUHlvSnotOS1OU2xkQjZDZ2pyN2ZVeW9IemciLCAiUHp6Y1Z1MHFiTXVCR1NqdWxmZXd6a2VzRDl6dXRPRXhuNUVXTndrclEtayIsICJiMkRrdzBqY0lGOXJHZzhfUEY4WmN2bmNXN3p3Wmo1cnlCV3ZYZnJwemVrIiwgImNQWUpISVo4VnUtZjlDQ3lWdWIyVWZnRWs4anZ2WGV6d0sxcF9KbmVlWFEiLCAiZ2xUM2hyU1U3ZlNXZ3dGNVVEWm1Xd0JUdzMyZ25VbGRJaGk4aEdWQ2FWNCIsICJydkpkNmlxNlQ1ZWptc0JNb0d3dU5YaDlxQUFGQVRBY2k0MG9pZEVlVnNBIiwgInVOSG9XWWhYc1poVkpDTkUyRHF5LXpxdDd0NjlnSkt5NVFhRnY3R3JNWDQiXX0sICJfc2RfYWxnIjogInNoYS0yNTYifQ.IjE4EfnYu1RZ1uz6yqtFh5Lppq36VC4VeSr-hLDFpZ9zqBNmMrT5JHLLXTuMJqKQp3NIzDsLaft4GK5bYyfqhg~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInJlZ2lvbiIsICJcdTZlMmZcdTUzM2EiXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImNvdW50cnkiLCAiSlAiXQ~";
  let sd_jwt: SdJwt = SdJwt::parse(sd_jwt).unwrap();
  let (payload, _header) = jwt::decode_with_verifier(&sd_jwt.jwt, &DecoyJwsVerifier {}).unwrap();
  let decoder = SdObjectDecoder::new_with_sha256();
  let decoded: Map<String, Value> = decoder.decode(payload.claims_set(), &sd_jwt.disclosures).unwrap();
  let expected_object = json!({
    "address": {
      "country": "JP",
      "region": "港区"
    },
    "iss": "https://issuer.example.com",
    "iat": 1683000000,
    "exp": 1883000000
  }
  )
  .as_object()
  .unwrap()
  .clone();
  assert_eq!(expected_object, decoded);
}

// Boilerplate to allow extracting JWS payload without verifying the signature.
#[derive(Debug, Clone)]
struct DecoyJwsAlgorithm;
impl JwsAlgorithm for DecoyJwsAlgorithm {
  fn name(&self) -> &str {
    "ES256"
  }

  fn box_clone(&self) -> Box<dyn JwsAlgorithm> {
    Box::new(self.clone())
  }
}

#[derive(Debug, Clone)]
struct DecoyJwsVerifier;
impl JwsVerifier for DecoyJwsVerifier {
  fn algorithm(&self) -> &dyn josekit::jws::JwsAlgorithm {
    &DecoyJwsAlgorithm {}
  }

  fn key_id(&self) -> Option<&str> {
    None
  }

  fn verify(&self, _message: &[u8], _signature: &[u8]) -> Result<(), josekit::JoseError> {
    Ok(())
  }

  fn box_clone(&self) -> Box<dyn JwsVerifier> {
    Box::new(self.clone())
  }
}
