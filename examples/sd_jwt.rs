// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use josekit::jws::JwsHeader;
use josekit::jws::HS256;
use josekit::jwt::JwtPayload;
use josekit::jwt::{self};
use sd_jwt_payload::Disclosure;
use sd_jwt_payload::SdJwt;
use sd_jwt_payload::SdObjectDecoder;
use sd_jwt_payload::SdObjectEncoder;
use serde_json::json;

fn main() -> Result<(), Box<dyn Error>> {
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

  let mut encoder: SdObjectEncoder = object.try_into()?;
  let disclosures: Vec<Disclosure> = vec![
    encoder.conceal("/email", None)?,
    encoder.conceal("phone_number", None)?,
    encoder.conceal("address/street_address", None)?,
    encoder.conceal("address", None)?,
    encoder.conceal(&"nationalities/0", None)?,
  ];
  encoder.add_sd_alg_property();

  println!("encoded object: {}", serde_json::to_string_pretty(encoder.object())?);

  // Create the JWT.
  // Creating JWTs is outside the scope of this library, josekit is used here as an example.
  let mut header = JwsHeader::new();
  header.set_token_type("sd-jwt");

  // Use the encoded object as a payload for the JWT.
  let payload = JwtPayload::from_map(encoder.object().as_object().unwrap().clone())?;
  let key = b"0123456789ABCDEF0123456789ABCDEF";
  let signer = HS256.signer_from_bytes(key)?;
  let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;

  // Create an SD_JWT by collecting the disclosures and creating an `SdJwt` instance.
  let disclosures: Vec<String> = disclosures
    .into_iter()
    .map(|disclosure| disclosure.to_string())
    .collect();
  let sd_jwt: SdJwt = SdJwt::new(jwt, disclosures.clone(), None);
  let sd_jwt: String = sd_jwt.presentation();

  // Decoding the SD-JWT
  // Extract the payload from the JWT of the SD-JWT after verifying the signature.
  let sd_jwt: SdJwt = SdJwt::parse(&sd_jwt)?;
  let verifier = HS256.verifier_from_bytes(key)?;
  let (payload, _header) = jwt::decode_with_verifier(&sd_jwt.jwt, &verifier)?;

  // Decode the payload by providing the disclosures that were parsed from the SD-JWT.
  let decoder = SdObjectDecoder::new_with_sha256();
  let decoded = decoder.decode(payload.claims_set(), &sd_jwt.disclosures)?;
  println!("decoded object: {}", serde_json::to_string_pretty(&decoded)?);
  Ok(())
}
