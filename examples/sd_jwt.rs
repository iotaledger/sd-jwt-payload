use josekit::jws::JwsHeader;
use josekit::jws::HS256;
use josekit::jwt::JwtPayload;
use josekit::jwt::{self};
use sd_jwt::Disclosure;
use sd_jwt::SdJwt;
use sd_jwt::SdObjectDecoder;
use sd_jwt::SdObjectEncoder;
use serde_json::json;

fn main() {
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
  let mut encoder: SdObjectEncoder = object.try_into().unwrap();
  let disclosure = encoder.conceal(&["email"], None).unwrap();
  disclosures.push(disclosure);
  let disclosure = encoder.conceal(&["phone_number"], None);
  disclosures.push(disclosure.unwrap());
  let disclosure = encoder.conceal(&["address", "street_address"], None);
  disclosures.push(disclosure.unwrap());
  let disclosure = encoder.conceal(&["address"], None);
  disclosures.push(disclosure.unwrap());
  let disclosure = encoder.conceal_array_entry(&["nationalities"], 0, None);
  disclosures.push(disclosure.unwrap());
  encoder.add_sd_alg_property();

  println!(
    "encoded object: {}",
    serde_json::to_string_pretty(encoder.object()).unwrap()
  );

  // Create the JWT.
  // Creating JWTs is out of the scope of this library, josekit is used here as an example
  let mut header = JwsHeader::new();
  header.set_token_type("sd-jwt");

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
  let decoder = SdObjectDecoder::new_with_sha256_hasher();
  let decoded = decoder.decode(payload.claims_set(), &sd_jwt.disclosures).unwrap();
  println!("decoded object: {}", serde_json::to_string_pretty(&decoded).unwrap());
}
