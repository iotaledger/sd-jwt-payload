// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use async_trait::async_trait;
use josekit::jws::alg::hmac::HmacJwsSigner;
use josekit::jws::JwsHeader;
use josekit::jws::HS256;
use josekit::jwt::JwtPayload;
use josekit::jwt::{self};
use sd_jwt_payload::JsonObject;
use sd_jwt_payload::JwsSigner;
use sd_jwt_payload::SdJwt;
use sd_jwt_payload::SdJwtBuilder;
use sd_jwt_payload::Sha256Hasher;
use serde_json::json;

struct HmacSignerAdapter(HmacJwsSigner);

#[async_trait]
impl JwsSigner for HmacSignerAdapter {
  type Error = josekit::JoseError;
  async fn sign(&self, header: &JsonObject, payload: &JsonObject) -> Result<Vec<u8>, Self::Error> {
    let header = JwsHeader::from_map(header.clone())?;
    let payload = JwtPayload::from_map(payload.clone())?;
    let jwt = jwt::encode_with_signer(&payload, &header, &self.0)?;
    let sig_bytes = jwt
      .split('.')
      .nth(2)
      .map(|sig| multibase::Base::Base64Url.decode(sig))
      .unwrap()
      .unwrap();

    Ok(sig_bytes)
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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

  let key = b"0123456789ABCDEF0123456789ABCDEF";
  let signer = HmacSignerAdapter(HS256.signer_from_bytes(key)?);
  let sd_jwt = SdJwtBuilder::new(object)?
    .make_concealable("/email")?
    .make_concealable("/phone_number")?
    .make_concealable("/address/street_address")?
    .make_concealable("/address")?
    .make_concealable("/nationalities/0")?
    .add_decoys("/nationalities", 1)?
    .add_decoys("", 2)?
    .require_key_binding(sd_jwt_payload::RequiredKeyBinding::Kid("key1".to_string()))
    .finish(&signer, "HS256")
    .await?;

  println!("raw object: {}", serde_json::to_string_pretty(sd_jwt.claims())?);

  // Issuer sends the SD-JWT with all its disclosures to its holder.
  let received_sd_jwt = sd_jwt.presentation();
  let sd_jwt = received_sd_jwt.parse::<SdJwt>()?;

  // The holder can withhold from a verifier any concealable claim by calling `conceal`.
  let hasher = Sha256Hasher::new();
  let (presented_sd_jwt, _removed_disclosures) = sd_jwt
    .into_presentation(&hasher)?
    .conceal("/email")?
    .conceal("/nationalities/0")?
    .finish();

  // The holder send its token to a verifier.
  let received_sd_jwt = presented_sd_jwt.presentation();
  let sd_jwt = received_sd_jwt.parse::<SdJwt>()?;

  println!(
    "object to verify: {}",
    serde_json::to_string_pretty(&sd_jwt.into_disclosed_object(&hasher)?)?
  );

  Ok(())
}
