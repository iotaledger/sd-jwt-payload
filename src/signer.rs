// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use async_trait::async_trait;
use serde_json::Map;
use serde_json::Value;

pub type JsonObject = Map<String, Value>;

/// JSON Web Signature (JWS) Signer.
#[async_trait]
pub trait JwsSigner {
  type Error: Error;
  /// Creates a JWS. The algorithm used for signed must be read from `header.alg` property.
  async fn sign(&self, header: &JsonObject, payload: &JsonObject) -> Result<Vec<u8>, Self::Error>;
}
