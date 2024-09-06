use std::error::Error;

use async_trait::async_trait;
use serde_json::Map;
use serde_json::Value;

pub type JsonObject = Map<String, Value>;

/// JSON Web Signature Signer.
#[async_trait]
pub trait JwsSigner {
  type Error: Error;
  /// Creates a JWS.
  async fn sign(&self, header: &JsonObject, payload: &JsonObject) -> Result<Vec<u8>, Self::Error>;
}
