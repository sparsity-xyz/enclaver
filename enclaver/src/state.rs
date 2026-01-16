//! State management module for encrypted S3-based persistence.
//!
//! This module provides APIs for saving and loading encrypted application state
//! to/from S3. Data is encrypted using the enclave's P-384 encryption key before
//! being stored externally.

use anyhow::{Result, anyhow};
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use crate::encryption_key::EncryptionKey;
use crate::manifest::StorageConfig;

/// State save request payload.
#[derive(Debug, Deserialize)]
pub struct StateSaveRequest {
    /// The application state data to save (arbitrary JSON).
    pub data: serde_json::Value,
}

/// State save response.
#[derive(Debug, Serialize)]
pub struct StateSaveResponse {
    /// keccak256 hash of the encrypted blob (for on-chain verification).
    pub state_hash: String,
    /// S3 object key where the state was stored.
    pub object_key: String,
}

/// State load response.
#[derive(Debug, Serialize)]
pub struct StateLoadResponse {
    /// The decrypted application state data.
    pub data: serde_json::Value,
    /// keccak256 hash of the encrypted blob.
    pub state_hash: String,
}

/// State manager for encrypted S3 persistence.
pub struct StateManager {
    s3_client: S3Client,
    config: StorageConfig,
    encryption_key: std::sync::Arc<EncryptionKey>,
}

impl StateManager {
    /// Create a new StateManager with the given configuration.
    pub async fn new(
        config: StorageConfig,
        encryption_key: std::sync::Arc<EncryptionKey>,
    ) -> Result<Self> {
        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let s3_client = S3Client::new(&aws_config);
        
        Ok(Self {
            s3_client,
            config,
            encryption_key,
        })
    }

    /// Calculate keccak256 hash and return as hex string.
    fn keccak256(data: &[u8]) -> String {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(data);
        hasher.finalize(&mut output);
        format!("0x{}", hex::encode(output))
    }

    /// Get the S3 object key for state storage.
    fn get_object_key(&self) -> String {
        match &self.config.s3_prefix {
            Some(prefix) => format!("{}/state.enc", prefix),
            None => "state.enc".to_string(),
        }
    }

    /// Save state to S3 with encryption.
    pub async fn save(&self, request: StateSaveRequest) -> Result<StateSaveResponse> {
        // Serialize the data to JSON
        let plaintext = serde_json::to_vec(&request.data)?;
        
        // Generate a nonce for encryption
        let nonce: [u8; 32] = rand::random();
        
        // Encrypt using our own public key (self-encryption)
        let our_pubkey_der = self.encryption_key.public_key_as_der()?;
        let ciphertext = self.encryption_key.encrypt(&plaintext, &our_pubkey_der, &nonce)?;
        
        // Build the encrypted blob: nonce (32 bytes) + ciphertext
        let mut encrypted_blob = Vec::with_capacity(32 + ciphertext.len());
        encrypted_blob.extend_from_slice(&nonce);
        encrypted_blob.extend_from_slice(&ciphertext);
        
        // Calculate state hash
        let state_hash = Self::keccak256(&encrypted_blob);
        
        // Upload to S3
        let object_key = self.get_object_key();
        self.s3_client
            .put_object()
            .bucket(&self.config.s3_bucket)
            .key(&object_key)
            .body(ByteStream::from(encrypted_blob))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to upload state to S3: {}", e))?;
        
        Ok(StateSaveResponse {
            state_hash,
            object_key,
        })
    }

    /// Load state from S3 with decryption.
    pub async fn load(&self) -> Result<StateLoadResponse> {
        let object_key = self.get_object_key();
        
        // Download from S3
        let response = self.s3_client
            .get_object()
            .bucket(&self.config.s3_bucket)
            .key(&object_key)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to download state from S3: {}", e))?;
        
        let encrypted_blob = response.body.collect().await
            .map_err(|e| anyhow!("Failed to read S3 response body: {}", e))?
            .into_bytes()
            .to_vec();
        
        if encrypted_blob.len() < 32 {
            return Err(anyhow!("Invalid encrypted blob: too short"));
        }
        
        // Calculate state hash
        let state_hash = Self::keccak256(&encrypted_blob);
        
        // Split nonce and ciphertext
        let nonce = &encrypted_blob[..32];
        let ciphertext = &encrypted_blob[32..];
        
        // Decrypt using our own public key
        let our_pubkey_der = self.encryption_key.public_key_as_der()?;
        let plaintext = self.encryption_key.decrypt(nonce, &our_pubkey_der, ciphertext)?;
        
        // Deserialize the data
        let data: serde_json::Value = serde_json::from_slice(&plaintext)?;
        
        Ok(StateLoadResponse {
            data,
            state_hash,
        })
    }
}
