// src/lib.rs
use k256::ecdsa::{SigningKey, VerifyingKey, Signature, RecoveryId};
use rand::rngs::OsRng;
use sha3::{Digest, Keccak256};
use hex;


pub struct EthKey {
    signing_key: SigningKey,
    verify_key: VerifyingKey,
}

impl EthKey {
    /// generate new key
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let verify_key = VerifyingKey::from(&signing_key);
        Self { signing_key, verify_key }
    }

    /// import key from hex
    pub fn new_from_bytes(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
            .map_err(|e| format!("Invalid hex: {}", e))?;

        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Private key must be 32 bytes".to_string())?;

        let signing_key = SigningKey::from_bytes(&arr.into())
            .map_err(|e| format!("Invalid private key: {:?}", e))?;
        let verify_key = VerifyingKey::from(&signing_key);
        Ok(Self { signing_key, verify_key })
    }

    /// private key hex
    pub fn private_key_hex(&self) -> String {
        format!("0x{}", hex::encode(self.signing_key.to_bytes()))
    }

    /// uncompressed public key
    pub fn public_key_hex(&self) -> String {
        format!(
            "0x{}",
            hex::encode(self.verify_key.to_encoded_point(false).as_bytes())
        )
    }

    /// Ethereum address
    pub fn address(&self) -> String {
        let pub_bytes = self.verify_key.to_encoded_point(false);
        let hash = Self::keccak256(&pub_bytes.as_bytes()[1..]);
        format!("0x{}", hex::encode(&hash[12..]))
    }

    /// Keccak256 hash
    fn keccak256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    fn sign_message(&self, message: &[u8]) -> String {
        let digest = Keccak256::new_with_prefix(message);
        let (sig, recid) = self.signing_key.sign_digest_recoverable(digest.clone()).unwrap();

        let mut result = [0u8; 65];
        result[..64].copy_from_slice(sig.to_bytes().as_ref());
        result[64] = recid.to_byte();
        format!("0x{}", hex::encode(result))
    }

    pub fn verify_message(sig_hex: String, message: &[u8], address: String) -> bool {
        let sig_bytes: Vec<u8> = hex::decode(sig_hex.strip_prefix("0x").unwrap_or(&sig_hex))
            .expect("invalid hex");
        let digest = Keccak256::new_with_prefix(message);
        let r_s = &sig_bytes[..64];
        let sig = Signature::from_bytes(r_s.into()).unwrap();
        let recid = RecoveryId::from_byte(sig_bytes[64]).expect("invalid recovery id");
        let verifying_key =
            VerifyingKey::recover_from_digest(digest.clone(), &sig, recid).unwrap();
        let pub_bytes = verifying_key.to_encoded_point(false);
        let hash = Self::keccak256(&pub_bytes.as_bytes()[1..]);
        format!("0x{}", hex::encode(&hash[12..])) == address.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_address() {
        let key = EthKey::new();
        println!("Private Key: {}", key.private_key_hex());
        println!("Public Key: {}", key.public_key_hex());
        println!("Address: {}", key.address());

        assert_eq!(key.private_key_hex().len(), 66);
        assert_eq!(key.public_key_hex().len(), 132);
        assert_eq!(key.address().len(), 42);
    }

    #[test]
    fn test_from_and_address() {
        let pk = "0x2151833c4e545b28d64d87ed80dcc735a14d70f537e8885b227a5dbe7994da26";
        let key = EthKey::new_from_bytes(&pk).unwrap();
        println!("Private Key: {}", key.private_key_hex());
        println!("Public Key: {}", key.public_key_hex());
        println!("Address: {}", key.address());

        assert_eq!(key.private_key_hex(), "0x2151833c4e545b28d64d87ed80dcc735a14d70f537e8885b227a5dbe7994da26");
        assert_eq!(key.public_key_hex(), "0x047df31522e92da43df5e709bbae0a5c3cb9cf746973cf98eae0f7bdd865809a5c91a2df421125debc451cdd0a41791f333fced9d69f9eeb14bfdbacbff9a7ccb1");
        assert_eq!(key.address(), "0xd30077d0ee91bc6907a1666f1d2054b4322a2b0f");
    }

    #[test]
    fn test_sign_verify() {
        let message = "Hello, Ethereum!";
        let pk = "0x2151833c4e545b28d64d87ed80dcc735a14d70f537e8885b227a5dbe7994da26";
        let key = EthKey::new_from_bytes(&pk).unwrap();

        let sig = key.sign_message(message.as_bytes());
        println!("Signature: {}", sig);

        let verified = EthKey::verify_message(sig, message.as_bytes(), key.address());
        println!("verified: {}", verified);
    }

}
