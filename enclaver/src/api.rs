use anyhow::Result;
use async_trait::async_trait;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::{Method, Request, Response, StatusCode};
use pkcs8::{DecodePublicKey, SubjectPublicKeyInfo};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::eth_key::EthKey;
use crate::http_util::{self, HttpHandler};
use crate::nsm::{AttestationParams, AttestationProvider};

const MIME_APPLICATION_CBOR: &str = "application/cbor";

pub struct ApiHandler {
    attester: Box<dyn AttestationProvider + Send + Sync>,
    eth_key: Arc<EthKey>,
}

impl ApiHandler {
    pub fn new(attester: Box<dyn AttestationProvider + Send + Sync>) -> Result<Self> {
        let eth_key = Arc::new(EthKey::new());
        log::info!("Enclave Ethereum address: {}", eth_key.address());
        Ok(Self { attester, eth_key })
    }

    async fn handle_request(
        &self,
        head: &hyper::http::request::Parts,
        body: Bytes,
    ) -> Result<Response<Full<Bytes>>> {
        match head.uri.path() {
            "/v1/attestation" => match head.method {
                Method::POST => self.handle_attestation(head, body).await,
                _ => Ok(http_util::method_not_allowed()),
            },
            "/v1/eth/address" => match head.method {
                Method::GET => self.handle_eth_address().await,
                _ => Ok(http_util::method_not_allowed()),
            },
            "/v1/eth/sign" => match head.method {
                Method::POST => self.handle_eth_sign(head, body).await,
                _ => Ok(http_util::method_not_allowed()),
            },
            _ => Ok(http_util::not_found()),
        }
    }

    async fn handle_attestation(
        &self,
        _head: &hyper::http::request::Parts,
        body: Bytes,
    ) -> Result<Response<Full<Bytes>>> {
        let attestation_req: AttestationRequest = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(err) => return Ok(http_util::bad_request(err.to_string())),
        };

        let params = match attestation_req.into_params(&self.eth_key) {
            Ok(params) => params,
            Err(err) => return Ok(http_util::bad_request(err.to_string())),
        };

        let att_doc = self.attester.attestation(params)?;

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, MIME_APPLICATION_CBOR)
            .body(Full::new(Bytes::from(att_doc)))?)
    }

    async fn handle_eth_address(&self) -> Result<Response<Full<Bytes>>> {
        let response = json::object! {
            address: self.eth_key.address(),
            public_key: self.eth_key.public_key_hex(),
        };
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json::stringify(response))))?)
    }

    async fn handle_eth_sign(
        &self,
        _head: &hyper::http::request::Parts,
        body: Bytes,
    ) -> Result<Response<Full<Bytes>>> {
        let req: EthSignRequest = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(err) => return Ok(http_util::bad_request(err.to_string())),
        };

        let msg_hash = match hex::decode(req.message_hash.trim_start_matches("0x")) {
            Ok(hash) if hash.len() == 32 => hash,
            _ => return Ok(http_util::bad_request("Invalid message hash".to_string())),
        };

        let signature = self.eth_key.sign_message(&msg_hash);

        let attestation = if req.include_attestation {
            let att_doc = self.attester.attestation(AttestationParams {
                nonce: Some(msg_hash.clone()),
                public_key: Some(self.eth_key.public_key_as_der()?),
                user_data: Some(self.eth_key.address_bytes()),
            })?;

            Some(base64::encode(att_doc))
        } else {
            None
        };

        let response = EthSignResponse {
            signature: format!("0x{}", hex::encode(signature)),
            address: self.eth_key.address(),
            attestation,
        };

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(serde_json::to_string(&response)?)))?)
    }
}

#[async_trait]
impl HttpHandler for ApiHandler {
    async fn handle(&self, req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>> {
        let (head, body) = req.into_parts();
        let body = body.collect().await?.to_bytes();

        self.handle_request(&head, body).await
    }
}

#[derive(Deserialize)]
struct AttestationRequest {
    nonce: Option<String>,
    public_key: Option<String>,
    user_data: Option<String>,
}

impl AttestationRequest {
    fn into_params(self, eth_key: &EthKey) -> Result<AttestationParams> {
        let nonce = self.nonce.map(base64::decode).transpose()?;

        let public_key = match self.public_key {
            Some(pem) => Some(pem_decode(&pem)?),
            None => Some(eth_key.public_key_as_der()?),
        };

        let user_data = match self.user_data {
            Some(b64) => Some(base64::decode(b64)?),
            None => {
                // Store ETH address as raw 20 bytes (not string)
                // This matches tee-tls format where get_address_bytes() returns 20 bytes
                Some(eth_key.address_bytes())
            }
        };

        Ok(AttestationParams {
            nonce,
            public_key,
            user_data,
        })
    }
}

#[derive(Deserialize)]
struct EthSignRequest {
    message_hash: String,
    include_attestation: bool,
}

#[derive(Serialize)]
struct EthSignResponse {
    signature: String,
    address: String,
    attestation: Option<String>,
}

struct DerPublicKey {
    bytes: Vec<u8>,
}

impl<'a> TryFrom<SubjectPublicKeyInfo<'a>> for DerPublicKey {
    type Error = pkcs8::spki::Error;

    fn try_from(spki: SubjectPublicKeyInfo<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: spki.subject_public_key.to_vec(),
        })
    }
}

impl DecodePublicKey for DerPublicKey {}

impl DerPublicKey {
    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

fn pem_decode(pem: &str) -> Result<Vec<u8>> {
    let der = DerPublicKey::from_public_key_pem(pem)?;
    Ok(der.into_bytes())
}

#[tokio::test]
async fn test_attestation_handler() {
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler = ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new()))).unwrap();

    let body = json::object!(
        public_key: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyY9b3O0t0zDH3pcxYWW2\nTBjW302L3eL+S4C1rmW6OFIXa6U1ZrBtSvMvI3ievCVHq7AOof6xkbXXqobgbokc\n0514+7stOsq/CqnXGWhWwW+aCIj5FFi+gf4kXbXvUYKhUVFFJm5Rq71r5stt3B1p\njYC0Nm391GjR98gO9Sw8TGYx21Q7KuNFsfMa/dtYboFX38fQFw4eTHvSafErgZNO\nMUmzLPibM+1zXqHbXX1M5hyFMBJE28zNi+TmvopdMxsG/a2yTiM1j6Srw2Y5ZrE6\nO1Rr8MxrAepPbmybNOn0K0YIcf/KZurDuvOIuhsurxFgGTVQhsMZ0iNaXA0usFM+\npQIDAQAB\n-----END PUBLIC KEY-----".to_string(),
    );

    let req = Request::builder()
        .method("POST")
        .uri("/v1/attestation")
        .body(Bytes::from(json::stringify(body)))
        .unwrap();

    let (head, body) = req.into_parts();

    let resp = handler.handle_request(&head, body).await.unwrap();
    assert!(resp.status() == StatusCode::OK);

    let body = json::object!(
        nonce: base64::encode("the nonce"),
        user_data: base64::encode("my data"),
    );

    let req = Request::builder()
        .method("POST")
        .uri("/v1/attestation")
        .body(Bytes::from(json::stringify(body)))
        .unwrap();

    let (head, body) = req.into_parts();

    let resp = handler.handle_request(&head, body).await.unwrap();
    assert!(resp.status() == StatusCode::OK);
}

#[tokio::test]
async fn test_eth_address_handler() {
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler = ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new()))).unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/v1/eth/address")
        .body(Bytes::new())
        .unwrap();

    let (head, body) = req.into_parts();
    let resp = handler.handle_request(&head, body).await.unwrap();

    assert!(resp.status() == StatusCode::OK);
    assert!(resp.headers().get(CONTENT_TYPE).unwrap() == "application/json");

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(response["address"].as_str().unwrap().starts_with("0x"));
    assert!(response["address"].as_str().unwrap().len() == 42);
    assert!(response["public_key"].as_str().unwrap().starts_with("0x"));
    assert!(response["public_key"].as_str().unwrap().len() == 132);
}

#[tokio::test]
async fn test_eth_sign_handler() {
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler = ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new()))).unwrap();

    let message_hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let body = json::object! {
        message_hash: message_hash,
        include_attestation: false,
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/eth/sign")
        .body(Bytes::from(json::stringify(body)))
        .unwrap();

    let (head, body) = req.into_parts();
    let resp = handler.handle_request(&head, body).await.unwrap();

    assert!(resp.status() == StatusCode::OK);
    assert!(resp.headers().get(CONTENT_TYPE).unwrap() == "application/json");

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(response["signature"].as_str().unwrap().starts_with("0x"));
    assert!(response["signature"].as_str().unwrap().len() == 132);
    assert!(response["address"].as_str().unwrap().starts_with("0x"));
    assert!(response["address"].as_str().unwrap().len() == 42);
    assert!(response["attestation"].is_null());
}

#[tokio::test]
async fn test_eth_sign_with_attestation() {
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler = ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new()))).unwrap();

    let message_hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let body = json::object! {
        message_hash: message_hash,
        include_attestation: true,
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/eth/sign")
        .body(Bytes::from(json::stringify(body)))
        .unwrap();

    let (head, body) = req.into_parts();
    let resp = handler.handle_request(&head, body).await.unwrap();

    assert!(resp.status() == StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(response["signature"].as_str().unwrap().starts_with("0x"));
    assert!(response["address"].as_str().unwrap().starts_with("0x"));
    assert!(response["attestation"].is_string());
}

#[tokio::test]
async fn test_eth_sign_invalid_hash() {
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;

    let handler = ApiHandler::new(Box::new(StaticAttestationProvider::new(Vec::new()))).unwrap();

    let body = json::object! {
        message_hash: "0xinvalid",
        include_attestation: false,
    };

    let req = Request::builder()
        .method("POST")
        .uri("/v1/eth/sign")
        .body(Bytes::from(json::stringify(body)))
        .unwrap();

    let (head, body) = req.into_parts();
    let resp = handler.handle_request(&head, body).await.unwrap();

    assert!(resp.status() == StatusCode::BAD_REQUEST);
}
