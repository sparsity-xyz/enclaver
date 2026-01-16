use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error, RootCertStore, ServerConfig, SignatureScheme,
};

static CRYPTO_PROVIDER_INIT: LazyLock<()> =
    LazyLock::new(|| aws_lc_rs::default_provider().install_default().unwrap());

fn init_crypto_provider() {
    LazyLock::force(&CRYPTO_PROVIDER_INIT);
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    Ok(rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))?;
    Ok(key)
}

pub fn load_server_config<P1: AsRef<Path>, P2: AsRef<Path>>(
    key: P1,
    cert: P2,
) -> Result<Arc<ServerConfig>> {
    init_crypto_provider();

    let certs = load_certs(cert.as_ref())?;
    let key = load_key(key.as_ref())?;

    Ok(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    ))
}

/// OID for Nova Attestation Extension (1.3.6.1.4.1.99999.1)
/// This is a private enterprise OID space for Nova platform.
pub const NOVA_ATTESTATION_OID: &str = "1.3.6.1.4.1.99999.1";

/// Generate an RA-TLS server configuration with embedded attestation document.
/// 
/// This creates a self-signed certificate with the attestation document
/// embedded in a custom X.509 extension.
#[cfg(feature = "odyn")]
pub fn generate_ratls_server_config(
    attestation_doc: &[u8],
) -> Result<(Arc<ServerConfig>, Vec<u8>, Vec<u8>)> {
    use rand::rngs::OsRng;
    use p384::SecretKey;
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    
    init_crypto_provider();
    
    // Generate a new P-384 key pair for the TLS certificate
    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();
    let public_key_bytes = public_key.to_encoded_point(false);
    
    // Build a self-signed certificate with embedded attestation
    // For now, we create a simple DER certificate structure
    // In production, this should use a proper X.509 library like rcgen
    
    let cert_der = build_ratls_certificate(public_key_bytes.as_bytes(), attestation_doc)?;
    let key_der = secret_key.to_sec1_der()
        .map_err(|e| anyhow!("Failed to serialize private key: {}", e))?
        .to_vec();
    
    // Parse the certificate for rustls
    let cert = CertificateDer::from(cert_der.clone());
    let private_key = PrivateKeyDer::try_from(key_der.clone())
        .map_err(|e| anyhow!("Failed to parse private key DER: {:?}", e))?;
    
    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], private_key)?,
    );
    
    Ok((config, cert_der, key_der))
}

/// Build a minimal X.509 certificate with embedded attestation.
/// 
/// This creates a DER-encoded certificate with:
/// - Subject: CN=Nova RA-TLS
/// - Validity: 1 year
/// - Extension: Nova Attestation (OID 1.3.6.1.4.1.99999.1)
#[cfg(feature = "odyn")]
fn build_ratls_certificate(public_key: &[u8], attestation: &[u8]) -> Result<Vec<u8>> {
    // For a proper implementation, use rcgen crate
    // This is a placeholder that returns a minimal certificate structure
    // 
    // TODO: Replace with rcgen-based implementation:
    // let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
    // params.custom_extensions.push(rcgen::CustomExtension::from_oid_content(
    //     &NOVA_ATTESTATION_OID.split('.').map(|s| s.parse().unwrap()).collect::<Vec<u64>>(),
    //     attestation.to_vec()
    // ));
    // let cert = rcgen::Certificate::from_params(params)?;
    // Ok(cert.serialize_der()?)
    
    log::info!("RA-TLS certificate generation: public_key len={}, attestation len={}", 
               public_key.len(), attestation.len());
    
    // For now, return an error indicating this needs proper implementation
    Err(anyhow!(
        "RA-TLS certificate generation requires rcgen crate. \
         Add 'rcgen = \"0.12\"' to Cargo.toml and implement proper X.509 generation."
    ))
}


pub fn load_client_config(cert: impl AsRef<Path> + 'static) -> Result<Arc<ClientConfig>> {
    init_crypto_provider();

    let mut roots = RootCertStore::empty();
    let mut certs = load_certs(cert.as_ref())?;
    roots.add(certs.remove(0))?;

    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

// from rustls example code
#[derive(Debug)]
pub struct NoCertificateVerification {}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Just say that we support all schemes
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

pub fn load_insecure_client_config() -> Result<Arc<ClientConfig>> {
    let roots = RootCertStore::empty();

    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    cfg.dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification {}));

    Ok(Arc::new(cfg))
}

#[cfg(test)]
fn data_file(name: &str) -> Result<std::path::PathBuf> {
    let mut path = std::path::PathBuf::from(file!()).canonicalize()?;
    path.pop(); // pop the filename of the .rs file
    path.push(name);
    Ok(path)
}

#[cfg(test)]
pub fn test_server_config() -> Result<Arc<ServerConfig>> {
    load_server_config(data_file("test.key")?, data_file("test.crt")?)
}
