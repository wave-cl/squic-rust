use ed25519_dalek::SigningKey;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;

/// Create a self-signed TLS certificate from an Ed25519 signing key.
/// Returns (cert chain, private key DER).
pub fn self_signed_cert(
    signing_key: &SigningKey,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), crate::Error> {
    // Export the Ed25519 private key as PKCS#8 DER
    let pkcs8 = signing_key.to_pkcs8_der();

    let key_der_for_rcgen = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.clone()));
    let key_pair = KeyPair::from_der_and_sign_algo(&key_der_for_rcgen, &PKCS_ED25519)
        .map_err(|e| crate::Error::Tls(format!("keypair from DER: {e}")))?;

    let mut params = CertificateParams::new(vec!["squic".to_string()])
        .map_err(|e| crate::Error::Tls(format!("cert params: {e}")))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "squic");

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| crate::Error::Tls(format!("self-sign: {e}")))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8));

    Ok((vec![cert_der], key_der))
}

/// Build a rustls ServerConfig with the given cert and ALPN protocols.
pub fn server_tls_config(
    signing_key: &SigningKey,
    alpn: &[Vec<u8>],
) -> Result<Arc<rustls::ServerConfig>, crate::Error> {
    let (certs, key) = self_signed_cert(signing_key)?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| crate::Error::Tls(format!("server config: {e}")))?;

    config.alpn_protocols = alpn.to_vec();
    config.max_early_data_size = 0; // No 0-RTT for now
    Ok(Arc::new(config))
}

/// Build a rustls ClientConfig that pins the server's Ed25519 public key.
pub fn client_tls_config(
    server_pub_key: &[u8; 32],
    alpn: &[Vec<u8>],
) -> Result<Arc<rustls::ClientConfig>, crate::Error> {
    let verifier = Arc::new(PinnedKeyVerifier {
        expected_pub: *server_pub_key,
    });

    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    config.alpn_protocols = alpn.to_vec();
    Ok(Arc::new(config))
}

/// Custom certificate verifier that pins the server's Ed25519 public key.
#[derive(Debug)]
struct PinnedKeyVerifier {
    expected_pub: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for PinnedKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Search for the expected 32-byte Ed25519 public key anywhere in the
        // DER-encoded certificate.  The Ed25519 OID (1.3.101.112) appears
        // twice in a self-signed cert (SubjectPublicKeyInfo and signature
        // AlgorithmIdentifier), so the old approach of searching after the
        // *first* OID hit was fragile.  Instead, we simply scan all 32-byte
        // windows of the DER bytes for the expected key.  This mirrors the Go
        // implementation which extracts the key via x509.ParseCertificate and
        // compares directly.
        let der = end_entity.as_ref();
        if der.len() < 32 {
            return Err(rustls::Error::General("cert too short".into()));
        }

        for window in der.windows(32) {
            if constant_time_eq(window, &self.expected_pub) {
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
        }

        Err(rustls::Error::General(
            "server public key does not match pinned key".into(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut r = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        r |= x ^ y;
    }
    r == 0
}

/// Helper: export Ed25519 signing key as PKCS#8 DER bytes.
trait ToPkcs8Der {
    fn to_pkcs8_der(&self) -> Vec<u8>;
}

impl ToPkcs8Der for SigningKey {
    fn to_pkcs8_der(&self) -> Vec<u8> {
        // PKCS#8 wrapper for Ed25519:
        // SEQUENCE {
        //   INTEGER 0
        //   SEQUENCE { OID 1.3.101.112 }
        //   OCTET STRING { OCTET STRING { 32-byte seed } }
        // }
        let seed = self.to_bytes();
        let mut der = Vec::with_capacity(48);
        // Outer SEQUENCE
        der.push(0x30);
        der.push(46); // total inner length
        // Version INTEGER 0
        der.extend_from_slice(&[0x02, 0x01, 0x00]);
        // AlgorithmIdentifier SEQUENCE { OID }
        der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
        // PrivateKey OCTET STRING wrapping OCTET STRING wrapping seed
        der.push(0x04); // OCTET STRING tag
        der.push(34); // length of inner octet string
        der.push(0x04); // inner OCTET STRING tag
        der.push(32); // length of seed
        der.extend_from_slice(&seed);
        der
    }
}
