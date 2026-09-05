use ed25519_dalek::SigningKey;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use x509_cert::der::Decode;
use x509_cert::spki::ObjectIdentifier;

/// id-Ed25519 (RFC 8410). The only key type a sQUIC identity can have.
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

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
    // No 0-RTT, and not "for now": a 0-RTT datagram carries no envelope and
    // cannot be given one, so accepting it would take application data from a
    // caller who passed no gate, no MAC1 and no whitelist (SIP-6). The
    // transport drops it as well — see `is_quic_zero_rtt`; this is the outer
    // half of the same refusal.
    config.max_early_data_size = 0;
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
        // Pin on the SubjectPublicKeyInfo, and on nothing else.
        //
        // The SPKI is the key that signs CertificateVerify, so it is the only
        // field whose value the peer must hold a private key for. Every other
        // byte of the certificate is chosen freely by whoever presented it.
        //
        // This has been got wrong twice. An early version searched for the
        // Ed25519 OID and read the key after it, which was fragile because the
        // OID appears twice in a self-signed certificate. Its replacement
        // scanned every 32-byte window of the DER for the pinned key, which is
        // not fragile but unsound: an attacker self-signs with a key of their
        // own, pastes the pinned key into a custom extension, and the scan
        // hits — after which rustls verifies CertificateVerify against the
        // certificate's own key, which the attacker holds. Both checks pass
        // and the client has authenticated an impostor. `rejects_a_certificate_
        // that_merely_contains_the_pinned_key` below is that attack.
        //
        // Parsing the structure is what squic-go has always done
        // (`x509.ParseCertificate`, then compare `cert.PublicKey`), and it is
        // what SIP-9 requires.
        let cert = x509_cert::Certificate::from_der(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("server certificate does not parse".into()))?;
        let spki = &cert.tbs_certificate.subject_public_key_info;

        if spki.algorithm.oid != ED25519_OID {
            return Err(rustls::Error::General(
                "server public key is not Ed25519".into(),
            ));
        }

        let key = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| rustls::Error::General("server public key is not whole bytes".into()))?;

        if key.len() != 32 || !constant_time_eq(key, &self.expected_pub) {
            return Err(rustls::Error::General(
                "server public key does not match pinned key".into(),
            ));
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{ServerName, UnixTime};

    fn keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    /// Build a self-signed certificate for `signing_key`, carrying `smuggled`
    /// verbatim inside a custom extension. That is the attacker's tool: a
    /// certificate whose *own* key is one the attacker controls, but whose DER
    /// contains any 32 bytes they choose.
    fn cert_smuggling(signing_key: &SigningKey, smuggled: &[u8]) -> CertificateDer<'static> {
        let pkcs8 = signing_key.to_pkcs8_der();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8));
        let key_pair = KeyPair::from_der_and_sign_algo(&key_der, &PKCS_ED25519).unwrap();

        let mut params = CertificateParams::new(vec!["squic".to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "squic");
        // An arbitrary private-enterprise OID; the content is what matters.
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 99999, 1],
                smuggled.to_vec(),
            ));

        let cert = params.self_signed(&key_pair).unwrap();
        CertificateDer::from(cert.der().to_vec())
    }

    fn verify(pinned: [u8; 32], cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let verifier = PinnedKeyVerifier {
            expected_pub: pinned,
        };
        verifier
            .verify_server_cert(
                cert,
                &[],
                &ServerName::try_from("squic").unwrap(),
                &[],
                UnixTime::now(),
            )
            .map(|_| ())
    }

    #[test]
    fn accepts_the_pinned_key() {
        let (sk, pk) = keypair();
        let (certs, _) = self_signed_cert(&sk).unwrap();
        assert!(verify(pk, &certs[0]).is_ok());
    }

    #[test]
    fn rejects_a_different_key() {
        let (sk, _) = keypair();
        let (_, other_pk) = keypair();
        let (certs, _) = self_signed_cert(&sk).unwrap();
        assert!(verify(other_pk, &certs[0]).is_err());
    }

    /// The pin must be on the key that signs the handshake — the
    /// SubjectPublicKeyInfo — and not on the certificate's bytes as a whole.
    ///
    /// An attacker who holds no part of the pinned identity can self-sign a
    /// certificate with their *own* key and paste the pinned key into any field
    /// they like. A verifier that searches the DER for the pinned bytes accepts
    /// it, and rustls then checks CertificateVerify against the certificate's
    /// own key — which the attacker holds. Both checks pass and the client has
    /// authenticated an impostor.
    #[test]
    fn rejects_a_certificate_that_does_not_parse() {
        let (_, pk) = keypair();
        let junk = CertificateDer::from(vec![0x30, 0x82, 0xff, 0xff, 0x00]);
        assert!(verify(pk, &junk).is_err());
    }

    /// A sQUIC identity is an Ed25519 key. A certificate carrying any other key
    /// type cannot be the pinned identity, whatever else it contains.
    #[test]
    fn rejects_a_non_ed25519_key() {
        let (_, pk) = keypair();
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["squic".to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "squic");
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 99999, 1],
                pk.to_vec(),
            ));
        let cert = params.self_signed(&key_pair).unwrap();
        let der = CertificateDer::from(cert.der().to_vec());

        assert!(verify(pk, &der).is_err());
    }

    #[test]
    fn rejects_a_certificate_that_merely_contains_the_pinned_key() {
        let (_victim_sk, victim_pk) = keypair();
        let (attacker_sk, attacker_pk) = keypair();
        assert_ne!(victim_pk, attacker_pk);

        let cert = cert_smuggling(&attacker_sk, &victim_pk);
        // The bytes really are in there, or the test proves nothing.
        assert!(
            cert.as_ref().windows(32).any(|w| w == victim_pk),
            "test setup failed: the pinned key is not present in the DER"
        );

        assert!(
            verify(victim_pk, &cert).is_err(),
            "a certificate signed by a key the attacker controls was accepted \
             because it happened to contain the pinned key"
        );
    }
}
