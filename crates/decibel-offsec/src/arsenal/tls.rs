//! TLS inspection (style of testssl/sslscan-lite): connect, complete the
//! handshake accepting ANY certificate (we are inspecting, not trusting), and
//! report the negotiated protocol/cipher plus the leaf certificate's subject,
//! issuer, validity window, serial, and SANs.
//!
//! Also exposes `connect` so the HTTP prober can speak HTTPS over the same
//! accept-any TLS stack. Pure-Rust (rustls + ring), no OpenSSL/C.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{ring, CryptoProvider};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio_rustls::TlsConnector;
use x509_parser::extensions::GeneralName;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub host: String,
    pub port: u16,
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial: String,
    pub sans: Vec<String>,
}

/// A certificate verifier that accepts everything. Correct for recon (we want
/// the cert details of arbitrary/self-signed/expired targets), NOT for a trust
/// decision.
#[derive(Debug)]
struct AcceptAny {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn accept_any_config() -> Result<ClientConfig, String> {
    let provider = Arc::new(ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny { provider }))
        .with_no_client_auth();
    Ok(config)
}

/// Open a TLS connection to `host:port`, accepting any certificate.
pub async fn connect(host: &str, port: u16, timeout_ms: u64) -> Result<TlsStream<TcpStream>, String> {
    let dur = Duration::from_millis(timeout_ms);
    let tcp = timeout(dur, TcpStream::connect((host, port)))
        .await
        .map_err(|_| format!("connect timeout: {host}:{port}"))?
        .map_err(|e| format!("connect: {e}"))?;

    let connector = TlsConnector::from(Arc::new(accept_any_config()?));
    let server_name = ServerName::try_from(host.to_string()).map_err(|e| format!("bad server name: {e}"))?;
    let tls = timeout(dur, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "tls handshake timeout".to_string())?
        .map_err(|e| format!("tls handshake: {e}"))?;
    Ok(tls)
}

/// Inspect the TLS endpoint: negotiated params + leaf certificate details.
pub async fn inspect(host: &str, port: u16, timeout_ms: u64) -> Result<TlsInfo, String> {
    let tls = connect(host, port, timeout_ms).await?;

    let (_io, conn) = tls.get_ref();
    let protocol = conn.protocol_version().map(|v| format!("{v:?}"));
    let cipher = conn.negotiated_cipher_suite().map(|c| format!("{:?}", c.suite()));
    let certs: Vec<CertificateDer<'static>> = conn
        .peer_certificates()
        .map(|c| c.iter().map(|d| d.clone().into_owned()).collect())
        .unwrap_or_default();

    let mut info = TlsInfo {
        host: host.to_string(),
        port,
        protocol,
        cipher,
        subject: String::new(),
        issuer: String::new(),
        not_before: String::new(),
        not_after: String::new(),
        serial: String::new(),
        sans: Vec::new(),
    };

    if let Some(leaf) = certs.first() {
        let (_, cert) =
            x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|e| format!("parse cert: {e}"))?;
        info.subject = cert.subject().to_string();
        info.issuer = cert.issuer().to_string();
        info.not_before = cert.validity().not_before.to_string();
        info.not_after = cert.validity().not_after.to_string();
        info.serial = cert.raw_serial_as_string();
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in &san.value.general_names {
                if let GeneralName::DNSName(d) = name {
                    info.sans.push(d.to_string());
                }
            }
        }
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;

    const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDSDCCAjCgAwIBAgIUBZljv8WfI5KkpIVVilsqCvsCwzwwDQYJKoZIhvcNAQEL\n\
BQAwGjEYMBYGA1UEAwwPZGVjZXB0aWNvbi50ZXN0MB4XDTI2MDgyMjIxMDE0MVoX\n\
DTM2MDgxOTIxMDE0MVowGjEYMBYGA1UEAwwPZGVjZXB0aWNvbi50ZXN0MIIBIjAN\n\
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo8IeAcNCaXGmi3k7xrjuKeUyLMRr\n\
nck9drg53Fmhvn9L8a2X1VrfOMNo5IDtDUx3/oCf8JIm5iUjV6HjcaSfeFIlT0dt\n\
Qe24VZv0GgX0d7LuAA8G4O++NGgHW5pRWwpzn+YNg3k7oHujMyzsJitqQQb3MCxx\n\
fozrcEaoeL4zuIiI2AUk3PhWvPwj8P5Q+l/xDH6+kkXR92kawVCGBdPuRGvETWsR\n\
fLj/5r9stcmaO+RM2LFwtEve9BGji/+t5zWQJOsaDln2HYBIf8S3oZufSAtUp+P9\n\
wIKbTzA8MNPc1U5f/U87D20JZR3aCxT7sNpGLPBCfHA/+ndTrKPz2JqXxQIDAQAB\n\
o4GFMIGCMB0GA1UdDgQWBBRDWC10W6eZQe1uuPMHsYs5b5Gn0DAfBgNVHSMEGDAW\n\
gBRDWC10W6eZQe1uuPMHsYs5b5Gn0DAPBgNVHRMBAf8EBTADAQH/MC8GA1UdEQQo\n\
MCaCD2RlY2VwdGljb24udGVzdIITd3d3LmRlY2VwdGljb24udGVzdDANBgkqhkiG\n\
9w0BAQsFAAOCAQEAKrBHk7xBi81WXMVB+MlfSFDBZ/JfqLzwn2kKsVUYBTjlkl0A\n\
6hrUj4kqnC92cnEEpjDZOGXJL3Tx5HISupGpMWD2Wg0D0NXU6lxv49C3uVRtgrNo\n\
RzF4X876uT4IL0RA6ruvD2qWFriHr4Gfn4D32oWNEzE8igx2YDCEqFg0ZplKqAtb\n\
JxeXPd/CG2evQicuul02TfVmtZ0+olDjJcw71I57t2kH6oRt2mG/DwT6PGUg1Wpn\n\
7J+qxPol6wt0VFoLNX9Udr3dFwPg24cdBUgm62MUNXX8iXpN+n3IAAbUREQnjiV8\n\
NkWAq2iZvNz1xAUSy/TbI2rY4BcpvdrzPy1MyA==\n\
-----END CERTIFICATE-----\n";

    const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCjwh4Bw0JpcaaL\n\
eTvGuO4p5TIsxGudyT12uDncWaG+f0vxrZfVWt84w2jkgO0NTHf+gJ/wkibmJSNX\n\
oeNxpJ94UiVPR21B7bhVm/QaBfR3su4ADwbg7740aAdbmlFbCnOf5g2DeTuge6Mz\n\
LOwmK2pBBvcwLHF+jOtwRqh4vjO4iIjYBSTc+Fa8/CPw/lD6X/EMfr6SRdH3aRrB\n\
UIYF0+5Ea8RNaxF8uP/mv2y1yZo75EzYsXC0S970EaOL/63nNZAk6xoOWfYdgEh/\n\
xLehm59IC1Sn4/3AgptPMDww09zVTl/9TzsPbQllHdoLFPuw2kYs8EJ8cD/6d1Os\n\
o/PYmpfFAgMBAAECggEADJHCHd6FQsoEv4s0VGIuHaxy986yd++nYRfDkS9BY/l/\n\
Xx3fm/JtVH0N7blw+JFYWyziRI6N9SJVSSJVmTZ1QGtbDm/BaiBmArmFY1ihABhi\n\
05b+WdZCYja4lzEMHOcmItgp91/J0jKglIqr1u4u1K5FMOm9uGShTwKNZzR/jHgG\n\
913k94xhMHhaWrkEgIH1/9g5sNhqim8oYX1wCaa/CsixT3My2+JuAuCpFZKmfFxz\n\
dWzkDWe9ph2cGhMpVnD1eWH2UcSA2A5Eu8ADOBJ7o9SRSzv1EjluddvD+ZT4G9iZ\n\
xBIXcuUbvxdbrF/O0rnCJK70N5JtmfImMlhlnTavAQKBgQDOsWozLBrBPG50it+m\n\
NGNEymXFqjpAciWG2Ywz0sW9ZtiYasxkU7gIFVDnNtmybXJgjCw/2Yx1jZk6iOvt\n\
oc1WS3e5Rx0U3Z/2Qn8JkwerrsYt+qOStGLJkMfeZEDHxTzSRfeAwggK1yxNd/cV\n\
7MTTJELA0yFJvsNmxvg1ngoPwQKBgQDK0rWpeHo06w7oMJAxrSU9yH1r3b4kp6GD\n\
9dsk+DPDpJK+FqwyoHKlv6/4NbfWWaLFVua5nj+e+qcMqRIvtZLGfteQbR5QYnFS\n\
OLAcsLLfyTupejY9x2Dohz883ytuucE7pTLffNBTRzu6BGkAwxZWkC3kq0KngJr2\n\
5cbAXnqJBQKBgF8oVthQSdEE3WVSOjzuiXU2KTyjbkYVRymaJm4Fb3wPSVCCeq8F\n\
zAgMqD6KhhcbRDkmz4hlw8Cq/Axy1QuGHl7IR8pI7x6YGfjqDEqAIlvsDtlENuJn\n\
ocNioGHGjfxq1eGIzLW+nq0++up/fIXfh44dd44GpaCp7pP2rncg10kBAoGAHKkr\n\
7JfOxR2WTK9YIPzzr0hemNiL3wglJc2fOxkrz3C5H816ZekQamWtCykkIlEmVDaU\n\
ghRfryqCYqKdpEpHRG92LL2OtBNFKjZChLtfe4onOSrA8Xf0NMev4v0yWQI80R3m\n\
E3jCw5HkWcP3xpjK1k6nfZHJ6Hue6lbMADEZpbUCgYAgjqCTpZXZMNcsa+iCyhde\n\
yVnsGwbfxvKrzt2Cz0W/RIhjUyhoyS94sVZgwEBQCauhG5Z8dGFdHLMP+yegi3Vs\n\
6d1L7LyGu5uYVyGXHrpMBvMdf65h+7rPaKIudy+zZWuHZivBKf4dZ8lbg/Tz+nou\n\
iwHVE0IhJ0fTRjIoib+ZRg==\n\
-----END PRIVATE KEY-----\n";

    async fn start_tls_server() -> u16 {
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut CERT_PEM.as_bytes()).collect::<Result<_, _>>().unwrap();
        let key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut KEY_PEM.as_bytes()).unwrap().unwrap();

        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { break };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // Completing the handshake is enough for the client to read
                    // the certificate; then hold briefly.
                    if let Ok(stream) = acceptor.accept(sock).await {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        drop(stream);
                    }
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn inspects_self_signed_cert_subject_and_sans() {
        let port = start_tls_server().await;
        let info = inspect("127.0.0.1", port, 5000).await.unwrap();

        assert!(info.subject.contains("decepticon.test"), "subject: {}", info.subject);
        assert!(info.sans.contains(&"decepticon.test".to_string()), "sans: {:?}", info.sans);
        assert!(info.sans.contains(&"www.decepticon.test".to_string()), "sans: {:?}", info.sans);
        assert!(info.protocol.is_some());
        assert!(info.cipher.is_some());
        assert!(!info.serial.is_empty());
    }

    #[tokio::test]
    async fn connect_to_dead_port_errors() {
        assert!(inspect("127.0.0.1", 1, 1500).await.is_err());
    }
}
