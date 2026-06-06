//! TLS certificate inspection.
//!
//! Opens a TLS connection and reads the leaf certificate. Trust is deliberately
//! NOT verified — we want to inspect the cert even when it's expired or
//! self-signed — so validity (dates, days-to-expiry) is computed from the
//! parsed certificate rather than from a chain-validation result.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
};
use x509_parser::prelude::*;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize)]
pub struct TlsInfo {
    pub domain: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub san: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub days_to_expiry: i64,
    pub expired: bool,
}

/// Inspect the leaf TLS certificate presented by `domain:port`.
pub async fn inspect(domain: &str, port: u16) -> Result<TlsInfo> {
    let connector = TlsConnector::from(client_config());
    let server_name = ServerName::try_from(domain.to_owned())
        .with_context(|| format!("`{domain}` is not a valid TLS server name"))?;

    let fut = async {
        let tcp = TcpStream::connect((domain, port))
            .await
            .with_context(|| format!("connecting to {domain}:{port}"))?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .with_context(|| format!("TLS handshake with {domain}:{port}"))?;
        let (_, conn) = tls.get_ref();
        let certs = conn
            .peer_certificates()
            .ok_or_else(|| anyhow!("server presented no certificate"))?;
        let leaf = certs
            .first()
            .ok_or_else(|| anyhow!("empty certificate chain"))?;
        parse_cert(domain, port, leaf)
    };

    timeout(HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| anyhow!("TLS handshake with {domain}:{port} timed out"))?
}

fn parse_cert(domain: &str, port: u16, der: &CertificateDer) -> Result<TlsInfo> {
    let (_, cert) =
        X509Certificate::from_der(der.as_ref()).map_err(|e| anyhow!("parsing certificate: {e}"))?;

    let subject = first_cn(cert.subject());
    let issuer = first_cn(cert.issuer()).or_else(|| {
        cert.issuer()
            .iter_organization()
            .next()
            .and_then(|a| a.as_str().ok())
            .map(str::to_string)
    });

    let mut san = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            if let GeneralName::DNSName(d) = name {
                san.push(d.to_string());
            }
        }
    }

    let not_before = cert.validity().not_before;
    let not_after = cert.validity().not_after;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days_to_expiry = (not_after.timestamp() - now) / 86_400;
    let expired = now > not_after.timestamp() || now < not_before.timestamp();

    Ok(TlsInfo {
        domain: domain.to_string(),
        port,
        subject,
        issuer,
        san,
        not_before: not_before.to_string(),
        not_after: not_after.to_string(),
        days_to_expiry,
        expired,
    })
}

fn first_cn(name: &X509Name) -> Option<String> {
    name.iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(str::to_string)
}

/// Shared client config with a no-op certificate verifier (inspection only).
fn client_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify::new()))
            .with_no_client_auth();
        Arc::new(config)
    })
    .clone()
}

/// A verifier that accepts any certificate — we inspect, we don't trust.
#[derive(Debug)]
struct NoVerify {
    schemes: Vec<SignatureScheme>,
}

impl NoVerify {
    fn new() -> Self {
        Self {
            schemes: ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}
