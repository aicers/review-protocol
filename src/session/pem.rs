//! PEM-based client TLS configuration with an explicit crypto provider.
use std::{io::Cursor, sync::Arc};

/// A failure to build a client TLS configuration from PEM material.
///
/// Malformed PEM is reported as `Pem`; certificate-free or key-free inputs
/// (including text without PEM blocks) use the corresponding `No*` variant.
/// Parsed DER that rustls refuses is reported as `Rustls`.
#[derive(Debug, thiserror::Error)]
pub enum ClientPemError {
    /// The chain input contained no certificate.
    #[error("no certificate in client chain")]
    NoCertificate,
    /// The key input contained no supported private key.
    #[error("no private key in client key input")]
    NoPrivateKey,
    /// The root inputs together contained no certificate.
    #[error("no root certificate in root inputs")]
    NoRootCertificate,
    /// A PEM block could not be parsed.
    #[error("parsing client TLS PEM: {0}")]
    Pem(#[from] std::io::Error),
    /// Rustls rejected the roots, chain, key, or protocol configuration.
    #[error("building client TLS configuration: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Builds client-authenticated TLS configuration from a PEM chain, key, and roots.
///
/// Each root input may contain multiple certificates. Uses the explicit aws-lc-rs
/// provider and safe default protocol versions, independently of the process
/// default provider. Applications retain control of their rustls dependency and
/// features (including `prefer-post-quantum`), or may supply their own config to
/// [`super::AgentConnector`].
///
/// # Errors
/// Returns a matchable [`ClientPemError`] for missing material, malformed PEM,
/// or material rejected by rustls.
pub fn client_config_from_pem(
    chain: &[u8],
    key: &[u8],
    roots: &[&[u8]],
) -> Result<Arc<rustls::ClientConfig>, ClientPemError> {
    let chain = rustls_pemfile::certs(&mut Cursor::new(chain)).collect::<Result<Vec<_>, _>>()?;
    if chain.is_empty() {
        return Err(ClientPemError::NoCertificate);
    }
    let key =
        rustls_pemfile::private_key(&mut Cursor::new(key))?.ok_or(ClientPemError::NoPrivateKey)?;
    let mut store = rustls::RootCertStore::empty();
    for input in roots {
        for cert in rustls_pemfile::certs(&mut Cursor::new(input)) {
            store.add(cert?)?;
        }
    }
    if store.is_empty() {
        return Err(ClientPemError::NoRootCertificate);
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(store)
    .with_client_auth_cert(chain, key)?;
    Ok(Arc::new(config))
}
