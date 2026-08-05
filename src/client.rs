//! Client-specific protocol implementation.

#[cfg(feature = "client")]
mod api;

#[cfg(feature = "client")]
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

#[cfg(any(feature = "client", feature = "server"))]
use num_enum::{FromPrimitive, IntoPrimitive};
#[cfg(feature = "client")]
use oinq::frame;

#[cfg(feature = "client")]
use crate::{
    AgentInfo,
    types::{AuditHealth, ManifestFormatRange, ProvisioningFingerprint},
};

/// Numeric representation of the message types that a client should handle.
#[cfg(any(feature = "client", feature = "server"))]
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, IntoPrimitive, PartialEq)]
#[repr(u32)]
pub(crate) enum RequestCode {
    /// Start DNS filtering
    DnsStart = 1,

    /// Stop DNS filtering
    DnsStop = 2,

    /// Reboot the host
    Reboot = 4,

    /// Reload the configuration
    ReloadConfig = 6,

    /// Fetch the TI database and reload it
    ReloadTi = 5,

    /// Collect resource usage stats
    ResourceUsage = 7,

    /// Update the list of tor exit nodes
    TorExitNodeList = 8,

    /// Update the list of sampling policies
    SamplingPolicyList = 9,

    /// Update traffic filter rules
    ReloadFilterRule = 10,

    /// Update Configuration
    UpdateConfig = 12,

    /// Delete the list of sampling policies
    DeleteSamplingPolicy = 13,

    /// Update the list of Internal network
    InternalNetworkList = 14,

    /// Update the list of allow
    Allowlist = 15,

    /// Update the list of block
    Blocklist = 16,

    /// Request Echo (for ping)
    EchoRequest = 17,

    /// Update the list of trusted User-agent
    TrustedUserAgentList = 18,

    /// Update the list of trusted domains
    TrustedDomainList = 0,

    /// Collect process list
    ProcessList = 19,

    /// Update the semi-supervised models
    SemiSupervisedModels = 20,

    /// Shutdown the host
    Shutdown = 21,

    /// Delete customer-owned filesystem data
    DeleteCustomerData = 22,

    // ── node feature-family request codes ──────────────────────
    //
    // Each node feature family maps to exactly one request code.
    // The typed enum payload (e.g. `NodeServiceRequest`) carries
    // the subcommand; no per-subcommand codes are needed.
    //
    // These codes are internal to the crate and must not appear in
    // the public API.
    /// Node service-control family.
    NodeService = 100,

    /// Node network-interface management family.
    NodeNetworkInterface = 101,

    /// Node hostname management family.
    NodeHostname = 102,

    /// Node time-synchronization management family.
    NodeTimeSync = 103,

    /// Node logging-configuration family.
    NodeLogging = 104,

    /// Node remote-access configuration family.
    NodeRemoteAccess = 105,

    /// Node power-control family.
    NodePower = 106,

    /// Node host-observation family.
    NodeObservation = 107,

    /// Node version-management family.
    NodeVersion = 108,

    /// Node package-management family.
    NodePackage = 109,

    /// Node service-enrollment family.
    NodeEnroll = 110,

    /// Unknown request
    #[num_enum(default)]
    Unknown = u32::MAX,
}

#[cfg(feature = "client")]
/// A builder for creating a new endpoint.
#[derive(Debug)]
pub struct ConnectionBuilder {
    remote_name: String,
    remote_addr: SocketAddr,
    local_addr: IpAddr,
    agent_name: String,
    agent_version: String,
    protocol_version: String,
    status: crate::Status,
    capabilities: BTreeSet<String>,
    active_trust_epoch: Option<u64>,
    manifest_formats: Option<ManifestFormatRange>,
    provisioning_fingerprint: Option<ProvisioningFingerprint>,
    audit_health: Option<AuditHealth>,
    roots: rustls::RootCertStore,
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

#[cfg(feature = "client")]
impl ConnectionBuilder {
    /// Creates a new builder with the remote address, certificate chain,
    /// and key.
    ///
    /// The handshake's conditional-tail fields start out advertising nothing:
    /// an empty capability set and an unknown reading for every optional field.
    /// Use [`capabilities`](Self::capabilities),
    /// [`active_trust_epoch`](Self::active_trust_epoch),
    /// [`manifest_formats`](Self::manifest_formats),
    /// [`provisioning_fingerprint`](Self::provisioning_fingerprint) and
    /// [`audit_health`](Self::audit_health) to report them.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate or key is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        remote_name: &str,
        remote_addr: SocketAddr,
        agent_name: &str,
        agent_version: &str,
        protocol_version: &str,
        status: crate::Status,
        cert: &[u8],
        key: &[u8],
    ) -> std::io::Result<Self> {
        let local_addr = if remote_addr.is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let certs: Vec<_> =
            rustls_pemfile::certs(&mut std::io::Cursor::new(cert)).collect::<Result<_, _>>()?;
        if certs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no certificate",
            ));
        }
        let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "no private key")
            })?;
        Ok(Self {
            remote_name: remote_name.to_string(),
            remote_addr,
            local_addr,
            agent_name: agent_name.to_string(),
            agent_version: agent_version.to_string(),
            protocol_version: protocol_version.to_string(),
            status,
            capabilities: BTreeSet::new(),
            active_trust_epoch: None,
            manifest_formats: None,
            provisioning_fingerprint: None,
            audit_health: None,
            roots: rustls::RootCertStore::empty(),
            certs,
            key,
        })
    }

    /// Sets the capability tags this agent advertises in the handshake.
    ///
    /// The tags are namespaced strings; [`types::capability`] lists the ones
    /// this crate knows about, but the set is open and an unknown tag is
    /// carried through untouched. Replaces any previously set tags; the
    /// default is an empty set, which advertises nothing.
    ///
    /// Security-sensitive tags such as `registrar` and `colocated:*` are
    /// claims that the manager corroborates elsewhere. Advertising one grants
    /// nothing by itself.
    ///
    /// [`types::capability`]: crate::types::capability
    pub fn capabilities<I, S>(&mut self, capabilities: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.capabilities = capabilities.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the release-signing trust-set generation this agent is active on.
    ///
    /// Left unset, the agent reports the epoch as unknown, which a manager
    /// reads as un-confirmed rather than as epoch 0.
    pub fn active_trust_epoch(&mut self, epoch: u64) -> &mut Self {
        self.active_trust_epoch = Some(epoch);
        self
    }

    /// Sets the range of package-manifest `format_version` values this agent
    /// can decode.
    ///
    /// Left unset, the agent reports no range, and a manager assumes the launch
    /// format only.
    pub fn manifest_formats(&mut self, formats: ManifestFormatRange) -> &mut Self {
        self.manifest_formats = Some(formats);
        self
    }

    /// Sets the provisioning-file digests this agent relays.
    ///
    /// The digests are the enforcing daemon's reading, relayed unchanged; an
    /// agent must not substitute digests it computed from its own read of the
    /// file.
    pub fn provisioning_fingerprint(&mut self, fingerprint: ProvisioningFingerprint) -> &mut Self {
        self.provisioning_fingerprint = Some(fingerprint);
        self
    }

    /// Sets the audit-store health this agent relays from its local endpoint.
    ///
    /// Only a registrar reports this.
    pub fn audit_health(&mut self, health: AuditHealth) -> &mut Self {
        self.audit_health = Some(health);
        self
    }

    /// Sets the client certificate chain for the connection.
    ///
    /// If the PEM contains a full chain (leaf + intermediates), all
    /// certificates are preserved and sent during the TLS handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate is invalid.
    pub fn cert(&mut self, cert: &[u8]) -> std::io::Result<&mut Self> {
        let certs: Vec<_> =
            rustls_pemfile::certs(&mut std::io::Cursor::new(cert)).collect::<Result<_, _>>()?;
        if certs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no certificate",
            ));
        }
        self.certs = certs;
        Ok(self)
    }

    /// Sets the private key for the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid.
    pub fn key(&mut self, key: &[u8]) -> std::io::Result<&mut Self> {
        self.key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "no private key")
            })?;
        Ok(self)
    }

    /// Sets the root certificates for the connection.
    ///
    /// Each item may contain multiple PEM-encoded certificates (e.g. a
    /// CA bundle); all certificates are loaded into the trust store.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the certificates are invalid.
    pub fn root_certs<I>(&mut self, certs: I) -> std::io::Result<&mut Self>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        self.roots = rustls::RootCertStore::empty();
        for pem in certs {
            for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(pem.as_ref())) {
                let cert = cert?;
                self.roots
                    .add(cert)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            }
        }
        Ok(self)
    }

    /// Adds root certificates to the certificate store.
    ///
    /// It reads certificates from the given reader, filtering out any PEM
    /// sections.
    ///
    /// # Errors
    ///
    /// Returns an error if the reader is invalid or the certificates are
    /// invalid.
    pub fn add_root_certs(&mut self, rd: &mut dyn std::io::BufRead) -> std::io::Result<&mut Self> {
        for cert in rustls_pemfile::certs(rd) {
            let cert = cert?;
            self.roots
                .add(cert)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        }
        Ok(self)
    }

    /// Sets the local address to bind to.
    ///
    /// This is only necessary if the unspecified address (:: for IPv6 and
    /// 0.0.0.0 for IPv4) is not desired.
    pub fn local_addr(&mut self, addr: IpAddr) -> &mut Self {
        self.local_addr = addr;
        self
    }

    /// Connects to the server and performs a handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails or the server requires a different
    /// protocol version.
    #[cfg(feature = "client")]
    pub async fn connect(&self) -> std::io::Result<Connection> {
        use std::io;

        let endpoint = self.build_endpoint()?;
        let connecting = endpoint
            .connect(self.remote_addr, &self.remote_name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let connection = connecting.await.map_err(|e| {
            // quinn (as of 0.11) provides automatic conversion from
            // `ConnectionError` to `ReadError`, and from `ReadError` to
            // `io::Error`. However, the conversion treats all `ConnectionError`
            // variants as `NotConnected`, which is too generic. We need to provide
            // more specific error messages.
            use quinn::ConnectionError;
            match e {
                ConnectionError::ApplicationClosed(e) => {
                    std::io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string())
                }
                ConnectionError::CidsExhausted => io::Error::other("connection IDs exhausted"),
                ConnectionError::ConnectionClosed(e) => {
                    std::io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string())
                }
                ConnectionError::LocallyClosed => {
                    io::Error::new(io::ErrorKind::NotConnected, "locally closed")
                }
                ConnectionError::Reset => io::Error::from(io::ErrorKind::ConnectionReset),
                ConnectionError::TimedOut => io::Error::from(io::ErrorKind::TimedOut),
                ConnectionError::TransportError(e) => {
                    std::io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                }
                ConnectionError::VersionMismatch => {
                    io::Error::new(io::ErrorKind::ConnectionRefused, "version mismatch")
                }
            }
        })?;

        // A placeholder for the address of this agent. Will be replaced by the
        // server.
        //
        // TODO: This is unnecessary in handshake, and thus should be removed in the
        // future.
        let addr = if connection.remote_address().is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };

        let agent_info = AgentInfo {
            agent_name: self.agent_name.clone(),
            agent_version: self.agent_version.clone(),
            protocol_version: self.protocol_version.clone(),
            status: self.status,
            addr,
            capabilities: self.capabilities.clone(),
            active_trust_epoch: self.active_trust_epoch,
            manifest_formats: self.manifest_formats,
            provisioning_fingerprint: self.provisioning_fingerprint.clone(),
            audit_health: self.audit_health,
        };

        let (mut send, mut recv) = connection.open_bi().await?;
        let mut buf = Vec::new();
        frame::send(&mut send, &mut buf, &agent_info).await?;
        match frame::recv::<Result<&str, &str>>(&mut recv, &mut buf).await? {
            Ok(_) => Ok(Connection {
                endpoint,
                connection,
            }),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("server requires protocol version {e}"),
            )),
        }
    }

    /// Creates a new endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored TLS configuration is invalid.
    fn build_endpoint(&self) -> std::io::Result<quinn::Endpoint> {
        use std::sync::Arc;
        use std::time::Duration;

        const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);

        let tls_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(self.roots.clone())
            .with_client_auth_cert(self.certs.clone(), self.key.clone_key())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
        let mut config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_cfg)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
        ));
        config.transport_config(Arc::new(transport));

        let mut endpoint = quinn::Endpoint::client(SocketAddr::new(self.local_addr, 0))?;
        endpoint.set_default_client_config(config);
        Ok(endpoint)
    }
}

#[cfg(feature = "client")]
/// A connection to a server.
#[derive(Clone, Debug)]
pub struct Connection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

#[cfg(feature = "client")]
impl Connection {
    /// Gets the local address of the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the call to the underlying
    /// [`local_addr`](quinn::Endpoint::local_addr) fails.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Gets the remote address of the connection.
    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// If the connection is cloesd, returns the reason; otherwise, returns `None`.
    #[must_use]
    pub fn close_reason(&self) -> Option<std::io::Error> {
        self.connection.close_reason().map(Into::into)
    }

    /// Initiates an outgoing bidirectional stream.
    ///
    /// This directly corresponds to the `open_bi` method of the underlying
    /// `quinn::Connection`. In the future, this method may be removed in favor
    /// of this crate's own implementation to provide additional features.
    #[must_use]
    pub fn open_bi(&self) -> quinn::OpenBi<'_> {
        self.connection.open_bi()
    }

    /// Initiates an outgoing unidirectional stream.
    ///
    /// This directly corresponds to the `open_uni` method of the underlying
    /// `quinn::Connection`. In the future, this method may be removed in favor
    /// of this crate's own implementation to provide additional features.
    #[must_use]
    pub fn open_uni(&self) -> quinn::OpenUni<'_> {
        self.connection.open_uni()
    }

    /// Accepts an incoming bidirectional stream.
    ///
    /// This directly corresponds to the `accept_bi` method of the underlying
    /// `quinn::Connection`. In the future, this method may be removed in favor
    /// of this crate's own implementation to provide additional features.
    #[must_use]
    pub fn accept_bi(&self) -> quinn::AcceptBi<'_> {
        self.connection.accept_bi()
    }

    /// Closes the connection.
    ///
    /// This is a helper method for testing and should not be used in production
    /// code.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn close(&self, error_code: quinn::VarInt, reason: &[u8]) {
        self.connection.close(error_code, reason);
    }
}

/// Sends a handshake request and processes the response.
///
/// # Errors
///
/// Returns `HandshakeError` if the handshake failed.
#[cfg(all(test, feature = "client", feature = "server"))]
pub(crate) async fn handshake(
    conn: &quinn::Connection,
    agent_name: &str,
    agent_version: &str,
    protocol_version: &str,
    status: crate::Status,
) -> Result<(), super::HandshakeError> {
    // A placeholder for the address of this agent. Will be replaced by the
    // server.
    //
    // TODO: This is unnecessary in handshake, and thus should be removed in the
    // future.

    let addr = if conn.remote_address().is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };

    let agent_info = AgentInfo {
        agent_name: agent_name.to_string(),
        agent_version: agent_version.to_string(),
        protocol_version: protocol_version.to_string(),
        status,
        addr,
        capabilities: BTreeSet::new(),
        active_trust_epoch: None,
        manifest_formats: None,
        provisioning_fingerprint: None,
        audit_health: None,
    };

    handshake_with(conn, &agent_info).await
}

/// Sends the given agent information as a handshake request and processes the
/// response.
///
/// The whole struct is sent in one frame, base fields first and the conditional
/// tail after them, which is what the derived `Serialize` produces.
///
/// # Errors
///
/// Returns `HandshakeError` if the handshake failed.
#[cfg(all(test, feature = "client", feature = "server"))]
pub(crate) async fn handshake_with(
    conn: &quinn::Connection,
    agent_info: &AgentInfo,
) -> Result<(), super::HandshakeError> {
    use crate::{handle_handshake_recv_io_error, handle_handshake_send_io_error};

    let (mut send, mut recv) = conn.open_bi().await?;
    let mut buf = Vec::new();
    frame::send(&mut send, &mut buf, agent_info)
        .await
        .map_err(handle_handshake_send_io_error)?;

    match frame::recv::<Result<&str, &str>>(&mut recv, &mut buf).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(super::HandshakeError::IncompatibleProtocol(
            agent_info.protocol_version.clone(),
            e.to_string(),
        )),
        Err(e) => Err(handle_handshake_recv_io_error(e)),
    }
}

#[cfg(all(test, feature = "client"))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

    use super::*;

    /// Generates a root CA, an intermediate CA signed by the root, and a leaf
    /// certificate signed by the intermediate. Returns the full client PEM
    /// chain (leaf + intermediate), the leaf private key PEM, the root CA PEM,
    /// and the count of certificates in the chain.
    fn generate_chain() -> (String, String, String, usize) {
        // Root CA
        let mut root_params = CertificateParams::new(vec!["root-ca".to_string()]).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_key = KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::from_params(&root_params, &root_key);

        // Intermediate CA signed by root
        let mut intermediate_params =
            CertificateParams::new(vec!["intermediate-ca".to_string()]).unwrap();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let intermediate_key = KeyPair::generate().unwrap();
        let intermediate_cert = intermediate_params
            .signed_by(&intermediate_key, &root_issuer)
            .unwrap();
        let intermediate_issuer = Issuer::from_params(&intermediate_params, &intermediate_key);

        // Leaf certificate signed by intermediate
        let leaf_params = CertificateParams::new(vec!["test-client".to_string()]).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &intermediate_issuer)
            .unwrap();

        // Build the full chain PEM: leaf + intermediate
        let chain_pem = format!("{}{}", leaf_cert.pem(), intermediate_cert.pem());
        let leaf_key_pem = leaf_key.serialize_pem();
        let root_pem = root_cert.pem();

        (chain_pem, leaf_key_pem, root_pem, 2)
    }

    #[test]
    fn new_preserves_full_cert_chain() {
        let (chain_pem, key_pem, _root_pem, expected_count) = generate_chain();

        let builder = ConnectionBuilder::new(
            "test-server",
            "127.0.0.1:443".parse().unwrap(),
            "test-agent",
            "1.0",
            "1.0",
            crate::Status::Ready,
            chain_pem.as_bytes(),
            key_pem.as_bytes(),
        )
        .unwrap();

        assert_eq!(
            builder.certs.len(),
            expected_count,
            "ConnectionBuilder::new must preserve the full certificate chain (leaf + intermediate)"
        );
    }

    #[test]
    fn cert_preserves_full_chain() {
        let (chain_pem, key_pem, _root_pem, expected_count) = generate_chain();

        // Start with a single self-signed cert
        let single = rcgen::generate_simple_self_signed(vec!["tmp".to_string()]).unwrap();
        let mut builder = ConnectionBuilder::new(
            "test-server",
            "127.0.0.1:443".parse().unwrap(),
            "test-agent",
            "1.0",
            "1.0",
            crate::Status::Ready,
            single.cert.pem().as_bytes(),
            single.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        assert_eq!(builder.certs.len(), 1);

        // Replace with a full chain via cert()
        builder.cert(chain_pem.as_bytes()).unwrap();
        builder.key(key_pem.as_bytes()).unwrap();

        assert_eq!(
            builder.certs.len(),
            expected_count,
            "cert() must preserve the full certificate chain (leaf + intermediate)"
        );
    }

    #[test]
    fn root_certs_loads_multiple_ca_certs() {
        let (_chain_pem, _key_pem, root_pem, _) = generate_chain();

        // Create a second independent CA
        let mut ca2_params = CertificateParams::new(vec!["ca2".to_string()]).unwrap();
        ca2_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca2_key = KeyPair::generate().unwrap();
        let ca2_cert = ca2_params.self_signed(&ca2_key).unwrap();

        // Bundle both CAs into a single PEM blob
        let bundle = format!("{}{}", root_pem, ca2_cert.pem());

        let single = rcgen::generate_simple_self_signed(vec!["tmp".to_string()]).unwrap();
        let mut builder = ConnectionBuilder::new(
            "test-server",
            "127.0.0.1:443".parse().unwrap(),
            "test-agent",
            "1.0",
            "1.0",
            crate::Status::Ready,
            single.cert.pem().as_bytes(),
            single.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();

        builder.root_certs([bundle.as_bytes()]).unwrap();

        assert_eq!(
            builder.roots.len(),
            2,
            "root_certs() must load all certificates from a CA bundle PEM"
        );
    }

    #[tokio::test]
    async fn full_chain_builds_valid_endpoint() {
        let (chain_pem, key_pem, root_pem, _) = generate_chain();

        let mut builder = ConnectionBuilder::new(
            "test-server",
            "[::1]:443".parse().unwrap(),
            "test-agent",
            "1.0",
            "1.0",
            crate::Status::Ready,
            chain_pem.as_bytes(),
            key_pem.as_bytes(),
        )
        .unwrap();
        builder.root_certs([root_pem.as_bytes()]).unwrap();

        let endpoint = builder.build_endpoint();
        assert!(
            endpoint.is_ok(),
            "build_endpoint() must succeed with a full certificate chain: {}",
            endpoint.unwrap_err()
        );
    }

    #[test]
    fn tail_fields_default_to_advertising_nothing() {
        let (chain_pem, key_pem, _root_pem, _) = generate_chain();

        let builder = ConnectionBuilder::new(
            "test-server",
            "127.0.0.1:443".parse().unwrap(),
            "test-agent",
            "1.0",
            "1.0",
            crate::Status::Ready,
            chain_pem.as_bytes(),
            key_pem.as_bytes(),
        )
        .unwrap();

        assert!(builder.capabilities.is_empty());
        assert_eq!(builder.active_trust_epoch, None);
        assert_eq!(builder.manifest_formats, None);
        assert_eq!(builder.provisioning_fingerprint, None);
        assert_eq!(builder.audit_health, None);
    }

    /// `capabilities` replaces the set rather than adding to it, so a caller
    /// that recomputes its roles cannot leave a stale tag advertised.
    #[test]
    fn capabilities_replaces_rather_than_accumulates() {
        use std::collections::BTreeSet;

        use crate::types::capability;

        let (chain_pem, key_pem, _root_pem, _) = generate_chain();

        let mut builder = ConnectionBuilder::new(
            "test-server",
            "127.0.0.1:443".parse().unwrap(),
            "test-agent",
            "1.0",
            "1.0",
            crate::Status::Ready,
            chain_pem.as_bytes(),
            key_pem.as_bytes(),
        )
        .unwrap();

        builder.capabilities([capability::REGISTRAR, capability::NODE_ENROLL]);
        builder.capabilities([capability::NODE_PACKAGE]);

        assert_eq!(
            builder.capabilities,
            BTreeSet::from([capability::NODE_PACKAGE.to_string()])
        );

        builder.capabilities(Vec::<String>::new());

        assert!(builder.capabilities.is_empty());
    }

    /// What the builder is told to advertise is what the manager receives.
    #[cfg(feature = "server")]
    #[tokio::test]
    async fn connect_sends_the_configured_tail() {
        use std::collections::{BTreeMap, BTreeSet};

        use crate::{
            test::TEST_ENV,
            types::{AuditHealth, ManifestFormatRange, ProvisioningFingerprint, capability},
        };

        let fingerprint = ProvisioningFingerprint {
            components: BTreeMap::from([("review".to_string(), "sha256:def".to_string())]),
            domain: "example.test".to_string(),
        };
        let health = AuditHealth {
            below_low_water: false,
            intent_without_outcome: 11,
        };

        let test_env = TEST_ENV.lock().await;
        let (server_conn, _client_conn, agent_info) = test_env
            .setup_with(|builder| {
                builder
                    .capabilities([capability::REGISTRAR, "future:thing"])
                    .active_trust_epoch(9)
                    .manifest_formats(ManifestFormatRange { min: 1, max: 3 })
                    .provisioning_fingerprint(fingerprint.clone())
                    .audit_health(health);
            })
            .await;

        assert_eq!(
            agent_info.capabilities,
            BTreeSet::from(["future:thing".to_string(), "registrar".to_string()])
        );
        assert_eq!(agent_info.active_trust_epoch, Some(9));
        assert_eq!(
            agent_info.manifest_formats,
            Some(ManifestFormatRange { min: 1, max: 3 })
        );
        assert_eq!(agent_info.provisioning_fingerprint, Some(fingerprint));
        assert_eq!(agent_info.audit_health, Some(health));

        test_env.teardown(&server_conn);
    }

    /// A builder left at its defaults connects and hands the manager the
    /// unknown readings. This is the other wire shape that reads as "advertises
    /// nothing": the tail is present, but every field carries the empty or
    /// absent value, so it must be indistinguishable from the base-only frame
    /// an agent predating the tail sends.
    #[cfg(feature = "server")]
    #[tokio::test]
    async fn connect_without_a_configured_tail_advertises_nothing() {
        use crate::test::TEST_ENV;

        let test_env = TEST_ENV.lock().await;
        let (server_conn, _client_conn, agent_info) = test_env.setup_with(|_builder| {}).await;

        assert!(agent_info.capabilities.is_empty());
        assert_eq!(agent_info.active_trust_epoch, None);
        assert_eq!(agent_info.manifest_formats, None);
        assert_eq!(agent_info.provisioning_fingerprint, None);
        assert_eq!(agent_info.audit_health, None);

        test_env.teardown(&server_conn);
    }
}
